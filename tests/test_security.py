"""Security and rate-limiting tests."""
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
import pytest


@pytest.fixture
def app_module():
    import app as app_module
    return app_module


@pytest.fixture
def _client(app_module):
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        with app_module.app.app_context():
            yield c


def _std_headers():
    return {
        "User-Agent": "pytest-client/1.0 (+https://example.test) long-ua",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }


def test_security_headers_on_index(_client):
    resp = _client.get("/", headers={"User-Agent": "pytest", "Accept-Language": "en"})
    assert resp.status_code == 200
    for h in [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Content-Security-Policy",
    ]:
        assert h in resp.headers


def test_suspicious_request_blocked_open_door(_client):
    resp = _client.post(
        "/open-door",
        data=json.dumps({"pin": "1234"}),
        headers={"Content-Type": "application/json", "User-Agent": "curl"},
    )
    assert resp.status_code == 403


def test_global_rate_limit_blocks(_client, app_module):
    app_module.rate_limiter.global_failed = app_module.MAX_GLOBAL_ATTEMPTS_PER_HOUR
    resp = _client.post(
        "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
    )
    assert resp.status_code == 429


def test_open_door_session_blocked_flow(_client, app_module):
    from config import get_current_time
    _client.post("/open-door", data=json.dumps({}), headers=_std_headers())
    with _client.session_transaction() as s:
        sid = s.get("_session_id")
    assert sid
    app_module.rate_limiter.global_failed = 0
    app_module.rate_limiter.global_last_reset = get_current_time()
    app_module.rate_limiter.session_blocked_until[sid] = get_current_time() + timedelta(seconds=60)
    r = _client.post(
        "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
    )
    assert r.status_code == 429
    data = r.get_json()
    assert "blocked_until" in data


def test_open_door_ip_blocked_flow(_client, app_module, monkeypatch):
    from config import get_current_time
    monkeypatch.setattr(
        "app.get_client_identifier", lambda: ("9.9.9.9", "sessX", "idkeyX")
    )
    app_module.rate_limiter.ip_blocked_until["idkeyX"] = get_current_time() + timedelta(seconds=60)
    r = _client.post(
        "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
    )
    assert r.status_code == 429


def test_admin_auth_blocking(_client, app_module, monkeypatch):
    wrong = {"password": "nope", "remember_me": False}
    h = _std_headers()
    for _ in range(app_module.SESSION_MAX_ATTEMPTS):
        r = _client.post("/admin/auth", data=json.dumps(wrong), headers=h)
        assert r.status_code == 403
    r = _client.post("/admin/auth", data=json.dumps(wrong), headers=h)
    assert r.status_code == 429


def test_admin_auth_success(_client, app_module, monkeypatch):
    import config
    monkeypatch.setattr(config, "admin_password", "secret")
    monkeypatch.setattr(app_module, "admin_password", "secret")
    r = _client.post(
        "/admin/auth",
        data=json.dumps({"password": "secret", "remember_me": True}),
        headers=_std_headers(),
    )
    assert r.status_code == 200
    r2 = _client.get("/admin/check-auth")
    assert r2.status_code == 200
    data = r2.get_json()
    assert data.get("authenticated") is True


def test_testmode_pin_success(_client, app_module):
    from config import get_current_time
    app_module.rate_limiter.global_failed = 0
    app_module.rate_limiter.global_last_reset = get_current_time()
    app_module.rate_limiter.ip_blocked_until.clear()
    app_module.rate_limiter.session_blocked_until.clear()
    app_module.user_pins["alice"] = "1234"
    app_module.test_mode = True
    r = _client.post(
        "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
    )
    assert r.status_code == 200
    assert "TEST MODE" in r.get_json().get("message", "")


def test_admin_logout_endpoint(_client):
    with _client.session_transaction() as s:
        s["admin_authenticated"] = True
        s["admin_login_time"] = datetime.now(timezone.utc).isoformat()
    r = _client.post("/admin/logout")
    assert r.status_code == 200
    r2 = _client.get("/admin/check-auth")
    assert r2.status_code == 200
    assert r2.get_json().get("authenticated") is False


def test_admin_page_renders(_client):
    r = _client.get("/admin")
    assert r.status_code == 200


def test_battery_non200_returns_none(_client, app_module):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "error"
    with patch.object(app_module.ha_client.session, "get", return_value=mock_response):
        response = _client.get("/battery")
        assert response.status_code == 200
        assert response.get_json()["level"] is None


def test_battery_exception_returns_none(_client, app_module):
    with patch.object(app_module.ha_client.session, "get", side_effect=Exception("boom")):
        response = _client.get("/battery")
        assert response.status_code == 200
        assert response.get_json()["level"] is None


def test_open_door_success_switch(_client, app_module, monkeypatch):
    import config
    app_module.user_pins["alice"] = "1234"
    monkeypatch.setattr(config, "entity_id", "switch.test_door")
    app_module.test_mode = False
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None
    with patch.object(app_module.ha_client.session, "post", return_value=mock_resp):
        r = _client.post(
            "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
        )
        assert r.status_code == 200
        msg = r.get_json().get("message", "")
        assert "Door open" in msg


def test_open_door_success_lock(_client, app_module, monkeypatch):
    import config
    app_module.user_pins["alice"] = "1234"
    monkeypatch.setattr(config, "entity_id", "lock.test_door")
    app_module.test_mode = False
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None
    with patch.object(app_module.ha_client.session, "post", return_value=mock_resp):
        r = _client.post(
            "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
        )
        assert r.status_code == 200


def test_open_door_success_input_boolean(_client, app_module, monkeypatch):
    import config
    app_module.user_pins["alice"] = "1234"
    monkeypatch.setattr(config, "entity_id", "input_boolean.open")
    app_module.test_mode = False
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None
    with patch.object(app_module.ha_client.session, "post", return_value=mock_resp):
        r = _client.post(
            "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
        )
        assert r.status_code == 200


def test_battery_invalid_format(_client, app_module):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"state": "unknown"}
    with patch.object(app_module.ha_client.session, "get", return_value=mock_response):
        response = _client.get("/battery")
        assert response.status_code == 200
        assert response.get_json()["level"] is None


def test_admin_logs_parsing(_client, app_module, tmp_path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "log.txt"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": "1.2.3.4",
        "user": "alice",
        "status": "SUCCESS",
        "details": "Door opened",
    }
    log_file.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    with patch("app.os.path.exists", return_value=True), patch(
        "app.os.path.join", return_value=str(log_file)
    ):
        with _client.session_transaction() as s:
            s["admin_authenticated"] = True
            s["admin_login_time"] = datetime.now(timezone.utc).isoformat()
        r = _client.get("/admin/logs")
        assert r.status_code == 200
        data = r.get_json()
        assert "logs" in data and isinstance(data["logs"], list)
        assert any(row.get("user") == "alice" for row in data["logs"])


def test_blocked_denies_correct_pin_and_returns_blocked_until(_client, app_module):
    from config import get_current_time
    app_module.user_pins["alice"] = "1234"
    _client.post("/open-door", data=json.dumps({}), headers=_std_headers())
    with _client.session_transaction() as s:
        sid = s.get("_session_id")
    assert sid
    app_module.rate_limiter.session_blocked_until[sid] = get_current_time() + timedelta(seconds=60)
    r = _client.post(
        "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
    )
    assert r.status_code == 429
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data


def test_open_door_block_set_on_failure_includes_blocked_until(_client, app_module):
    headers = _std_headers()
    _client.post("/open-door", data=json.dumps({"pin": "0000"}), headers=headers)
    with _client.session_transaction() as s:
        sid = s.get("_session_id")
    assert sid
    for i in range(app_module.SESSION_MAX_ATTEMPTS - 1):
        r = _client.post("/open-door", data=json.dumps({"pin": "0000"}), headers=headers)
    assert r.status_code == 401
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data
    r2 = _client.post("/open-door", data=json.dumps({"pin": "0000"}), headers=headers)
    assert r2.status_code == 429
    data2 = r2.get_json()
    assert "blocked_until" in data2


def test_persisted_block_cookie_blocks_correct_pin(_client, app_module):
    app_module.user_pins["zoe"] = "4321"
    with _client.session_transaction() as s:
        s["_session_id"] = "sessCookie"
        s["blocked_until_ts"] = time.time() + 60
    r = _client.post(
        "/open-door", data=json.dumps({"pin": "4321"}), headers=_std_headers()
    )
    assert r.status_code == 429
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data


def test_success_clears_persisted_block_cookie_when_expired(_client, app_module):
    app_module.user_pins["amy"] = "1234"
    with _client.session_transaction() as s:
        s["_session_id"] = "sessExpired"
        s["blocked_until_ts"] = time.time() - 1  # already expired
    r = _client.post(
        "/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers()
    )
    assert r.status_code in (200, 502, 500)
    with _client.session_transaction() as s:
        assert "blocked_until_ts" not in s
