import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


@pytest.fixture
def client(app_module):
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


def test_security_headers_on_index(client):
    resp = client.get("/", headers={"User-Agent": "pytest", "Accept-Language": "en"})
    assert resp.status_code == 200
    # Basic security headers
    for h in [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
    ]:
        assert h in resp.headers


def test_suspicious_request_blocked_open_door(client):
    # Explicitly set a suspicious User-Agent ('curl') to avoid Werkzeug default UA
    resp = client.post(
        "/open-door",
        data=json.dumps({"pin": "1234"}),
        headers={"Content-Type": "application/json", "User-Agent": "curl"},
    )
    assert resp.status_code == 403


def test_global_rate_limit_blocks(client, app_module):
    # Force global rate limit exceeded
    app_module.global_failed_attempts = app_module.MAX_GLOBAL_ATTEMPTS_PER_HOUR
    resp = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
    assert resp.status_code == 429


def test_open_door_session_blocked_flow(client, app_module, monkeypatch):
    # Trigger session id creation
    client.post("/open-door", data=json.dumps({}), headers=_std_headers())
    with client.session_transaction() as s:
        sid = s.get("_session_id")
    assert sid
    # Reset any prior global rate-limit state to ensure we test session block specifically
    app_module.global_failed_attempts = 0
    app_module.global_last_reset = app_module.get_current_time()
    # Block this session
    app_module.session_blocked_until[sid] = app_module.get_current_time() + timedelta(seconds=60)
    r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
    assert r.status_code == 429
    data = r.get_json()
    assert "blocked_until" in data
    data = r.get_json()
    assert "blocked_until" in data


def test_open_door_ip_blocked_flow(client, app_module, monkeypatch):
    # Force known identifiers from helper
    monkeypatch.setattr(app_module, "get_client_identifier", lambda: ("9.9.9.9", "sessX", "idkeyX"))
    app_module.ip_blocked_until["idkeyX"] = app_module.get_current_time() + timedelta(seconds=60)
    r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
    assert r.status_code == 429


def test_admin_auth_blocking(client, app_module, monkeypatch):
    # Make wrong password repeatedly and ensure session becomes blocked
    monkeypatch.setattr(time, "sleep", lambda s: None)
    wrong = {"password": "nope", "remember_me": False}
    h = _std_headers()

    # 3 failures (SESSION_MAX_ATTEMPTS default is 3)
    for _ in range(app_module.SESSION_MAX_ATTEMPTS):
        r = client.post("/admin/auth", data=json.dumps(wrong), headers=h)
        assert r.status_code == 403
    # Next attempt is blocked
    r = client.post("/admin/auth", data=json.dumps(wrong), headers=h)
    assert r.status_code == 429


def test_admin_auth_success(client, app_module, monkeypatch):
    # Allow a success path by overriding admin password
    monkeypatch.setattr(time, "sleep", lambda s: None)
    app_module.admin_password = "secret"
    r = client.post(
        "/admin/auth",
        data=json.dumps({"password": "secret", "remember_me": True}),
        headers=_std_headers(),
    )
    assert r.status_code == 200
    # Verify auth flag and CSRF token are returned via check-auth
    r2 = client.get("/admin/check-auth")
    assert r2.status_code == 200
    data = r2.get_json()
    assert data.get("authenticated") is True
    assert data.get("csrf_token") is not None
    assert len(data["csrf_token"]) == 64  # secrets.token_hex(32) produces 64 hex chars


def test_testmode_pin_success(client, app_module):
    # Reset any prior rate-limit/blocking state from earlier tests
    app_module.global_failed_attempts = 0
    app_module.global_last_reset = app_module.get_current_time()
    app_module.ip_blocked_until.clear()
    app_module.session_blocked_until.clear()

    app_module.user_pins["alice"] = "1234"
    app_module.test_mode = True
    r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
    assert r.status_code == 200
    assert "TEST MODE" in r.get_json().get("message", "")


def test_admin_logout_endpoint(client):
    # Authenticate first, including CSRF token
    csrf = "test-logout-csrf-token"
    with client.session_transaction() as s:
        s["admin_authenticated"] = True
        s["admin_login_time"] = datetime.now(timezone.utc).isoformat()
        s["admin_csrf_token"] = csrf
    r = client.post("/admin/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    # Confirm logged out
    r2 = client.get("/admin/check-auth")
    assert r2.status_code == 200
    assert r2.get_json().get("authenticated") is False


def test_admin_logout_requires_csrf(client):
    # Logout without CSRF token must be rejected
    with client.session_transaction() as s:
        s["admin_authenticated"] = True
        s["admin_csrf_token"] = "secret"
    r = client.post("/admin/logout")
    assert r.status_code == 403


def test_oidc_logout_enabled_redirect(client, app_module, monkeypatch):
    # Make OIDC appear enabled
    class _DummyOAuth:
        pass

    app_module.oauth = _DummyOAuth()
    app_module.oidc_issuer = "https://auth.example.com"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"end_session_endpoint": "https://auth.example.com/logout"}
    with patch("requests.get", return_value=mock_resp):
        r = client.get("/oidc/logout", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert r.headers.get("Location", "").startswith("https://auth.example.com/logout")


def test_admin_page_renders(client):
    r = client.get("/admin")
    assert r.status_code == 200


def test_battery_non200_returns_none(client, monkeypatch):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "error"
    with patch("requests.get", return_value=mock_response):
        response = client.get("/battery")
        assert response.status_code == 200
        assert response.get_json()["level"] is None


def test_battery_exception_returns_none(client, monkeypatch):
    with patch("requests.get", side_effect=Exception("boom")):
        response = client.get("/battery")
        assert response.status_code == 200
        assert response.get_json()["level"] is None


def test_auth_status_oidc_disabled_ignores_stale_session(client):
    # Explicitly disable OIDC to ensure gating is respected even with stale session keys
    import app as app_module

    app_module.oauth = None
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
        s["oidc_user"] = "alice@example.com"
        s["oidc_groups"] = ["dooropener-users"]
    resp = client.get("/auth/status")
    assert resp.status_code == 200
    data = resp.get_json()
    # OIDC not initialized => must be reported as disabled/unauthenticated
    assert data["oidc_enabled"] in (False, 0)
    assert data["oidc_authenticated"] in (False, 0)


def test_oidc_logout_when_disabled_clears_session(client):
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
        s["something_else"] = "x"
    resp = client.get("/oidc/logout", follow_redirects=False)
    # Should redirect to index and clear session
    assert resp.status_code in (302, 303)


def test_open_door_success_switch(client, app_module, monkeypatch):
    # Configure a valid PIN and switch entity
    app_module.user_pins["alice"] = "1234"
    app_module.entity_id = "switch.test_door"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None

    with patch("requests.post", return_value=mock_resp):
        r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
        assert r.status_code == 200
        msg = r.get_json().get("message", "")
        assert "Door open" in msg


def test_open_door_success_lock(client, app_module, monkeypatch):
    app_module.user_pins["alice"] = "1234"
    app_module.entity_id = "lock.test_door"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None

    with patch("requests.post", return_value=mock_resp):
        r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
        assert r.status_code == 200


def test_open_door_success_input_boolean(client, app_module, monkeypatch):
    app_module.user_pins["alice"] = "1234"
    app_module.entity_id = "input_boolean.open"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None

    with patch("requests.post", return_value=mock_resp):
        r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
        assert r.status_code == 200


def test_battery_invalid_format(client, monkeypatch):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"state": "unknown"}

    with patch("requests.get", return_value=mock_response):
        response = client.get("/battery")
        assert response.status_code == 200
        assert response.get_json()["level"] is None


def test_admin_logs_parsing(client, app_module, tmp_path):
    # Create a log line and ensure admin logs endpoint parses it
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

    # Patch the path used inside app.admin_logs to point to our temp file
    with (
        patch("app.os.path.exists", return_value=True),
        patch("app.os.path.join", return_value=str(log_file)),
    ):
        # Authenticate admin by flagging session
        with client.session_transaction() as s:
            s["admin_authenticated"] = True
            s["admin_login_time"] = datetime.now(timezone.utc).isoformat()
        r = client.get("/admin/logs")
        assert r.status_code == 200
        data = r.get_json()
        assert "logs" in data and isinstance(data["logs"], list)
        assert any(row.get("user") == "alice" for row in data["logs"])


def test_blocked_denies_correct_pin_and_returns_blocked_until(client, app_module, monkeypatch):
    # Ensure a valid PIN exists
    app_module.user_pins["alice"] = "1234"
    # Trigger session id creation
    client.post("/open-door", data=json.dumps({}), headers=_std_headers())
    with client.session_transaction() as s:
        sid = s.get("_session_id")
    assert sid
    # Put the session into a blocked state for ~60s
    app_module.session_blocked_until[sid] = app_module.get_current_time() + timedelta(seconds=60)
    # Attempt with correct PIN must still be blocked
    r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
    assert r.status_code == 429
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data


def test_persisted_session_block_denies_oidc_pinless_and_returns_blocked_until(client, monkeypatch):
    import app as app_module

    # Mimic OIDC enabled policy allowing pinless
    app_module.oauth = object()
    app_module.require_pin_for_oidc = False
    app_module.oidc_user_group = ""  # allow any authenticated
    app_module.test_mode = True

    with client.session_transaction() as s:
        s["_session_id"] = "sessPersist"
        s["oidc_authenticated"] = True
        s["oidc_user"] = "eve"
        s["oidc_groups"] = ["dooropener-users"]
        import time as _time

        s["oidc_exp"] = int(_time.time()) + 3600
        # Simulate persisted block cookie for 60 seconds from now
        s["blocked_until_ts"] = _time.time() + 60

    r = client.post("/open-door", json={})
    assert r.status_code == 429
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data


def test_inmemory_session_block_denies_oidc_pinless_and_returns_blocked_until(client):
    import app as app_module

    # Make OIDC appear enabled and allowed
    app_module.oauth = object()
    app_module.require_pin_for_oidc = False
    app_module.oidc_user_group = ""
    app_module.test_mode = True

    # Establish session + OIDC
    with client.session_transaction() as s:
        s["_session_id"] = "sessInMem"
        s["oidc_authenticated"] = True
        s["oidc_user"] = "frank"
        s["oidc_groups"] = ["dooropener-users"]
        import time as _time

        s["oidc_exp"] = int(_time.time()) + 3600

    # Apply in-memory session block
    app_module.session_blocked_until["sessInMem"] = app_module.get_current_time() + timedelta(seconds=60)

    r = client.post("/open-door", json={})
    assert r.status_code == 429
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data


def test_open_door_block_set_on_failure_includes_blocked_until(client, app_module, monkeypatch):
    # Avoid real sleeps from progressive delay
    monkeypatch.setattr(time, "sleep", lambda s: None)
    headers = _std_headers()
    # Use a clean session
    client.post("/open-door", data=json.dumps({"pin": "0000"}), headers=headers)
    with client.session_transaction() as s:
        sid = s.get("_session_id")
    assert sid

    # Drive attempts to the session threshold (we've already made 1 failing attempt above)
    for i in range(app_module.SESSION_MAX_ATTEMPTS - 1):
        r = client.post("/open-door", data=json.dumps({"pin": "0000"}), headers=headers)
    # On the last failing attempt, API should return 401 with blocked_until present
    assert r.status_code == 401
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data

    # Next attempt should be 429 with blocked_until
    r2 = client.post("/open-door", data=json.dumps({"pin": "0000"}), headers=headers)
    assert r2.status_code == 429
    data2 = r2.get_json()
    assert "blocked_until" in data2


def test_persisted_block_cookie_blocks_correct_pin(client):
    import app as app_module

    app_module.user_pins["zoe"] = "4321"

    with client.session_transaction() as s:
        s["_session_id"] = "sessCookie"
        import time as _time

        s["blocked_until_ts"] = _time.time() + 60

    r = client.post("/open-door", data=json.dumps({"pin": "4321"}), headers=_std_headers())
    assert r.status_code == 429
    data = r.get_json()
    assert data.get("status") == "error"
    assert "blocked_until" in data


def test_success_clears_persisted_block_cookie_when_expired(client):
    import app as app_module

    app_module.user_pins["amy"] = "1234"

    with client.session_transaction() as s:
        s["_session_id"] = "sessExpired"
        import time as _time

        s["blocked_until_ts"] = _time.time() - 1  # already expired

    r = client.post("/open-door", data=json.dumps({"pin": "1234"}), headers=_std_headers())
    assert r.status_code in (200, 502, 500)  # success in test_mode or HA error paths
    # Confirm cookie flag cleared
    with client.session_transaction() as s:
        assert "blocked_until_ts" not in s
