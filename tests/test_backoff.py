"""Exponential per-client backoff replaces the global lockout."""


def test_block_duration_doubles_and_caps():
    import app as app_module

    first = app_module.next_block_duration("k")
    second = app_module.next_block_duration("k")
    assert second == first * 2
    for _ in range(30):
        d = app_module.next_block_duration("k")
    assert d == app_module.MAX_BLOCK_TIME


def test_block_duration_first_block_is_configured_block_time():
    import app as app_module

    assert app_module.next_block_duration("fresh") == app_module.BLOCK_TIME


def test_successful_login_resets_backoff(client, monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "get_client_identifier", lambda: ("5.5.5.5", "sessBackoff", "idBackoff"))
    app_module.user_pins["ok"] = "4321"
    app_module.block_strikes["idBackoff"] = 3
    app_module.block_strikes["sessBackoff"] = 2
    h = {"User-Agent": "pytest-client/1.0 (+https://example.test)", "Content-Type": "application/json"}
    assert client.post("/open-door", json={"pin": "4321"}, headers=h).status_code == 200
    assert "idBackoff" not in app_module.block_strikes
    assert "sessBackoff" not in app_module.block_strikes


def test_cleanup_keeps_blocked_client_state_for_the_full_backoff(monkeypatch):
    """A client blocked for up to MAX_BLOCK_TIME must not be evicted before the block expires."""
    import time

    import app as app_module

    now = app_module.get_current_time()
    app_module.ip_blocked_until["1.2.3.4"] = now + app_module.MAX_BLOCK_TIME
    app_module.block_strikes["1.2.3.4"] = 5
    # idle for 3 hours: past the old 1h+10m TTL, well inside the 24h block
    app_module._rate_limit_last_seen["1.2.3.4"] = time.monotonic() - 3 * 3600
    monkeypatch.setattr(app_module, "_last_cleanup_mono", 0.0)
    app_module._cleanup_rate_limit_state()
    assert app_module.ip_blocked_until.get("1.2.3.4")
    assert app_module.block_strikes.get("1.2.3.4") == 5


def test_notify_admin_logs_http_errors(monkeypatch, caplog):
    import requests

    import app as app_module

    class Resp:
        def raise_for_status(self):
            raise requests.HTTPError("401 Unauthorized")

    monkeypatch.setattr(app_module, "pushbullet_token", "tok")
    monkeypatch.setattr(app_module.requests, "post", lambda *a, **kw: Resp())
    with caplog.at_level("ERROR", logger="dooropener"):
        app_module._notify_admin("t", "b")
    assert "Pushbullet alert failed" in caplog.text
