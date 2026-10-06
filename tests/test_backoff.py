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
