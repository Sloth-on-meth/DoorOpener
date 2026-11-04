"""A valid PIN that fails to open the door because Home Assistant failed must be audited."""

import pytest
import requests

UA = {"User-Agent": "pytest-client/1.0 (+https://example.test)"}


@pytest.fixture
def setup(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "test_mode", False)
    monkeypatch.setattr(app_module, "user_pins", {"ok": "4321"})
    calls = []
    monkeypatch.setattr(app_module, "log_attempt", lambda status, details, **kw: calls.append((status, details, kw)))
    touched = []
    monkeypatch.setattr(app_module.users_store, "touch_user", lambda u: touched.append(u))
    app_module.app.config["TESTING"] = True
    return app_module, app_module.app.test_client(), calls, touched


def _http_error(code):
    resp = requests.Response()
    resp.status_code = code
    err = requests.HTTPError(f"{code} Server Error for url: http://secret-ha.local:8123/api", response=resp)
    return err


@pytest.mark.parametrize(
    "exc, expected",
    [
        (
            requests.ConnectionError("http://secret-ha.local:8123 refused"),
            "Home Assistant unreachable (ConnectionError)",
        ),
        (requests.Timeout("timed out"), "Home Assistant unreachable (Timeout)"),
        (_http_error(401), "Home Assistant API error: 401"),
        (_http_error(500), "Home Assistant API error: 500"),
    ],
)
def test_ha_failure_after_a_valid_pin_is_audited(setup, monkeypatch, exc, expected):
    app_module, client, calls, touched = setup

    def boom(*a, **kw):
        raise exc

    monkeypatch.setattr(app_module.requests, "post", boom)
    r = client.post("/open-door", json={"pin": "4321"}, headers=UA)
    assert r.status_code == 502  # user-visible behaviour is unchanged
    assert r.get_json()["message"] == "Failed to contact Home Assistant"
    failures = [c for c in calls if c[0] == "FAILURE"]
    assert len(failures) == 1
    assert failures[0][1] == expected
    assert failures[0][2]["user"] == "ok"
    assert touched == []  # a failed open is not counted as a use


def test_audit_entry_never_contains_the_ha_url_or_token(setup, monkeypatch):
    app_module, client, calls, _ = setup

    def boom(*a, **kw):
        raise requests.ConnectionError("HTTPConnectionPool(host='secret-ha.local', port=8123): Max retries")

    monkeypatch.setattr(app_module.requests, "post", boom)
    client.post("/open-door", json={"pin": "4321"}, headers=UA)
    blob = repr(calls)
    assert "secret-ha.local" not in blob and app_module.ha_token not in blob


def test_successful_open_is_still_recorded_as_success(setup, monkeypatch):
    app_module, client, calls, touched = setup

    class OK:
        status_code = 200

        def raise_for_status(self):
            pass

    monkeypatch.setattr(app_module.requests, "post", lambda *a, **kw: OK())
    r = client.post("/open-door", json={"pin": "4321"}, headers=UA)
    assert r.status_code == 200
    assert [c[0] for c in calls] == ["SUCCESS"] and touched == ["ok"]
