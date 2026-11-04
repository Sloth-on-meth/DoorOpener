"""Admin sessions are stateless signed cookies, so the server must enforce their age."""

from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


@pytest.fixture
def client(app_module, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    with app_module.app.test_client() as c:
        yield c


def _session(client, *, age, permanent=False, login_time="auto"):
    with client.session_transaction() as s:
        s["admin_authenticated"] = True
        s["admin_csrf_token"] = "tok"
        if login_time == "auto":
            s["admin_login_time"] = (datetime.now(timezone.utc) - age).isoformat()
        elif login_time is not None:
            s["admin_login_time"] = login_time
        s.permanent = permanent


def _authed(client):
    return client.get("/admin/check-auth").get_json()["authenticated"]


def test_fresh_session_is_valid(client):
    _session(client, age=timedelta(minutes=5))
    assert _authed(client) is True


def test_session_older_than_the_limit_is_rejected_and_cleared(client, app_module):
    _session(client, age=app_module.ADMIN_SESSION_MAX_AGE + timedelta(minutes=1))
    assert _authed(client) is False
    with client.session_transaction() as s:
        assert "admin_authenticated" not in s and "admin_csrf_token" not in s


def test_protected_endpoints_reject_an_expired_session(client, app_module):
    _session(client, age=app_module.ADMIN_SESSION_MAX_AGE + timedelta(hours=1))
    assert client.get("/admin/users").status_code == 401
    assert client.get("/admin/logs").status_code == 401
    assert client.post("/admin/logs/clear", json={"mode": "all"}, headers={"X-CSRF-Token": "tok"}).status_code == 401
    assert client.post("/admin/notice", json={"notice": "x"}, headers={"X-CSRF-Token": "tok"}).status_code == 401


def test_admin_page_does_not_render_as_authenticated_when_expired(client, app_module):
    _session(client, age=app_module.ADMIN_SESSION_MAX_AGE + timedelta(hours=1))
    assert client.get("/admin").status_code == 200
    assert _authed(client) is False


def test_remember_me_session_lives_longer_but_not_forever(client, app_module):
    between = app_module.ADMIN_SESSION_MAX_AGE + timedelta(hours=1)
    assert between < app_module.ADMIN_REMEMBER_MAX_AGE
    _session(client, age=between, permanent=True)
    assert _authed(client) is True
    _session(client, age=app_module.ADMIN_REMEMBER_MAX_AGE + timedelta(hours=1), permanent=True)
    assert _authed(client) is False


@pytest.mark.parametrize("login_time", [None, "not-a-date", "2999-01-01T00:00:00+00:00"])
def test_missing_garbled_or_future_login_time_fails_closed(client, login_time):
    _session(client, age=timedelta(0), login_time=login_time)
    assert _authed(client) is False


def test_naive_login_time_is_treated_as_utc(client):
    _session(client, age=timedelta(0), login_time=datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
    assert _authed(client) is True


def test_login_then_logout_roundtrip_still_works(client):
    assert client.post("/admin/auth", json={"password": "testpass"}).status_code == 200
    token = client.get("/admin/check-auth").get_json()["csrf_token"]
    assert client.post("/admin/logout", headers={"X-CSRF-Token": token}).status_code == 200
    assert _authed(client) is False
