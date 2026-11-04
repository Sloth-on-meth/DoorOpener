"""/open-door and /admin/auth edge paths: blocking, OIDC rules, the Home Assistant call, cleanup."""

import time
from datetime import timedelta
from types import SimpleNamespace

import pytest
import requests

UA = {"User-Agent": "pytest-client/1.0 (+https://example.test)"}


@pytest.fixture
def env(monkeypatch):
    import app as app_module

    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    monkeypatch.setattr(app_module, "user_pins", {"ok": "4321"})
    audit = []
    real = app_module.log_attempt

    def spy(status, details, **kw):
        audit.append((status, details, kw.get("user")))
        return real(status, details, **kw)

    monkeypatch.setattr(app_module, "log_attempt", spy)
    return SimpleNamespace(app=app_module, client=app_module.app.test_client(), audit=audit, mp=monkeypatch)


def statuses(env):
    return [a[0] for a in env.audit]


def post(env, body=None, client=None, **kw):
    return (client or env.client).post("/open-door", json=body if body is not None else {}, headers=UA, **kw)


# --- validation and blocking ------------------------------------------------------------------


def test_request_without_a_pin_is_a_400(env):
    r = post(env, {"other": 1})
    assert r.status_code == 400 and r.get_json()["message"] == "PIN required"


def test_invalid_pin_format_is_counted_as_a_failure(env):
    r = post(env, {"pin": "12"})
    assert r.status_code == 400 and "INVALID_FORMAT" in statuses(env)
    assert sum(env.app.ip_failed_attempts.values()) == 1 and env.app.global_failed_attempts == 1


def test_three_wrong_pins_block_the_session_and_the_cookie_remembers_it(env):
    for _ in range(3):
        last = post(env, {"pin": "0000"})
    assert last.status_code == 401 and "blocked_until" in last.get_json()
    blocked = post(env, {"pin": "4321"})  # even the right PIN is refused now
    assert blocked.status_code == 429 and "SESSION_BLOCKED" in statuses(env)
    # the block survives losing the in-memory counters because it lives in the signed cookie
    env.app.session_blocked_until.clear()
    assert post(env, {"pin": "4321"}).status_code == 429


def test_an_expired_cookie_block_no_longer_applies(env):
    with env.client.session_transaction() as s:
        s["blocked_until_ts"] = time.time() - 5
    assert post(env, {"pin": "4321"}).status_code == 200


def test_ip_block_refuses_the_right_pin_with_the_remaining_time(env):
    for _ in range(env.app.MAX_ATTEMPTS):
        env.client.delete_cookie("session")  # fresh session each time so only the IP accumulates
        post(env, {"pin": "0000"})
    env.client.delete_cookie("session")
    r = post(env, {"pin": "4321"})
    assert r.status_code == 429 and r.get_json()["blocked_until"] > time.time()
    assert "IP_BLOCKED" in statuses(env)


def test_block_is_enforced_even_if_it_appears_after_the_early_checks(env):
    """_enforce_active_block is the last gate before a correct PIN opens the door."""
    now = env.app.get_current_time()
    env.mp.setattr(env.app, "get_client_identifier", lambda: ("9.9.9.9", "sess", "ident"))
    env.app.ip_blocked_until["ident"] = now + timedelta(minutes=3)
    env.app.session_blocked_until["sess"] = now + timedelta(minutes=1)
    with env.app.app.app_context():
        resp, code = env.app._enforce_active_block("sess", "ident", now, "9.9.9.9", "ok")
        assert code == 429 and 150 < resp.get_json()["blocked_until"] - now.timestamp() < 200
        assert env.app._enforce_active_block("other", "other", now, "9.9.9.9", "ok") is None
    assert "BLOCK_ENFORCED" in statuses(env)


def test_success_clears_counters_blocks_and_the_cookie_block(env):
    env.client.post("/open-door", json={"pin": "0000"}, headers=UA)
    with env.client.session_transaction() as s:
        s["blocked_until_ts"] = time.time() - 1
    assert post(env, {"pin": "4321"}).status_code == 200
    assert not any(env.app.ip_failed_attempts.values())
    with env.client.session_transaction() as s:
        assert "blocked_until_ts" not in s


# --- OIDC pinless rules -----------------------------------------------------------------------


@pytest.fixture
def oidc(env):
    env.mp.setattr(env.app, "oauth", object())
    env.mp.setattr(env.app, "require_pin_for_oidc", False)
    env.mp.setattr(env.app, "oidc_user_group", "door-users")
    env.mp.setattr(env.app, "test_mode", True)

    def login(groups=("door-users",), exp=None, user="alice"):
        with env.client.session_transaction() as s:
            s["oidc_authenticated"] = True
            s["oidc_user"] = user
            s["oidc_groups"] = list(groups)
            s["oidc_exp"] = int(time.time()) + 3600 if exp is None else exp

    env.login = login
    return env


def test_oidc_user_opens_without_a_pin(oidc):
    oidc.login()
    r = post(oidc)
    assert r.status_code == 200 and "via OIDC" in [a[1] for a in oidc.audit if a[0] == "SUCCESS"][0]


def test_oidc_user_outside_the_group_still_needs_a_pin(oidc):
    oidc.login(groups=("someone-else",))
    assert post(oidc).status_code == 400  # "PIN required"


def test_policy_can_require_a_pin_even_for_oidc_users(oidc):
    oidc.mp.setattr(oidc.app, "require_pin_for_oidc", True)
    oidc.login()
    assert post(oidc).status_code == 400
    assert post(oidc, {"pin": "4321"}).status_code == 200


def test_expired_oidc_session_is_cleared_and_asks_to_log_in_again(oidc):
    oidc.login(exp=int(time.time()) - 10)
    r = post(oidc)
    assert r.status_code == 401 and "expired" in r.get_json()["message"].lower()
    with oidc.client.session_transaction() as s:
        assert not s.get("oidc_authenticated") and not s.get("oidc_user")


def test_expired_oidc_session_can_still_use_a_pin(oidc):
    oidc.login(exp=int(time.time()) - 10)
    assert post(oidc, {"pin": "4321"}).status_code == 200


def test_oidc_pinless_open_is_refused_while_blocked(oidc):
    oidc.login()
    with oidc.client.session_transaction() as s:
        s["blocked_until_ts"] = time.time() + 300
    assert post(oidc).status_code == 429


# --- the Home Assistant call ------------------------------------------------------------------


@pytest.fixture
def ha(env):
    env.mp.setattr(env.app, "test_mode", False)
    calls = []
    touched = []
    env.mp.setattr(env.app.users_store, "touch_user", lambda u: touched.append(u))
    env.calls, env.touched = calls, touched

    def respond(status=200, error=None):
        def fake_post(url, **kw):
            calls.append((url, kw))
            if error:
                raise error
            return SimpleNamespace(status_code=status, raise_for_status=lambda: None)

        env.mp.setattr(env.app.requests, "post", fake_post)

    env.respond = respond
    return env


@pytest.mark.parametrize(
    "entity, service",
    [
        ("lock.front", "/api/services/lock/unlock"),
        ("input_boolean.door", "/api/services/input_boolean/turn_on"),
        ("switch.door", "/api/services/switch/turn_on"),
    ],
)
def test_service_url_depends_on_the_entity_type(ha, entity, service):
    ha.mp.setattr(ha.app, "entity_id", entity)
    ha.respond(200)
    assert post(ha, {"pin": "4321"}).status_code == 200
    url, kw = ha.calls[0]
    assert url.endswith(service) and kw["json"] == {"entity_id": entity}
    assert kw["headers"]["Authorization"].startswith("Bearer ") and kw["timeout"] == 10
    assert ha.touched == ["ok"]


def test_ha_success_counts_a_use_and_logs_success(ha):
    ha.respond(200)
    r = post(ha, {"pin": "4321"})
    assert r.status_code == 200 and "Welcome home, Ok!" in r.get_json()["message"]
    assert statuses(ha) == ["SUCCESS"]


def test_a_non_200_success_status_is_a_failure(ha):
    ha.respond(204)
    r = post(ha, {"pin": "4321"})
    assert r.status_code == 500 and statuses(ha) == ["FAILURE"] and ha.touched == []


def test_ha_http_error_is_a_502_and_does_not_count_a_use(ha):
    ha.respond(error=requests.HTTPError("500"))
    assert post(ha, {"pin": "4321"}).status_code == 502 and ha.touched == []


def test_unexpected_error_is_logged_with_a_traceback_and_a_generic_message(ha):
    ha.respond(error=ValueError("boom"))
    r = post(ha, {"pin": "4321"})
    assert r.status_code == 500 and r.get_json()["message"] == "Internal server error during API call"
    assert "API_FAILURE" in statuses(ha) and "boom" not in r.get_data(as_text=True)


def test_ca_bundle_is_passed_to_requests_when_configured(ha):
    ha.mp.setattr(ha.app, "ha_ca_bundle", "/etc/ha-ca.pem")
    ha.respond(200)
    post(ha, {"pin": "4321"})
    assert ha.calls[0][1]["verify"] == "/etc/ha-ca.pem"


# --- admin login throttling -------------------------------------------------------------------


def test_admin_login_success_and_remember_me(env):
    r = env.client.post("/admin/auth", json={"password": "testpass", "remember_me": True})
    assert r.status_code == 200
    with env.client.session_transaction() as s:
        assert s["admin_authenticated"] and s.permanent is True
    env.client.post(
        "/admin/logout", headers={"X-CSRF-Token": env.client.get("/admin/check-auth").get_json()["csrf_token"]}
    )
    env.client.post("/admin/auth", json={"password": "testpass"})
    with env.client.session_transaction() as s:
        assert s.permanent is False


def test_admin_login_with_wrong_or_missing_password_is_a_403(env):
    assert env.client.post("/admin/auth", json={"password": "nope"}).status_code == 403
    assert env.client.post("/admin/auth", json={}).status_code == 403


def test_three_wrong_admin_passwords_block_the_session(env):
    for _ in range(3):
        env.client.post("/admin/auth", json={"password": "nope"})
    r = env.client.post("/admin/auth", json={"password": "testpass"})
    assert r.status_code == 429  # even the right password, until the block expires


def test_admin_login_ip_block_applies_across_sessions(env):
    for _ in range(3):
        env.client.delete_cookie("session")
        env.client.post("/admin/auth", json={"password": "nope"})
    env.client.delete_cookie("session")
    assert env.client.post("/admin/auth", json={"password": "testpass"}).status_code == 429


# --- rate-limit housekeeping ------------------------------------------------------------------


def test_cleanup_evicts_idle_clients_but_keeps_recent_ones_and_prunes_reports(env):
    app = env.app
    now_mono = time.monotonic()
    env.mp.setattr(app, "_last_cleanup_mono", float("-inf"))  # not 0.0: monotonic() counts from boot
    env.mp.setattr(app, "_rate_limit_last_seen", {"idle": now_mono - 10**6, "recent": now_mono})
    app.ip_failed_attempts.update({"idle": 3, "recent": 2})
    app.block_strikes.update({"idle": 2})
    now = app.get_current_time()
    app.ip_blocked_until["expired"] = now - timedelta(minutes=1)
    env.mp.setattr(app, "_report_timestamps", {"old-ip": [now - timedelta(hours=3)], "new-ip": [now]})
    app._cleanup_rate_limit_state()
    assert "idle" not in app.ip_failed_attempts and "idle" not in app.block_strikes
    assert app.ip_failed_attempts["recent"] == 2
    assert "expired" not in app.ip_blocked_until
    assert list(app._report_timestamps) == ["new-ip"]


def test_cleanup_is_throttled(env):
    app = env.app
    env.mp.setattr(app, "_last_cleanup_mono", time.monotonic())
    env.mp.setattr(app, "_rate_limit_last_seen", {"idle": 0.0})
    app.ip_failed_attempts["idle"] = 1
    app._cleanup_rate_limit_state()
    assert app.ip_failed_attempts["idle"] == 1  # swept too recently: nothing evicted
