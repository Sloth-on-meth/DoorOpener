"""OIDC login, callback validation and logout, driven with a fake Authentik client."""

import time
from types import SimpleNamespace

import pytest


class FakeAuthentik:
    def __init__(self, claims=None, *, userinfo=None, id_token_error=False, token_error=False, token_userinfo=True):
        self.claims = claims
        self._userinfo = userinfo
        self.id_token_error = id_token_error
        self.token_error = token_error
        self.token_userinfo = token_userinfo
        self.redirect_kwargs = None

    def authorize_redirect(self, **kwargs):
        from flask import redirect

        self.redirect_kwargs = kwargs
        return redirect("https://idp.example/authorize")

    def authorize_access_token(self):
        if self.token_error:
            raise RuntimeError("token exchange failed")
        token = {"id_token": "jwt"}
        if self.token_userinfo:
            token["userinfo"] = self.claims
        return token

    def parse_id_token(self, token):
        if self.id_token_error:
            raise RuntimeError("bad id token")
        return self.claims

    def userinfo(self, token=None):
        if self._userinfo is None:
            raise RuntimeError("no userinfo")
        return self._userinfo


def make_claims(**over):
    claims = {
        "aud": "client-1",
        "iss": "https://idp.example/application/o/door",
        "exp": int(time.time()) + 600,
        "nonce": "nonce-1",
        "email": "alice@example.com",
        "groups": ["door-users"],
    }
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


@pytest.fixture
def env(monkeypatch):
    import app as app_module

    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    monkeypatch.setattr(app_module, "oidc_client_id", "client-1")
    monkeypatch.setattr(app_module, "oidc_issuer", "https://idp.example/application/o/door")
    monkeypatch.setattr(app_module, "oidc_admin_group", "")
    monkeypatch.setattr(app_module, "oidc_user_group", "")

    def install(authentik):
        monkeypatch.setattr(app_module, "oauth", SimpleNamespace(authentik=authentik))
        return app_module.app.test_client()

    return SimpleNamespace(app=app_module, install=install, monkeypatch=monkeypatch)


def callback(client, *, state="s-1", nonce="nonce-1", plant=None):
    with client.session_transaction() as s:
        if state:
            s["oidc_state"] = state
        if nonce:
            s["oidc_nonce"] = nonce
        for k, v in (plant or {}).items():
            s[k] = v
    return client.get(f"/oidc/callback?state={state or ''}")


def denied(client, resp, code=401):
    """The visitor was refused with exactly `code` and no session of any kind was created."""
    with client.session_transaction() as s:
        assert not s.get("oidc_authenticated")
        assert not s.get("admin_authenticated")
    return resp.status_code == code


# --- login redirect ---------------------------------------------------------------------------


def test_login_without_oidc_falls_back_to_admin_page(client):
    import app as app_module

    assert app_module.oauth is None
    r = client.get("/login")
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin")


def test_login_stores_state_and_nonce_and_passes_them_to_the_provider(env):
    fake = FakeAuthentik()
    client = env.install(fake)
    r = client.get("/login")
    assert r.status_code == 302
    with client.session_transaction() as s:
        assert s["oidc_state"] and s["oidc_nonce"] and s["oidc_state"] != s["oidc_nonce"]
        assert fake.redirect_kwargs["state"] == s["oidc_state"]
        assert fake.redirect_kwargs["nonce"] == s["oidc_nonce"]


def test_callback_without_oidc_redirects_to_admin(client):
    r = client.get("/oidc/callback?state=x")
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin")


# --- successful logins ------------------------------------------------------------------------


def test_login_with_no_group_policy_creates_a_user_session_only(env):
    client = env.install(FakeAuthentik(make_claims()))
    r = callback(client)
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    with client.session_transaction() as s:
        assert s["oidc_authenticated"] is True
        assert s["oidc_user"] == "alice@example.com"
        assert s["oidc_groups"] == ["door-users"]
        assert s["oidc_exp"] > time.time()
        assert not s.get("admin_authenticated")


def test_admin_group_member_also_gets_an_admin_session(env):
    env.monkeypatch.setattr(env.app, "oidc_admin_group", "door-admins")
    client = env.install(FakeAuthentik(make_claims(groups=["door-admins"])))
    assert callback(client).status_code == 302
    with client.session_transaction() as s:
        assert s["admin_authenticated"] is True
        assert s["admin_user"] == "alice@example.com"
        assert s["admin_csrf_token"] and s["admin_login_time"]
    assert client.get("/admin/check-auth").get_json()["authenticated"] is True


def test_user_group_member_is_not_an_admin(env):
    env.monkeypatch.setattr(env.app, "oidc_user_group", "door-users")
    env.monkeypatch.setattr(env.app, "oidc_admin_group", "door-admins")
    client = env.install(FakeAuthentik(make_claims(groups=["door-users"])))
    assert callback(client).status_code == 302
    with client.session_transaction() as s:
        assert s["oidc_authenticated"] and not s.get("admin_authenticated")


def test_groups_as_a_comma_separated_string_and_the_roles_claim(env):
    env.monkeypatch.setattr(env.app, "oidc_user_group", "door-users")
    client = env.install(FakeAuthentik(make_claims(groups=None, roles="other, door-users")))
    assert callback(client).status_code == 302
    with client.session_transaction() as s:
        assert s["oidc_groups"] == ["other", "door-users"]


@pytest.mark.parametrize(
    "claims, expected",
    [
        ({"email": None, "preferred_username": "alice"}, "alice"),
        ({"email": None, "preferred_username": None, "name": "Alice A"}, "Alice A"),
        ({"email": None, "preferred_username": None, "name": None}, "oidc-user"),
    ],
)
def test_username_falls_back_through_the_claims(env, claims, expected):
    client = env.install(FakeAuthentik(make_claims(**claims)))
    assert callback(client).status_code == 302
    with client.session_transaction() as s:
        assert s["oidc_user"] == expected


def test_audience_may_be_a_list_and_the_issuer_may_have_a_trailing_slash(env):
    client = env.install(
        FakeAuthentik(make_claims(aud=["other", "client-1"], iss="https://idp.example/application/o/door/"))
    )
    assert callback(client).status_code == 302


def test_claims_fall_back_to_the_id_token_then_to_userinfo(env):
    # no userinfo in the token: parsed from the id_token
    client = env.install(FakeAuthentik(make_claims(), token_userinfo=False))
    assert callback(client).status_code == 302
    # id_token unusable too: the userinfo endpoint supplies the claims
    client = env.install(FakeAuthentik(None, userinfo=make_claims(), token_userinfo=False, id_token_error=True))
    assert callback(client).status_code == 302


def test_session_is_reset_on_login_to_prevent_fixation(env):
    client = env.install(FakeAuthentik(make_claims()))
    callback(client, plant={"planted": "attacker", "admin_authenticated": True})
    with client.session_transaction() as s:
        assert "planted" not in s and not s.get("admin_authenticated")
        assert s["oidc_authenticated"] is True


def test_expiry_and_not_before_allow_a_minute_of_clock_skew(env):
    ok = FakeAuthentik(make_claims(exp=int(time.time()) - 30, nbf=int(time.time()) + 30))
    assert callback(env.install(ok)).status_code == 302


# --- rejected logins --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"aud": "someone-else"},
        {"aud": ["a", "b"]},
        {"aud": None},
        {"iss": "https://evil.example/"},
        {"exp": int(time.time()) - 3600},
        {"nbf": int(time.time()) + 3600},
    ],
)
def test_invalid_audience_issuer_or_times_are_rejected(env, over):
    client = env.install(FakeAuthentik(make_claims(**over)))
    assert denied(client, callback(client))


def test_user_outside_the_required_group_is_denied_with_403(env):
    env.monkeypatch.setattr(env.app, "oidc_user_group", "door-users")
    client = env.install(FakeAuthentik(make_claims(groups=["somewhere-else"])))
    assert denied(client, callback(client), code=403)


def test_group_policy_with_no_groups_in_the_token_is_denied_with_403(env):
    env.monkeypatch.setattr(env.app, "oidc_user_group", "door-users")
    client = env.install(FakeAuthentik(make_claims(groups=None)))
    assert denied(client, callback(client), code=403)


def test_token_exchange_failure_is_a_401(env):
    client = env.install(FakeAuthentik(make_claims(), token_error=True))
    r = callback(client)
    assert r.status_code == 401 and denied(client, r)


def test_claims_that_cannot_be_obtained_are_rejected(env):
    client = env.install(FakeAuthentik(None, token_userinfo=False, id_token_error=True))
    assert denied(client, callback(client))


def test_configured_public_key_validates_the_signature(env):
    seen = {}

    class Decoded(dict):
        def validate(self):
            seen["validated"] = True

    env.monkeypatch.setattr(env.app, "config", SimpleNamespace(get=lambda *a, **k: "PEM-KEY"))
    env.monkeypatch.setattr(env.app.jwt, "decode", lambda token, key: Decoded(make_claims()))
    client = env.install(FakeAuthentik(make_claims()))
    assert callback(client).status_code == 302
    assert seen["validated"] is True


def test_a_bad_signature_is_rejected(env):
    def boom(token, key):
        raise ValueError("signature mismatch")

    env.monkeypatch.setattr(env.app, "config", SimpleNamespace(get=lambda *a, **k: "PEM-KEY"))
    env.monkeypatch.setattr(env.app.jwt, "decode", boom)
    client = env.install(FakeAuthentik(make_claims()))
    assert denied(client, callback(client))


# --- logout -----------------------------------------------------------------------------------


def _discovery(env, monkeypatch, *, status=200, body=None, error=None):
    class Resp:
        status_code = status

        def json(self):
            return body

    def get(url, timeout=None):
        assert url.endswith("/.well-known/openid-configuration")
        if error:
            raise error
        return Resp()

    monkeypatch.setattr(env.app.requests, "get", get)


def test_logout_without_oidc_clears_the_session_and_goes_home(client):
    with client.session_transaction() as s:
        s["anything"] = 1
    r = client.get("/oidc/logout")
    assert r.status_code == 302
    with client.session_transaction() as s:
        assert "anything" not in s


def test_logout_redirects_to_the_provider_end_session_endpoint(env, monkeypatch):
    _discovery(env, monkeypatch, body={"end_session_endpoint": "https://idp.example/logout"})
    client = env.install(FakeAuthentik())
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
    r = client.get("/oidc/logout")
    assert r.status_code == 302 and r.headers["Location"].startswith("https://idp.example/logout?redirect_uri=")
    with client.session_transaction() as s:
        assert not s.get("oidc_authenticated")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"body": {}},  # no end_session_endpoint advertised
        {"status": 503, "body": {}},
        {"error": RuntimeError("network down")},
    ],
)
def test_logout_failures_are_a_500_but_still_clear_the_session(env, monkeypatch, kwargs):
    _discovery(env, monkeypatch, **kwargs)
    client = env.install(FakeAuthentik())
    with client.session_transaction() as s:
        s["oidc_authenticated"] = True
    r = client.get("/oidc/logout")
    assert r.status_code == 500 and r.get_json()["status"] == "error"
    with client.session_transaction() as s:
        assert not s.get("oidc_authenticated")
