"""The OIDC callback must reject a missing state or nonce, not just a mismatched one."""

import time

import pytest


class FakeAuthentik:
    def __init__(self, claims):
        self.claims = claims
        self.calls = 0

    def authorize_access_token(self):
        self.calls += 1
        return {"id_token": "x", "userinfo": self.claims}

    def parse_id_token(self, token):
        return self.claims


class FakeOAuth:
    def __init__(self, claims):
        self.authentik = FakeAuthentik(claims)


def _claims(**over):
    c = {
        "aud": "client-1",
        "iss": "https://idp.example",
        "exp": int(time.time()) + 600,
        "nonce": "nonce-123",
        "email": "alice@example.com",
        "groups": ["dooropener-users"],
    }
    c.update(over)
    return c


@pytest.fixture
def setup(monkeypatch):
    import app as app_module

    def _setup(claims):
        fake = FakeOAuth(claims)
        monkeypatch.setattr(app_module, "oauth", fake)
        monkeypatch.setattr(app_module, "oidc_client_id", "client-1")
        monkeypatch.setattr(app_module, "oidc_issuer", "https://idp.example")
        monkeypatch.setattr(app_module, "oidc_admin_group", "")
        monkeypatch.setattr(app_module, "oidc_user_group", "")
        app_module.app.config["TESTING"] = True
        return app_module.app.test_client(), fake

    return _setup


def _seed(client, state="state-abc", nonce="nonce-123"):
    with client.session_transaction() as s:
        if state is not None:
            s["oidc_state"] = state
        if nonce is not None:
            s["oidc_nonce"] = nonce


def test_valid_state_and_nonce_logs_in(setup):
    client, _ = setup(_claims())
    _seed(client)
    r = client.get("/oidc/callback?state=state-abc")
    assert r.status_code == 302
    with client.session_transaction() as s:
        assert s["oidc_authenticated"] is True and s["oidc_user"] == "alice@example.com"


def test_missing_state_everywhere_is_rejected_before_any_token_exchange(setup):
    client, fake = setup(_claims())
    _seed(client, state=None)  # no state stored, none supplied: None == None
    assert client.get("/oidc/callback").status_code == 401
    assert fake.authentik.calls == 0


def test_state_supplied_but_none_stored_is_rejected(setup):
    client, fake = setup(_claims())
    _seed(client, state=None)
    assert client.get("/oidc/callback?state=anything").status_code == 401
    assert fake.authentik.calls == 0


def test_state_stored_but_none_supplied_is_rejected(setup):
    client, _ = setup(_claims())
    _seed(client)
    assert client.get("/oidc/callback").status_code == 401


def test_wrong_state_is_rejected(setup):
    client, _ = setup(_claims())
    _seed(client)
    assert client.get("/oidc/callback?state=other").status_code == 401


def test_missing_nonce_everywhere_is_rejected(setup):
    client, _ = setup(_claims(nonce=None))
    _seed(client, nonce=None)  # no nonce stored and none in the token: None == None
    assert client.get("/oidc/callback?state=state-abc").status_code == 401
    with client.session_transaction() as s:
        assert not s.get("oidc_authenticated")


def test_token_without_nonce_is_rejected(setup):
    client, _ = setup(_claims(nonce=None))
    _seed(client)
    assert client.get("/oidc/callback?state=state-abc").status_code == 401


def test_nonce_stored_but_different_is_rejected(setup):
    client, _ = setup(_claims(nonce="attacker"))
    _seed(client)
    assert client.get("/oidc/callback?state=state-abc").status_code == 401


def test_state_is_single_use(setup):
    client, _ = setup(_claims())
    _seed(client)
    assert client.get("/oidc/callback?state=state-abc").status_code == 302
    assert client.get("/oidc/callback?state=state-abc").status_code == 401  # replay
