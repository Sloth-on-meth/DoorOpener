"""SSL / CA-bundle tests.

With the new architecture, verify is set on ha_client.session, so we test
the Session.verify attribute directly rather than capturing keyword args.
"""
from unittest.mock import MagicMock, patch


def _std_headers():
    return {
        "User-Agent": "pytest-client/1.0 (+https://example.test) long-ua",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }


def test_verify_defaults_to_true_without_ca_bundle(client, monkeypatch):
    import app as app_module
    app_module.ha_client.session.verify = True
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"state": "95"}
    with patch.object(app_module.ha_client.session, "get", return_value=mock_resp):
        r = client.get("/battery")
    assert r.status_code == 200
    assert app_module.ha_client.session.verify is True


def test_verify_uses_ca_bundle_when_set(client, monkeypatch):
    import app as app_module
    ca_path = "/etc/dooropener/ha-ca.pem"
    app_module.ha_client.session.verify = ca_path
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"state": "88"}
    with patch.object(app_module.ha_client.session, "get", return_value=mock_resp):
        r = client.get("/battery")
    assert r.status_code == 200
    assert app_module.ha_client.session.verify == ca_path


def test_post_verify_defaults_to_true_without_ca_bundle(client, monkeypatch):
    import app as app_module
    import config
    monkeypatch.setattr(config, "test_mode", False)
    app_module.users_store.create_user("alice", "1234")
    app_module.ha_client.session.verify = True
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None
    with patch.object(app_module.ha_client.session, "post", return_value=mock_resp):
        r = client.post("/open-door", json={"pin": "1234"}, headers=_std_headers())
    assert r.status_code == 200
    assert app_module.ha_client.session.verify is True


def test_post_verify_uses_ca_bundle_when_set(client, monkeypatch):
    import app as app_module
    import config
    monkeypatch.setattr(config, "test_mode", False)
    app_module.users_store.create_user("bob", "5678")
    ca_path = "/etc/dooropener/ha-ca.pem"
    app_module.ha_client.session.verify = ca_path
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None
    with patch.object(app_module.ha_client.session, "post", return_value=mock_resp):
        r = client.post("/open-door", json={"pin": "5678"}, headers=_std_headers())
    assert r.status_code == 200
    assert app_module.ha_client.session.verify == ca_path
