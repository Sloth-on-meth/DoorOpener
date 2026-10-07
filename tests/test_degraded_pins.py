"""An unreadable users.json must not re-enable users who were disabled in the store."""

import pytest

from users_store import UsersStore

HEADERS = {"User-Agent": "pytest-client/1.0 (+https://example.test)", "Content-Type": "application/json"}


def test_degraded_pins_fail_closed_without_a_good_snapshot(tmp_path):
    store = UsersStore(str(tmp_path / "users.json"))
    assert store.degraded_pins({"on": "2222"}) == {}


def test_degraded_pins_reflect_disable_made_after_the_last_login(tmp_path):
    """update_user() must refresh the snapshot, not just effective_pins()."""
    path = tmp_path / "users.json"
    store = UsersStore(str(path))
    store.create_user("alice", "1111")
    base = {"alice": "1111", "bob": "2222"}
    store.effective_pins(base)
    store.update_user("alice", active=False)
    path.write_text("{corrupt")
    assert store.degraded_pins(base) == {"bob": "2222"}


def test_degraded_pins_do_not_resurrect_a_config_pin_the_store_replaced(tmp_path):
    path = tmp_path / "users.json"
    store = UsersStore(str(path))
    store.create_user("alice", "9999")  # overrides config's alice=1111
    base = {"alice": "1111"}
    assert store.effective_pins(base) == {"alice": "9999"}
    path.write_text("{corrupt")
    assert store.degraded_pins(base) == {"alice": "9999"}


def test_degraded_pins_exclude_users_known_disabled(tmp_path):
    path = tmp_path / "users.json"
    store = UsersStore(str(path))
    store.create_user("off", "1111", active=False)
    base = {"off": "1111", "on": "2222"}
    assert store.effective_pins(base) == {"on": "2222"}
    path.write_text("{corrupt")
    with pytest.raises(Exception):
        store.effective_pins(base)
    assert store.degraded_pins(base) == {"on": "2222"}


def test_login_does_not_revive_disabled_config_user_when_store_corrupt(client, tmp_path, monkeypatch):
    import app as app_module

    path = tmp_path / "users.json"
    store = UsersStore(str(path))
    store.create_user("off", "1111", active=False)
    monkeypatch.setattr(app_module, "users_store", store)
    monkeypatch.setattr(app_module, "user_pins", {"off": "1111", "on": "2222"})
    monkeypatch.setattr(app_module, "get_client_identifier", lambda: ("192.0.2.1", "corrupt-session", "corrupt-ip"))

    assert client.post("/open-door", json={"pin": "2222"}, headers=HEADERS).status_code == 200
    path.write_text("{corrupt")
    assert client.post("/open-door", json={"pin": "2222"}, headers=HEADERS).status_code == 200
    response = client.post("/open-door", json={"pin": "1111"}, headers=HEADERS)
    assert response.status_code == 401
    # an unreadable store must not let the wrong-PIN path skip the failure counters
    assert app_module.ip_failed_attempts["corrupt-ip"] == 1
    assert app_module.session_failed_attempts["corrupt-session"] == 1
    assert app_module.global_failed_attempts == 1
