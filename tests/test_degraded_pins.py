"""An unreadable users.json must not re-enable users who were disabled in the store."""

import pytest

from users_store import UsersStore

HEADERS = {"User-Agent": "pytest-client/1.0 (+https://example.test)", "Content-Type": "application/json"}


def test_degraded_pins_fail_closed_without_a_good_snapshot(tmp_path):
    store = UsersStore(str(tmp_path / "users.json"))
    assert store.degraded_pins({"on": "2222"}) == {}


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
    app_module.user_pins.update({"off": "1111", "on": "2222"})

    assert client.post("/open-door", json={"pin": "2222"}, headers=HEADERS).status_code == 200
    path.write_text("{corrupt")
    assert client.post("/open-door", json={"pin": "2222"}, headers=HEADERS).status_code == 200
    assert client.post("/open-door", json={"pin": "1111"}, headers=HEADERS).status_code == 401
