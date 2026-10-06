"""A disabled account's PIN must be indistinguishable from a wrong PIN and count as a failure."""

HEADERS = {"User-Agent": "pytest-client/1.0 (+https://example.test)", "Content-Type": "application/json"}


def test_disabled_user_pin_counts_and_looks_like_wrong_pin(client, tmp_path, monkeypatch):
    import app as app_module
    from users_store import UsersStore

    store = UsersStore(str(tmp_path / "users.json"))
    store.create_user("gone", "7777", active=False)
    monkeypatch.setattr(app_module, "users_store", store)

    wrong = client.post("/open-door", json={"pin": "0000"}, headers=HEADERS)
    disabled = client.post("/open-door", json={"pin": "7777"}, headers=HEADERS)
    assert disabled.status_code == wrong.status_code == 401
    assert disabled.get_json()["message"] == wrong.get_json()["message"]
    assert sum(app_module.ip_failed_attempts.values()) == 2
    assert app_module.global_failed_attempts == 2


def test_disabled_user_attempt_is_audited_with_account_name(client, tmp_path, monkeypatch):
    import app as app_module
    from users_store import UsersStore

    store = UsersStore(str(tmp_path / "users.json"))
    store.create_user("gone", "7777", active=False)
    monkeypatch.setattr(app_module, "users_store", store)
    calls = []
    monkeypatch.setattr(app_module, "log_attempt", lambda status, details, **kw: calls.append((status, kw.get("user"))))
    client.post("/open-door", json={"pin": "7777"}, headers=HEADERS)
    assert ("DISABLED_USER", "gone") in calls
