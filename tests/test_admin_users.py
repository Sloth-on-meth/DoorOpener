"""Admin user management tests."""
import pytest
import tempfile
import os
from datetime import datetime, timezone

from users_store import UsersStore


def client_app():
    from app import app as flask_app
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


@pytest.fixture
def temp_users_file():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def mock_users_store(temp_users_file, monkeypatch):
    import app as app_module
    store = UsersStore(temp_users_file)
    monkeypatch.setattr(app_module, "users_store", store)
    return store


def _admin_session(client):
    with client.session_transaction() as s:
        s["admin_authenticated"] = True
        s["admin_login_time"] = datetime.now(timezone.utc).isoformat()


def test_admin_users_list_empty(mock_users_store, monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, "user_pins", {})
    c = client_app()
    _admin_session(c)
    response = c.get("/admin/users")
    assert response.status_code == 200
    data = response.get_json()
    assert "users" in data
    assert len(data["users"]) == 0


def test_admin_users_list_with_json_users(mock_users_store, monkeypatch):
    import app as app_module
    monkeypatch.setattr(app_module, "user_pins", {})
    mock_users_store.create_user("alice", "1234")
    mock_users_store.create_user("bob", "5678")
    mock_users_store.touch_user("alice")

    c = client_app()
    _admin_session(c)
    response = c.get("/admin/users")
    assert response.status_code == 200

    data = response.get_json()
    users = data["users"]
    assert len(users) == 2

    alice = next(u for u in users if u["username"] == "alice")
    bob = next(u for u in users if u["username"] == "bob")
    assert alice["source"] == "store"
    assert alice["can_edit"] is True
    assert alice["times_used"] == 1
    assert bob["times_used"] == 0


def test_admin_users_create(mock_users_store):
    c = client_app()
    _admin_session(c)
    response = c.post(
        "/admin/users", json={"username": "newuser", "pin": "1234", "active": True}
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data["status"] == "created"

    users = mock_users_store.list_users()["users"]
    assert len(users) == 1
    assert users[0]["username"] == "newuser"
    assert users[0]["active"] is True
    assert users[0]["times_used"] == 0


def test_admin_users_create_duplicate(mock_users_store):
    mock_users_store.create_user("existing", "1234")
    c = client_app()
    _admin_session(c)
    response = c.post(
        "/admin/users", json={"username": "existing", "pin": "5678", "active": True}
    )
    assert response.status_code == 409
    assert "already exists" in response.get_json()["error"]


def test_admin_users_create_invalid_data(mock_users_store):
    c = client_app()
    _admin_session(c)
    response = c.post("/admin/users", json={"pin": "1234", "active": True})
    assert response.status_code == 400
    response = c.post(
        "/admin/users", json={"username": "test", "pin": "12", "active": True}
    )
    assert response.status_code == 400


def test_admin_users_update(mock_users_store):
    mock_users_store.create_user("testuser", "1234")
    c = client_app()
    _admin_session(c)
    response = c.put("/admin/users/testuser", json={"pin": "5678", "active": False})
    assert response.status_code == 200
    assert response.get_json()["status"] == "updated"
    users = mock_users_store.list_users()["users"]
    assert users[0]["active"] is False


def test_admin_users_update_nonexistent(mock_users_store):
    c = client_app()
    _admin_session(c)
    response = c.put("/admin/users/nonexistent", json={"pin": "1234", "active": True})
    assert response.status_code == 404
    assert "not found" in response.get_json()["error"]


def test_admin_users_delete(mock_users_store):
    mock_users_store.create_user("testuser", "1234")
    c = client_app()
    _admin_session(c)
    response = c.delete("/admin/users/testuser")
    assert response.status_code == 200
    assert response.get_json()["status"] == "deleted"
    assert len(mock_users_store.list_users()["users"]) == 0


def test_admin_users_delete_nonexistent(mock_users_store):
    c = client_app()
    _admin_session(c)
    response = c.delete("/admin/users/nonexistent")
    assert response.status_code == 404
    assert "not found" in response.get_json()["error"]


def test_admin_users_unauthenticated_access(mock_users_store):
    c = client_app()
    endpoints = [
        ("GET", "/admin/users"),
        ("POST", "/admin/users"),
        ("PUT", "/admin/users/test"),
        ("DELETE", "/admin/users/test"),
    ]
    for method, endpoint in endpoints:
        if method == "GET":
            response = c.get(endpoint)
        elif method == "POST":
            response = c.post(endpoint, json={})
        elif method == "PUT":
            response = c.put(endpoint, json={})
        elif method == "DELETE":
            response = c.delete(endpoint)
        assert response.status_code == 401
        assert "Authentication required" in response.get_json()["error"]


def test_times_used_counter_integration(mock_users_store, monkeypatch):
    import app as app_module
    mock_users_store.create_user("testuser", "1234")
    monkeypatch.setattr(app_module, "user_pins", {})
    app_module.test_mode = True

    c = client_app()
    response = c.post(
        "/open-door",
        json={"pin": "1234"},
        headers={
            "User-Agent": "pytest-client/1.0 (+https://example.test)",
            "Accept-Language": "en-US",
        },
    )
    assert response.status_code == 200

    users = mock_users_store.list_users()["users"]
    assert users[0]["times_used"] == 1
    assert users[0]["last_used_at"] is not None


def test_user_management_ui_data_structure(mock_users_store):
    mock_users_store.create_user("active_user", "1111")
    mock_users_store.create_user("inactive_user", "2222")
    mock_users_store.update_user("inactive_user", active=False)
    mock_users_store.touch_user("active_user")
    mock_users_store.touch_user("active_user")

    c = client_app()
    _admin_session(c)
    response = c.get("/admin/users")
    assert response.status_code == 200

    users = response.get_json()["users"]
    for user in users:
        assert "username" in user
        assert "active" in user
        assert "source" in user
        assert "can_edit" in user
        assert "created_at" in user
        assert "last_used_at" in user
        if user["source"] == "store":
            assert "times_used" in user
            assert isinstance(user["times_used"], int)

    active_user = next(u for u in users if u["username"] == "active_user")
    inactive_user = next(u for u in users if u["username"] == "inactive_user")
    assert active_user["active"] is True
    assert active_user["times_used"] == 2
    assert inactive_user["active"] is False
    assert inactive_user["times_used"] == 0
