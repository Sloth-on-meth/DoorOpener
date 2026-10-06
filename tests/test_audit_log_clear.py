"""The audit log must keep recording after an admin clears entries."""

import logging
import uuid

import pytest


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


@pytest.fixture
def client(app_module):
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def _login(client):
    assert client.post("/admin/auth", json={"password": "testpass"}).status_code == 200
    return {"X-CSRF-Token": client.get("/admin/check-auth").get_json()["csrf_token"]}


def _details(client):
    for h in logging.getLogger("door_attempts").handlers:
        h.flush()
    return [row["details"] for row in client.get("/admin/logs").get_json()["logs"]]


@pytest.mark.parametrize("mode", ["test_only", "all"])
def test_audit_log_survives_clear(client, app_module, mode):
    headers = _login(client)
    app_module.log_attempt("SUCCESS", "Door opened (TEST MODE)", user="a")
    r = client.post("/admin/logs/clear", json={"mode": mode}, headers=headers)
    assert r.status_code == 200
    marker = f"after-clear-{uuid.uuid4().hex}"  # unique: the log file can persist across runs
    app_module.log_attempt("SUCCESS", marker, user="c")
    assert marker in _details(client)


def test_admin_logs_reads_the_configured_log_file(client, app_module):
    _login(client)
    marker = f"read-path-{uuid.uuid4().hex}"
    app_module.log_attempt("SUCCESS", marker, user="c")
    assert marker in _details(client)
    assert app_module.log_path.endswith("log.txt")
