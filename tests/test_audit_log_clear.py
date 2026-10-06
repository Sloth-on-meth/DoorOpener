"""The audit log must keep recording after an admin clears entries."""

import logging
import time
import uuid

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


def test_entry_written_during_test_only_clear_is_not_lost(client, app_module, monkeypatch):
    """A concurrent audit write between the read and the swap must wait for the lock, not vanish."""
    import threading

    headers = _login(client)
    marker = f"during-clear-{uuid.uuid4().hex}"
    real_load = app_module.json.loads
    started = threading.Event()
    writer = threading.Thread(
        target=lambda: (started.set(), app_module.log_attempt("SUCCESS", marker, user="w", primary_ip="9.9.9.9"))
    )

    def slow_loads(*a, **kw):
        # first audit line parsed: kick off a concurrent writer while the clear is mid-filter
        # (request-body parsing also goes through json.loads, so key on the audit entry itself)
        if not started.is_set() and isinstance(a[0], str) and '"timestamp"' in a[0]:
            writer.start()
            started.wait()
            time.sleep(0.3)  # give an unlocked writer time to land between the read and the swap
        return real_load(*a, **kw)

    app_module.log_attempt("SUCCESS", "Door opened (TEST MODE)", user="seed")
    monkeypatch.setattr(app_module.json, "loads", slow_loads)
    r = client.post("/admin/logs/clear", json={"mode": "test_only"}, headers=headers)
    monkeypatch.setattr(app_module.json, "loads", real_load)
    writer.join(timeout=10)
    assert r.status_code == 200
    assert marker in _details(client)
