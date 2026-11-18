"""/admin/logs carries categories; /admin/stats summarises the audit log. Both need an admin session."""

import logging

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


def _flush():
    for h in logging.getLogger("door_attempts").handlers:
        h.flush()


@pytest.mark.parametrize("path", ["/admin/logs", "/admin/stats"])
def test_endpoints_require_an_admin_session(client, path):
    assert client.get(path).status_code == 401


def test_logs_carry_category_label_severity_and_test_flag(client, app_module):
    _login(client)
    app_module.log_attempt("AUTH_FAILURE", "Invalid PIN")
    app_module.log_attempt("SUCCESS", "Door opened (TEST MODE)", user="statuser")
    _flush()
    rows = client.get("/admin/logs").get_json()["logs"]
    wrong = [r for r in rows if r["status"] == "AUTH_FAILURE"][-1]
    assert (wrong["category"], wrong["label"], wrong["severity"]) == ("door", "Wrong PIN", "warn")
    test_open = [r for r in rows if r["user"] == "statuser"][-1]
    assert test_open["test"] is True and test_open["category"] == "door"
    # the fields the previous UI relied on are all still there
    assert {"timestamp", "ip", "user", "status", "details"} <= set(wrong)


def test_stats_reflect_new_entries_and_keep_admin_out_of_door_numbers(client, app_module):
    _login(client)
    before = client.get("/admin/stats").get_json()
    app_module.log_attempt("SUCCESS", "Door opened", user="statuser2")
    app_module.log_attempt("AUTH_FAILURE", "Invalid PIN")
    app_module.log_attempt("IP_BLOCKED", "IP blocked for 60 seconds")
    app_module.attempt_logger.info(
        '{"timestamp": "%s", "ip": "1.1.1.1", "user": "ADMIN", "status": "ADMIN_USER_CREATE", "details": "username=x"}'
        % app_module.get_current_time().isoformat()
    )
    _flush()
    after = client.get("/admin/stats").get_json()
    assert after["door"]["opens"] == before["door"]["opens"] + 1
    assert after["door"]["denied"] == before["door"]["denied"] + 1
    assert (
        after["door"]["attempts"] == before["door"]["attempts"] + 2
    )  # the block and the admin change are not attempts
    assert after["security"]["blocks"] == before["security"]["blocks"] + 1
    assert after["admin"]["changes"] == before["admin"]["changes"] + 1
    assert after["door"]["opens_today"] == before["door"]["opens_today"] + 1
    assert len(after["door"]["daily"]) == 14 and len(after["door"]["heatmap"]) == 7


def test_stats_with_no_log_file(client, app_module, monkeypatch, tmp_path):
    _login(client)
    monkeypatch.setattr(app_module, "log_path", str(tmp_path / "does-not-exist.txt"))
    s = client.get("/admin/stats").get_json()
    assert s["entries"] == 0 and s["door"]["success_rate"] is None


def test_stats_failure_is_a_clean_500(client, app_module, monkeypatch):
    _login(client)

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(app_module, "compute_stats", boom)
    r = client.get("/admin/stats")
    assert r.status_code == 500 and r.get_json() == {"error": "Failed to compute statistics"}
