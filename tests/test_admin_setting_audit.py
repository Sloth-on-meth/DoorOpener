"""Changes made from the admin dashboard (notice, test mode, background) are written to the audit log."""

import io
import logging
from configparser import RawConfigParser
from types import SimpleNamespace

import pytest

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64


@pytest.fixture
def env(tmp_path, monkeypatch):
    import app as app_module

    cfg = RawConfigParser()
    cfg.read_dict({"server": {}, "pins": {}})
    path = tmp_path / "config.ini"
    path.write_text("")
    static = tmp_path / "static"
    static.mkdir()
    (static / "background_default.jpg").write_bytes(JPEG)
    monkeypatch.setattr(app_module, "config", cfg)
    monkeypatch.setattr(app_module, "config_path", str(path))
    monkeypatch.setattr(app_module, "STATIC_DIR", str(static))
    monkeypatch.setattr(app_module, "BACKGROUND_DEFAULT_PATH", str(static / "background_default.jpg"))
    monkeypatch.setattr(app_module, "BACKGROUND_DIR", str(tmp_path / "uploads"))
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    client = app_module.app.test_client()
    assert client.post("/admin/auth", json={"password": "testpass"}).status_code == 200
    token = client.get("/admin/check-auth").get_json()["csrf_token"]
    return SimpleNamespace(client=client, csrf={"X-CSRF-Token": token}, app=app_module, mp=monkeypatch)


def _settings(env):
    for h in logging.getLogger("door_attempts").handlers:
        h.flush()
    rows = env.client.get("/admin/logs").get_json()["logs"]
    return [r for r in rows if r["status"] == "ADMIN_SETTING"]


def _new(env, before):
    return [r["details"] for r in _settings(env)[len(before) :]]


def _upload(env, data=PNG):
    return env.client.post(
        "/admin/background",
        data={"file": (io.BytesIO(data), "bg.png")},
        headers=env.csrf,
        content_type="multipart/form-data",
    )


def test_notice_set_and_cleared_are_recorded(env):
    before = _settings(env)
    env.client.post("/admin/notice", json={"notice": "Back at 5 pm"}, headers=env.csrf)
    env.client.post("/admin/notice", json={"notice": ""}, headers=env.csrf)
    assert _new(env, before) == ["Public notice set: Back at 5 pm", "Public notice cleared"]


def test_a_long_notice_is_shortened_in_the_log(env):
    before = _settings(env)
    env.client.post("/admin/notice", json={"notice": "x" * 300}, headers=env.csrf)
    (detail,) = _new(env, before)
    assert detail.endswith("...") and len(detail) < 120


def test_test_mode_on_and_off_are_recorded(env):
    before = _settings(env)
    env.client.post("/admin/test-mode", json={"enabled": True}, headers=env.csrf)
    env.client.post("/admin/test-mode", json={"enabled": False}, headers=env.csrf)
    assert _new(env, before) == [
        "Test mode turned on: the door will not open",
        "Test mode turned off: the door opens again",
    ]


def test_background_replaced_and_reset_are_recorded(env):
    before = _settings(env)
    assert _upload(env).status_code == 200
    assert env.client.delete("/admin/background", headers=env.csrf).status_code == 200
    new = _new(env, before)
    assert new[0].startswith("Background image replaced (png,") and new[1] == "Background image reset to the default"


def test_entries_are_attributed_to_the_admin_with_the_client_ip(env):
    env.client.post("/admin/notice", json={"notice": "who did this"}, headers=env.csrf)
    row = _settings(env)[-1]
    assert row["user"] == "ADMIN" and row["ip"] and row["category"] == "admin" and row["label"] == "Setting changed"


@pytest.mark.parametrize(
    "call",
    [
        lambda env: env.client.post("/admin/notice", json={"notice": "x"}, headers=env.csrf),
        lambda env: env.client.post("/admin/test-mode", json={"enabled": True}, headers=env.csrf),
    ],
    ids=["notice", "test-mode"],
)
def test_a_change_that_could_not_be_saved_is_not_logged_as_done(env, call):
    before = _settings(env)
    env.mp.setattr(env.app, "save_config", lambda: (_ for _ in ()).throw(OSError("read-only")))
    assert call(env).status_code == 500
    assert _new(env, before) == []


def test_rejected_or_unauthorised_requests_are_not_logged(env):
    before = _settings(env)
    anon = env.app.app.test_client()
    assert anon.post("/admin/notice", json={"notice": "x"}).status_code == 401
    assert env.client.post("/admin/notice", json={"notice": "x"}).status_code == 403  # no CSRF token
    assert env.client.post("/admin/test-mode", json={}, headers=env.csrf).status_code == 400
    assert _upload(env, b"<html>not an image</html>").status_code == 415
    assert _new(env, before) == []


def test_clearing_test_entries_keeps_the_record_that_test_mode_was_switched_on(env):
    """'Clear logs > test entries only' deletes every line containing 'TEST MODE'."""
    env.client.post("/admin/test-mode", json={"enabled": True}, headers=env.csrf)
    env.app.log_attempt("SUCCESS", "Door opened (TEST MODE)", user="tester", primary_ip="10.0.0.9")
    env.client.post("/admin/logs/clear", json={"mode": "test_only"}, headers=env.csrf)
    for h in logging.getLogger("door_attempts").handlers:
        h.flush()
    rows = env.client.get("/admin/logs").get_json()["logs"]
    assert any(r["details"] == "Test mode turned on: the door will not open" for r in rows)
    assert not any(r["details"] == "Door opened (TEST MODE)" for r in rows)


def test_the_statistics_count_these_as_admin_changes(env):
    before = env.client.get("/admin/stats").get_json()["admin"]["changes"]
    env.client.post("/admin/notice", json={"notice": "hello"}, headers=env.csrf)
    for h in logging.getLogger("door_attempts").handlers:
        h.flush()
    stats = env.client.get("/admin/stats").get_json()
    assert stats["admin"]["changes"] == before + 1
    assert stats["admin"]["recent"][0]["label"] == "Setting changed"
