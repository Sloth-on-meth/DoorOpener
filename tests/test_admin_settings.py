"""Admin endpoints for the notice, test mode, background image, problem reports, logs and migration."""

import io
import json
from collections import defaultdict
from configparser import RawConfigParser
from types import SimpleNamespace

import pytest

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
GIF = b"GIF89a" + b"\x00" * 64
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 64


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


@pytest.fixture
def env(app_module, tmp_path, monkeypatch):
    """A real config parser + config file in a temp dir so nothing touches the repo's config.ini."""
    cfg = RawConfigParser()
    cfg.read_dict({"server": {}, "pins": {}})
    path = tmp_path / "config.ini"
    path.write_text("")
    monkeypatch.setattr(app_module, "config", cfg)
    monkeypatch.setattr(app_module, "config_path", str(path))
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    client = app_module.app.test_client()
    assert client.post("/admin/auth", json={"password": "testpass"}).status_code == 200
    token = client.get("/admin/check-auth").get_json()["csrf_token"]
    return SimpleNamespace(
        client=client,
        csrf={"X-CSRF-Token": token},
        cfg=cfg,
        path=path,
        tmp=tmp_path,
        app=app_module,
        mp=monkeypatch,
    )


@pytest.fixture
def anon(app_module, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    return app_module.app.test_client()


# --- notice -----------------------------------------------------------------------------------


def test_notice_is_public_to_read_and_admin_only_to_change(env, anon):
    assert anon.get("/admin/notice").get_json() == {"notice": ""}
    assert anon.post("/admin/notice", json={"notice": "x"}).status_code == 401
    assert env.client.post("/admin/notice", json={"notice": "x"}).status_code == 403  # no CSRF token


def test_set_and_clear_the_notice_persists_to_the_config_file(env, anon):
    r = env.client.post("/admin/notice", json={"notice": "  Lift is out of order  "}, headers=env.csrf)
    assert r.status_code == 200 and r.get_json()["notice"] == "Lift is out of order"
    assert "notice = Lift is out of order" in env.path.read_text()
    assert anon.get("/admin/notice").get_json()["notice"] == "Lift is out of order"
    env.client.post("/admin/notice", json={"notice": ""}, headers=env.csrf)
    assert "notice" not in env.path.read_text()


def test_notice_save_failure_is_a_500(env):
    def boom():
        raise OSError("read-only")

    env.mp.setattr(env.app, "save_config", boom)
    r = env.client.post("/admin/notice", json={"notice": "x"}, headers=env.csrf)
    assert r.status_code == 500


# --- test mode --------------------------------------------------------------------------------


def test_test_mode_requires_admin_and_csrf(env, anon):
    assert anon.get("/admin/test-mode").status_code == 401
    assert anon.post("/admin/test-mode", json={"enabled": True}).status_code == 401
    assert env.client.post("/admin/test-mode", json={"enabled": True}).status_code == 403


def test_test_mode_toggle_updates_the_flag_and_the_file(env):
    r = env.client.post("/admin/test-mode", json={"enabled": False}, headers=env.csrf)
    assert r.status_code == 200 and env.app.test_mode is False
    assert env.client.get("/admin/test-mode").get_json() == {"test_mode": False}
    assert "test_mode = false" in env.path.read_text()
    env.client.post("/admin/test-mode", json={"enabled": True}, headers=env.csrf)
    assert env.app.test_mode is True and "test_mode = true" in env.path.read_text()


def test_test_mode_needs_the_enabled_field(env):
    assert env.client.post("/admin/test-mode", json={}, headers=env.csrf).status_code == 400


def test_test_mode_is_not_changed_when_the_config_cannot_be_saved(env):
    env.app.test_mode = True
    env.cfg.set("server", "test_mode", "true")

    def boom():
        raise OSError("read-only")

    env.mp.setattr(env.app, "save_config", boom)
    r = env.client.post("/admin/test-mode", json={"enabled": False}, headers=env.csrf)
    assert r.status_code == 500 and env.app.test_mode is True
    assert env.cfg.get("server", "test_mode") == "true"  # the in-memory config was rolled back too


def test_a_failed_test_mode_save_is_not_persisted_by_a_later_unrelated_save(env):
    """Before: the failed change stayed in memory and the next successful save (here, a notice)
    wrote `test_mode = false` to disk even though the admin was told it failed."""
    env.app.test_mode = True
    env.cfg.set("server", "test_mode", "true")
    real_save = env.app.save_config
    env.mp.setattr(env.app, "save_config", lambda: (_ for _ in ()).throw(OSError("read-only")))
    assert env.client.post("/admin/test-mode", json={"enabled": False}, headers=env.csrf).status_code == 500
    env.mp.setattr(env.app, "save_config", real_save)
    assert env.client.post("/admin/notice", json={"notice": "hello"}, headers=env.csrf).status_code == 200
    on_disk = env.path.read_text()
    assert "test_mode = true" in on_disk and "test_mode = false" not in on_disk


def test_a_test_mode_option_that_did_not_exist_is_removed_again_after_a_failed_save(env):
    assert not env.cfg.has_option("server", "test_mode")
    env.mp.setattr(env.app, "save_config", lambda: (_ for _ in ()).throw(OSError("read-only")))
    assert env.client.post("/admin/test-mode", json={"enabled": True}, headers=env.csrf).status_code == 500
    assert not env.cfg.has_option("server", "test_mode")


def test_a_failed_notice_save_is_rolled_back_too(env):
    env.cfg.set("server", "notice", "old notice")
    real_save = env.app.save_config
    env.mp.setattr(env.app, "save_config", lambda: (_ for _ in ()).throw(OSError("read-only")))
    assert env.client.post("/admin/notice", json={"notice": "new notice"}, headers=env.csrf).status_code == 500
    assert env.client.post("/admin/notice", json={"notice": ""}, headers=env.csrf).status_code == 500  # clearing
    assert env.cfg.get("server", "notice") == "old notice"
    env.mp.setattr(env.app, "save_config", real_save)
    env.client.post("/admin/test-mode", json={"enabled": True}, headers=env.csrf)  # an unrelated successful save
    assert "old notice" in env.path.read_text() and "new notice" not in env.path.read_text()


# --- background image -------------------------------------------------------------------------


@pytest.fixture
def bg(env):
    static = env.tmp / "static"
    static.mkdir()
    env.mp.setattr(env.app, "STATIC_DIR", str(static))
    env.mp.setattr(env.app, "BACKGROUND_PATH", str(static / "background.jpg"))
    env.mp.setattr(env.app, "BACKGROUND_DEFAULT_PATH", str(static / "background_default.jpg"))
    env.static = static
    return env


def _upload(env, data, name="bg.png", headers=True):
    return env.client.post(
        "/admin/background",
        data={"file": (io.BytesIO(data), name)},
        headers=env.csrf if headers else {},
        content_type="multipart/form-data",
    )


def test_background_endpoints_need_admin_and_csrf(bg, anon):
    assert anon.get("/admin/background").status_code == 401
    assert anon.post("/admin/background").status_code == 401
    assert anon.delete("/admin/background").status_code == 401
    assert _upload(bg, PNG, headers=False).status_code == 403
    assert bg.client.delete("/admin/background").status_code == 403


@pytest.mark.parametrize("data", [PNG, JPEG, GIF, WEBP], ids=["png", "jpeg", "gif", "webp"])
def test_valid_images_are_accepted_and_replace_the_background(bg, data):
    assert _upload(bg, data).status_code == 200
    assert (bg.static / "background.jpg").read_bytes() == data
    assert [p.name for p in bg.static.iterdir()] == ["background.jpg"]  # no temp file left behind


def test_non_images_and_disguised_files_are_rejected(bg):
    assert _upload(bg, b"<html>not an image</html>", "evil.png").status_code == 415
    assert _upload(bg, b"MZ\x90\x00" + b"\x00" * 64, "x.jpg").status_code == 415
    assert not (bg.static / "background.jpg").exists()


def test_missing_or_empty_file_field_is_a_400(bg):
    assert (
        bg.client.post("/admin/background", data={}, headers=bg.csrf, content_type="multipart/form-data").status_code
        == 400
    )
    assert _upload(bg, PNG, name="").status_code == 400


def test_oversized_image_is_a_413(bg):
    bg.mp.setattr(bg.app, "MAX_BACKGROUND_SIZE", 100)
    assert _upload(bg, PNG + b"\x00" * 200).status_code == 413


def test_upload_write_failure_is_a_500_and_leaves_no_temp_file(bg):
    def boom(src, dst):
        raise OSError("disk full")

    bg.mp.setattr(bg.app.os, "replace", boom)
    assert _upload(bg, PNG).status_code == 500
    assert list(bg.static.iterdir()) == []


def test_custom_flag_and_reset_to_the_default(bg):
    (bg.static / "background.jpg").write_bytes(JPEG)
    (bg.static / "background_default.jpg").write_bytes(JPEG)
    assert bg.client.get("/admin/background").get_json() == {"custom": False}
    assert _upload(bg, PNG).status_code == 200
    assert bg.client.get("/admin/background").get_json() == {"custom": True}
    assert bg.client.delete("/admin/background", headers=bg.csrf).status_code == 200
    assert (bg.static / "background.jpg").read_bytes() == JPEG
    assert bg.client.get("/admin/background").get_json() == {"custom": False}


def test_reset_without_a_saved_default_is_a_404(bg):
    assert bg.client.delete("/admin/background", headers=bg.csrf).status_code == 404


def test_reset_copy_failure_is_a_500(bg):
    (bg.static / "background_default.jpg").write_bytes(JPEG)

    def boom(src, dst):
        raise OSError("read-only")

    bg.mp.setattr(bg.app.shutil, "copy2", boom)
    assert bg.client.delete("/admin/background", headers=bg.csrf).status_code == 500


def test_custom_flag_is_true_when_the_current_image_is_missing_so_reset_can_restore_it(bg):
    """A saved default with no current image is not 'the default in place': report it as custom.

    That keeps "reset to default" available, and resetting is exactly what restores the file.
    """
    (bg.static / "background_default.jpg").write_bytes(JPEG)  # default exists, background.jpg does not
    assert bg.client.get("/admin/background").get_json() == {"custom": True}
    assert bg.client.delete("/admin/background", headers=bg.csrf).status_code == 200
    assert (bg.static / "background.jpg").read_bytes() == JPEG
    assert bg.client.get("/admin/background").get_json() == {"custom": False}


# --- problem reports --------------------------------------------------------------------------


@pytest.fixture
def report(app_module, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    monkeypatch.setattr(app_module, "_report_timestamps", defaultdict(list))
    sent = []

    class Resp:
        def raise_for_status(self):
            pass

    def post(url, **kw):
        sent.append((url, kw))
        return Resp()

    monkeypatch.setattr(app_module.requests, "post", post)
    return SimpleNamespace(app=app_module, client=app_module.app.test_client(), sent=sent, mp=monkeypatch)


def test_reporting_is_disabled_without_a_pushbullet_token(report):
    report.mp.setattr(report.app, "pushbullet_token", "")
    assert report.client.post("/report-problem", json={"message": "hi"}).status_code == 503
    assert report.sent == []


def test_report_is_validated_and_forwarded_to_pushbullet(report):
    report.mp.setattr(report.app, "pushbullet_token", "tok-123")
    assert report.client.post("/report-problem", json={}).status_code == 400
    assert report.client.post("/report-problem", json={"message": "   "}).status_code == 400
    assert report.client.post("/report-problem", json={"message": "x" * 501}).status_code == 400
    r = report.client.post("/report-problem", json={"message": "Door is stuck"})
    assert r.status_code == 200
    url, kw = report.sent[0]
    assert url == "https://api.pushbullet.com/v2/pushes"
    assert kw["headers"]["Access-Token"] == "tok-123" and kw["json"]["body"] == "Door is stuck"


def test_reports_are_limited_per_ip_per_hour(report):
    report.mp.setattr(report.app, "pushbullet_token", "tok")
    codes = [report.client.post("/report-problem", json={"message": f"m{i}"}).status_code for i in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert len(report.sent) == 3


def test_pushbullet_failure_is_a_502(report):
    import requests

    report.mp.setattr(report.app, "pushbullet_token", "tok")

    def boom(url, **kw):
        raise requests.ConnectionError("down")

    report.mp.setattr(report.app.requests, "post", boom)
    assert report.client.post("/report-problem", json={"message": "x"}).status_code == 502


# --- logs -------------------------------------------------------------------------------------


@pytest.fixture
def logfile(env):
    path = env.tmp / "log.txt"
    env.mp.setattr(env.app, "log_path", str(path))
    env.logpath = path
    return env


def _line(**kw):
    entry = {
        "timestamp": "2026-01-01T10:00:00+00:00",
        "ip": "1.2.3.4",
        "user": "alice",
        "status": "SUCCESS",
        "details": "ok",
    }
    entry.update(kw)
    return json.dumps(entry)


def test_logs_parse_prefixed_json_old_format_and_skip_garbage(logfile):
    logfile.logpath.write_text(
        "\n".join(
            [
                "2026-01-01 10:00:00,000 - " + _line(),  # logging-module prefix
                _line(user="UNKNOWN", status="AUTH_FAILURE", details="Invalid PIN"),
                "2026-01-01T09:00:00 - 5.6.7.8 - bob - SUCCESS - Door opened - extra",  # old format
                "this line is not a log entry at all",
                "",
            ]
        )
    )
    logs = logfile.client.get("/admin/logs").get_json()["logs"]
    assert [entry["status"] for entry in logs] == ["SUCCESS", "AUTH_FAILURE", "SUCCESS"]
    assert logs[1]["user"] is None  # UNKNOWN is shown as no user
    assert logs[2]["ip"] == "5.6.7.8" and logs[2]["user"] == "bob" and logs[2]["details"].startswith("Door opened")


def test_logs_with_no_file_are_an_empty_list(logfile):
    assert logfile.client.get("/admin/logs").get_json() == {"logs": []}


def test_logs_need_admin(anon):
    assert anon.get("/admin/logs").status_code == 401
    assert anon.post("/admin/logs/clear", json={"mode": "all"}).status_code == 401


def test_clear_all_truncates_the_log(logfile):
    logfile.logpath.write_text(_line() + "\n" + _line() + "\n")
    r = logfile.client.post("/admin/logs/clear", json={"mode": "all"}, headers=logfile.csrf)
    assert r.status_code == 200 and r.get_json()["mode"] == "all"
    assert _line() not in logfile.logpath.read_text()


def test_clear_test_only_removes_just_the_test_mode_entries(logfile):
    keep = _line(details="Door opened")
    drop = _line(details="Door opened (TEST MODE)")
    logfile.logpath.write_text("\n".join([keep, drop, "unparsable line", drop]) + "\n")
    r = logfile.client.post("/admin/logs/clear", json={"mode": "test_only"}, headers=logfile.csrf)
    body = r.get_json()
    assert r.status_code == 200 and body["removed"] == 2 and body["kept"] == 2
    text = logfile.logpath.read_text()
    assert keep in text and "unparsable line" in text and "TEST MODE" not in text.split("ADMIN_LOGS_CLEAR")[0]


# --- migration from config.ini ----------------------------------------------------------------


@pytest.fixture
def migrate(env):
    from users_store import UsersStore

    store = UsersStore(str(env.tmp / "users.json"))
    env.mp.setattr(env.app, "users_store", store)
    pins = {"alice": "1111", "bob": "2222"}
    env.mp.setattr(env.app, "user_pins", pins)
    env.cfg.read_dict({"pins": pins})
    env.store = store
    env.pins = pins
    return env


def test_migrate_endpoints_need_admin_and_csrf(migrate, anon):
    assert anon.post("/admin/users/alice/migrate").status_code == 401
    assert anon.post("/admin/users/migrate-all").status_code == 401
    assert migrate.client.post("/admin/users/alice/migrate").status_code == 403
    assert migrate.client.post("/admin/users/migrate-all").status_code == 403


def test_migrate_moves_a_user_into_the_store_and_out_of_the_config(migrate):
    r = migrate.client.post("/admin/users/alice/migrate", json={}, headers=migrate.csrf)
    assert r.status_code == 200 and r.get_json()["status"] == "migrated"
    assert migrate.store.user_exists("alice") and "alice" not in migrate.pins
    assert "alice" not in migrate.path.read_text() and "bob" in migrate.path.read_text()
    assert migrate.store.effective_pins({})["alice"] == "1111"


def test_migrate_can_set_a_new_pin(migrate):
    r = migrate.client.post("/admin/users/alice/migrate", json={"pin": "987654"}, headers=migrate.csrf)
    assert r.status_code == 200 and migrate.store.effective_pins({})["alice"] == "987654"


@pytest.mark.parametrize("pin", ["12", "abcd", "123456789", 1234, "١٢٣٤"])
def test_migrate_rejects_an_invalid_new_pin(migrate, pin):
    r = migrate.client.post("/admin/users/alice/migrate", json={"pin": pin}, headers=migrate.csrf)
    assert r.status_code == 400 and not migrate.store.user_exists("alice")


def test_migrate_unknown_user_is_a_404(migrate):
    assert migrate.client.post("/admin/users/nobody/migrate", json={}, headers=migrate.csrf).status_code == 404


def test_migrating_a_user_that_already_exists_in_the_store_fails_cleanly(migrate):
    migrate.store.create_user("alice", "5555")
    r = migrate.client.post("/admin/users/alice/migrate", json={}, headers=migrate.csrf)
    assert r.status_code == 500
    assert migrate.store.effective_pins({})["alice"] == "5555"  # the existing record is untouched


def test_migrate_all_moves_everyone(migrate):
    r = migrate.client.post("/admin/users/migrate-all", headers=migrate.csrf)
    assert r.status_code == 200 and r.get_json() == {"migrated": 2, "failed": []}
    assert migrate.pins == {} and migrate.store.user_exists("alice") and migrate.store.user_exists("bob")


def test_migrate_all_with_nothing_to_do(migrate):
    migrate.mp.setattr(migrate.app, "user_pins", {})
    r = migrate.client.post("/admin/users/migrate-all", headers=migrate.csrf)
    assert r.status_code == 200 and r.get_json() == {"migrated": 0, "failed": []}


def test_migrate_all_reports_bad_entries_and_skips_existing_ones(migrate):
    migrate.pins.update({"badfmt": "12", "numeric": 5})
    migrate.store.create_user("bob", "7777")  # already in the store: skipped, not overwritten
    r = migrate.client.post("/admin/users/migrate-all", headers=migrate.csrf)
    body = r.get_json()
    assert r.status_code == 207 and body["migrated"] == 1  # only alice
    assert {f["username"]: f["error"] for f in body["failed"]} == {"badfmt": "invalid_format", "numeric": "invalid_pin"}
    assert migrate.store.effective_pins({})["bob"] == "7777"
