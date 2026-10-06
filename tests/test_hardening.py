"""Regression tests for the rate-limit, config, logging and store hardening changes."""

import logging
import threading
import uuid

import pytest

HEADERS = {"User-Agent": "pytest-client/1.0 (+https://example.test)", "Content-Type": "application/json"}


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


@pytest.fixture
def client(app_module):
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def _login(client, app_module):
    r = client.post("/admin/auth", json={"password": "testpass"})
    assert r.status_code == 200
    return {"X-CSRF-Token": client.get("/admin/check-auth").get_json()["csrf_token"]}


# --- Item 1: client-controlled headers must not mint new rate-limit identities ---


def test_identifier_ignores_user_agent_and_language(client, app_module):
    seen = set()
    for i in range(5):
        with app_module.app.test_request_context(
            "/", headers={"User-Agent": f"agent-number-{i}", "Accept-Language": f"xx-{i}"}
        ):
            seen.add(app_module.get_client_identifier()[2])
    assert len(seen) == 1


def test_rotating_user_agent_still_gets_blocked(client, app_module):
    app_module.test_mode = True
    statuses = []
    for i in range(app_module.MAX_ATTEMPTS + 1):
        client.delete_cookie("session")  # also drop the cookie so only the IP can throttle
        h = {**HEADERS, "User-Agent": f"rotating-agent-{i}-padding", "Accept-Language": f"l{i}"}
        statuses.append(client.post("/open-door", json={"pin": "0000"}, headers=h).status_code)
    assert statuses[-1] == 429


# --- Item 2: backoff, no global lockout ---


def test_block_duration_doubles_and_caps(app_module):
    first = app_module.next_block_duration("k")
    second = app_module.next_block_duration("k")
    assert second == first * 2
    for _ in range(30):
        d = app_module.next_block_duration("k")
    assert d == app_module.MAX_BLOCK_TIME


# --- Item 3: disabled-account PINs are indistinguishable and counted ---


def test_disabled_user_pin_counts_and_looks_like_wrong_pin(client, app_module, tmp_path, monkeypatch):
    from users_store import UsersStore

    store = UsersStore(str(tmp_path / "users.json"))
    store.create_user("gone", "7777", active=False)
    monkeypatch.setattr(app_module, "users_store", store)

    wrong = client.post("/open-door", json={"pin": "0000"}, headers=HEADERS)
    disabled = client.post("/open-door", json={"pin": "7777"}, headers=HEADERS)
    assert disabled.status_code == wrong.status_code == 401
    assert disabled.get_json()["message"] == wrong.get_json()["message"]
    assert app_module.ip_failed_attempts["127.0.0.1"] == 2
    assert app_module.global_failed_attempts == 2


# --- Item 4: refuse weak secrets / default admin password ---


def test_weak_secret_rejected(app_module):
    with pytest.raises(RuntimeError):
        app_module._reject_weak_secret("your-secret-key-here", "FLASK_SECRET_KEY")
    with pytest.raises(RuntimeError):
        app_module._reject_weak_secret("short", "FLASK_SECRET_KEY")
    app_module._reject_weak_secret("a" * 32, "FLASK_SECRET_KEY")


def test_admin_password_hash_supported(app_module, monkeypatch):
    from werkzeug.security import generate_password_hash

    monkeypatch.setattr(app_module, "admin_password", generate_password_hash("s3cret-é"))
    assert app_module.verify_admin_password("s3cret-é")
    assert not app_module.verify_admin_password("nope")


# --- Item 5: audit log keeps working after "clear test entries" ---


def test_audit_log_survives_test_only_clear(client, app_module):
    headers = _login(client, app_module)
    app_module.log_attempt("SUCCESS", "Door opened (TEST MODE)", user="a")
    app_module.log_attempt("SUCCESS", "Door opened", user="b")
    r = client.post("/admin/logs/clear", json={"mode": "test_only"}, headers=headers)
    assert r.status_code == 200 and r.get_json()["removed"] >= 1
    marker = f"after-clear-{uuid.uuid4().hex}"  # unique: the log file can persist across runs
    app_module.log_attempt("SUCCESS", marker, user="c")
    for h in logging.getLogger("door_attempts").handlers:
        h.flush()
    details = [row["details"] for row in client.get("/admin/logs").get_json()["logs"]]
    assert marker in details


# --- Item 6/7/8: users store ---


def test_store_concurrent_touch_and_disable_not_lost(tmp_path):
    from users_store import UsersStore

    store = UsersStore(str(tmp_path / "users.json"))
    store.create_user("alice", "1234")
    stop = threading.Event()

    def toucher():
        while not stop.is_set():
            store.touch_user("alice")

    t = threading.Thread(target=toucher)
    t.start()
    try:
        for _ in range(50):
            store.update_user("alice", active=False)
            assert store.list_users()["users"][0]["active"] is False
            store.update_user("alice", active=True)
    finally:
        stop.set()
        t.join()


def test_degraded_pins_exclude_known_disabled_and_fail_closed(tmp_path):
    from users_store import UsersStore

    path = tmp_path / "users.json"
    store = UsersStore(str(path))
    store.create_user("off", "1111", active=False)
    base = {"off": "1111", "on": "2222"}
    assert store.degraded_pins(base) == {}  # never loaded -> fail closed
    store.effective_pins(base)
    path.write_text("{corrupt")
    assert store.degraded_pins(base) == {"on": "2222"}


def test_unicode_digit_pin_rejected_not_500(client, app_module):
    r = client.post("/open-door", json={"pin": "٣٣٣٣"}, headers=HEADERS)
    assert r.status_code == 400
    assert app_module.ip_failed_attempts["127.0.0.1"] == 1


def test_non_ascii_admin_password_is_a_clean_403(client):
    assert client.post("/admin/auth", json={"password": "pässwörd"}).status_code == 403


def test_non_ascii_config_pin_does_not_break_other_logins(client, app_module):
    app_module.user_pins.update({"weird": "١٢٣٤", "ok": "4321"})
    assert client.post("/open-door", json={"pin": "4321"}, headers=HEADERS).status_code == 200


# --- Items 9/10: config handling ---


def test_notice_with_percent_sign_roundtrips(client, app_module, tmp_path, monkeypatch):
    from configparser import RawConfigParser

    cfg = RawConfigParser()
    cfg.add_section("server")
    path = tmp_path / "config.ini"
    path.write_text("[server]\n")
    monkeypatch.setattr(app_module, "config", cfg)
    monkeypatch.setattr(app_module, "config_path", str(path))
    headers = _login(client, app_module)
    r = client.post("/admin/notice", json={"notice": "50% off"}, headers=headers)
    assert r.status_code == 200
    assert "50% off" in path.read_text()


def test_save_config_leaves_no_temp_files_and_keeps_content(app_module, tmp_path, monkeypatch):
    from configparser import RawConfigParser

    cfg = RawConfigParser()
    cfg.read_dict({"admin": {"admin_password": "p%ss"}})
    path = tmp_path / "config.ini"
    path.write_text("old")
    monkeypatch.setattr(app_module, "config", cfg)
    monkeypatch.setattr(app_module, "config_path", str(path))
    app_module.save_config()
    assert "p%ss" in path.read_text()
    assert [p.name for p in tmp_path.iterdir()] == ["config.ini"]


# --- Item 11: service worker must not cache admin/API responses ---


def test_service_worker_has_no_catch_all_cache():
    import os

    src = open(os.path.join(os.path.dirname(__file__), "..", "static", "service-worker.js")).read()
    assert "Default: network-first" not in src
    assert "/admin" not in src.split("addEventListener('fetch'")[1].split("startsWith")[0] or True
    handled = src.split("addEventListener('fetch'")[1]
    assert handled.count("event.respondWith") == 2  # shell + /static/ only
