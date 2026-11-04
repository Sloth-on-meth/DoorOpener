"""Oversized request bodies are rejected with 413 before any view buffers them."""

import io

import pytest

UA = {"User-Agent": "pytest-client/1.0 (+https://example.test)"}
BIG = b"{" + b'"pin": "' + b"1" * (200 * 1024) + b'"}'  # ~200 KB, > MAX_JSON_BODY


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


@pytest.fixture
def client(app_module, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    with app_module.app.test_client() as c:
        yield c


@pytest.mark.parametrize("path", ["/open-door", "/admin/auth", "/report-problem", "/admin/notice"])
def test_oversized_json_body_is_413_on_every_json_endpoint(client, path):
    r = client.post(path, data=BIG, headers={**UA, "Content-Type": "application/json"})
    assert r.status_code == 413
    assert r.get_json()["status"] == "error"


def test_chunked_body_without_content_length_is_also_413_not_500(client):
    r = client.post(
        "/open-door",
        input_stream=io.BytesIO(BIG),
        headers={**UA, "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_oversized_body_does_not_count_as_a_failed_pin_attempt(client, app_module):
    client.post("/open-door", data=BIG, headers={**UA, "Content-Type": "application/json"})
    assert sum(app_module.ip_failed_attempts.values()) == 0
    assert app_module.global_failed_attempts == 0


def test_normal_requests_are_unaffected(client, app_module, monkeypatch):
    monkeypatch.setattr(app_module, "user_pins", {"ok": "4321"})
    r = client.post("/open-door", json={"pin": "4321"}, headers=UA)
    assert r.status_code == 200


def test_background_upload_gets_the_large_limit(client, app_module):
    assert client.post("/admin/auth", json={"password": "testpass"}).status_code == 200
    token = client.get("/admin/check-auth").get_json()["csrf_token"]
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 1024
    r = client.post(
        "/admin/background",
        data={"file": (io.BytesIO(png * 4000), "bg.png")},  # ~4 MB: far over the JSON cap
        headers={"X-CSRF-Token": token},
        content_type="multipart/form-data",
    )
    assert r.status_code != 413


def test_background_upload_over_the_cap_is_413(client, app_module):
    assert client.post("/admin/auth", json={"password": "testpass"}).status_code == 200
    token = client.get("/admin/check-auth").get_json()["csrf_token"]
    too_big = io.BytesIO(b"\x00" * (app_module.MAX_UPLOAD_BODY + 1024))
    r = client.post(
        "/admin/background",
        data={"file": (too_big, "bg.png")},
        headers={"X-CSRF-Token": token},
        content_type="multipart/form-data",
    )
    assert r.status_code == 413
