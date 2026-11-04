"""Static files are revalidated, not re-downloaded; everything dynamic stays uncacheable."""

import pytest


@pytest.fixture
def client(monkeypatch):
    import app as app_module

    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    with app_module.app.test_client() as c:
        yield c


def test_static_files_are_cacheable_but_must_be_revalidated(client):
    r = client.get("/static/gear.png")
    assert r.status_code == 200
    cc = r.headers["Cache-Control"]
    assert "no-store" not in cc and "no-cache" in cc
    assert r.headers.get("ETag") and r.headers.get("Last-Modified")


def test_unchanged_static_file_revalidates_with_304(client):
    first = client.get("/static/gear.png")
    again = client.get("/static/gear.png", headers={"If-None-Match": first.headers["ETag"]})
    assert again.status_code == 304
    assert again.data == b""


def test_replaced_static_file_is_served_again(client, tmp_path, monkeypatch):
    import os

    import app as app_module

    path = os.path.join(app_module.STATIC_DIR, "cache-test-tmp.png")
    try:
        open(path, "wb").write(b"first")
        etag = client.get("/static/cache-test-tmp.png").headers["ETag"]
        os.utime(path, (1, 1))  # different mtime -> different ETag
        open(path, "wb").write(b"second!")
        r = client.get("/static/cache-test-tmp.png", headers={"If-None-Match": etag})
        assert r.status_code == 200 and r.data == b"second!"
    finally:
        os.path.exists(path) and os.remove(path)


@pytest.mark.parametrize("path", ["/", "/battery", "/health", "/auth/status", "/admin", "/admin/check-auth"])
def test_dynamic_responses_stay_no_store(client, path):
    r = client.get(path)
    assert "no-store" in r.headers["Cache-Control"]
    assert r.headers.get("Pragma") == "no-cache"


def test_security_headers_still_apply_to_static_files(client):
    r = client.get("/static/gear.png")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in r.headers
