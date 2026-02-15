"""Route-level behaviour tests: service worker, manifest, CSP, counters."""
from datetime import timedelta


def test_service_worker_endpoint(client):
    r = client.get("/service-worker.js")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert "javascript" in (r.mimetype or "")


def test_manifest_endpoint(client):
    r = client.get("/manifest.webmanifest")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert "application/manifest+json" in (r.mimetype or "")


def test_csp_directives_on_index(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "connect-src 'self'" in csp


def test_delay_function_values():
    from security import get_delay_seconds
    expected = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 16}
    for attempts, delay in expected.items():
        assert get_delay_seconds(attempts) == delay


def test_counters_reset_on_success_after_no_block(client, monkeypatch):
    import app as app_module
    monkeypatch.setattr(
        "app.get_client_identifier",
        lambda: ("2.2.2.2", "sessReset", "idReset"),
    )
    app_module.users_store.create_user("ok", "9999")

    headers = {
        "User-Agent": "pytest-client/1.0 (+https://example.test)",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }

    r1 = client.post("/open-door", json={"pin": "0000"}, headers=headers)
    assert r1.status_code in (401, 429)

    r2 = client.post("/open-door", json={"pin": "9999"}, headers=headers)
    assert r2.status_code in (200, 502, 500)

    assert app_module.rate_limiter.ip_failed.get("idReset", 0) == 0
    assert app_module.rate_limiter.session_failed.get("sessReset", 0) == 0
    assert (
        "idReset" not in app_module.rate_limiter.ip_blocked_until
        or not app_module.rate_limiter.ip_blocked_until["idReset"]
    )
    assert (
        "sessReset" not in app_module.rate_limiter.session_blocked_until
        or not app_module.rate_limiter.session_blocked_until["sessReset"]
    )


def test_counters_not_reset_on_success_when_block_active(client, monkeypatch):
    import app as app_module
    from config import get_current_time

    monkeypatch.setattr(
        "app.get_client_identifier",
        lambda: ("3.3.3.3", "sessBlock", "idBlock"),
    )
    app_module.users_store.create_user("ok2", "1111")

    app_module.rate_limiter.session_blocked_until[
        "sessBlock"
    ] = get_current_time() + timedelta(seconds=30)

    headers = {
        "User-Agent": "pytest-client/1.0 (+https://example.test)",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
    }

    r = client.post("/open-door", json={"pin": "1111"}, headers=headers)
    assert r.status_code == 429

    assert app_module.rate_limiter.ip_failed.get("idBlock", 0) == 0
    assert app_module.rate_limiter.session_failed.get("sessBlock", 0) == 0
    assert (
        app_module.rate_limiter.session_blocked_until["sessBlock"]
        > get_current_time()
    )
