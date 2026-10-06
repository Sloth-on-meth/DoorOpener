"""Rate limits must key on the client IP, not on headers the client controls."""

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


def test_identifier_ignores_user_agent_and_language(app_module):
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
