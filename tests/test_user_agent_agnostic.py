"""Scripts, Shortcuts and monitoring tools must work: the door endpoint never judges the User-Agent.

It used to reject agents containing 'curl', 'wget', 'python-requests', 'bot' or 'crawler', and
any UA under 10 characters. That was trivially bypassed by sending a different header, and it
broke legitimate automations.
"""

import pytest


@pytest.fixture
def client(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "user_pins", {"ok": "4321"})
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    with app_module.app.test_client() as c:
        yield c


@pytest.mark.parametrize(
    "ua",
    ["curl/8.5.0", "Wget/1.21", "python-requests/2.33.0", "Googlebot/2.1", "MyCrawler", "x", "iOS Shortcuts"],
)
def test_valid_pin_opens_regardless_of_user_agent(client, ua):
    r = client.post("/open-door", json={"pin": "4321"}, headers={"User-Agent": ua})
    assert r.status_code == 200


def test_valid_pin_opens_with_no_user_agent_at_all(client):
    r = client.post("/open-door", json={"pin": "4321"}, headers={"User-Agent": ""})
    assert r.status_code == 200


def test_user_agent_does_not_change_how_wrong_pins_are_throttled(client):
    import app as app_module

    for ua in ("curl/8.5.0", "Mozilla/5.0 (X11; Linux x86_64)", ""):
        r = client.post("/open-door", json={"pin": "0000"}, headers={"User-Agent": ua})
        assert r.status_code == 401  # a normal failed attempt for every agent, never 403
    assert sum(app_module.ip_failed_attempts.values()) == 3
