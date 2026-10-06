from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest


# Test utility functions
def test_get_current_time():
    from app import get_current_time

    assert isinstance(get_current_time(), datetime)


# Test client fixture
@pytest.fixture
def client():
    from app import app as flask_app

    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        with flask_app.app_context():
            yield client


# Route tests
def test_index_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Door" in response.data


def test_battery_route(client, monkeypatch):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"state": "85"}

    with patch("requests.get", return_value=mock_response):
        response = client.get("/battery")
        assert response.status_code == 200
        assert response.json["level"] == 85


def test_open_door_invalid_input(client):
    # Test missing pin
    response = client.post("/open-door", json={})
    assert response.status_code == 400

    # Test invalid pin format
    response = client.post("/open-door", json={"pin": "abc"})
    assert response.status_code == 400


def test_admin_authentication(client):
    # Test unauthenticated access
    response = client.get("/admin/logs")
    assert response.status_code == 401


def test_battery_fetches_on_a_freshly_booted_host(client, monkeypatch):
    """time.monotonic() counts from boot; a host up for < BATTERY_CACHE_TTL must still fetch."""
    import time

    monkeypatch.setattr(time, "monotonic", lambda: 10.0)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"state": "85"}
    with patch("requests.get", return_value=mock_response):
        assert client.get("/battery").json["level"] == 85
