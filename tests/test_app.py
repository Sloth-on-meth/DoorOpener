import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime


# Test utility functions
def test_get_current_time():
    from app import get_current_time

    assert isinstance(get_current_time(), datetime)


def test_get_delay_seconds():
    from app import get_delay_seconds

    assert get_delay_seconds(1) == 1
    assert get_delay_seconds(2) == 2
    assert get_delay_seconds(3) == 4
    assert get_delay_seconds(4) == 8
    assert get_delay_seconds(5) == 16
    assert get_delay_seconds(10) == 16  # Max delay


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
