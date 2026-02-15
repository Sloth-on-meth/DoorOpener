"""Utility helper tests."""
import json


class MockResponse:
    """Mock response object reusable across tests."""

    def __init__(self, status_code=200, json_data=None, text=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text or (json.dumps(json_data) if json_data else "")

    def json(self):
        return self._json


def test_mock_response_json():
    r = MockResponse(status_code=201, json_data={"x": 1})
    assert r.status_code == 201
    assert r.json() == {"x": 1}
    assert "1" in r.text
