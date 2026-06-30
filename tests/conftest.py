"""Pytest configuration and fixtures for DoorOpener tests."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Test Configuration
TEST_CONFIG = {
    "pins": {"test_user": "1234", "admin": "admin123"},
    "admin": {"admin_password": "testpass"},
    "server": {"test_mode": "true", "port": "5000"},
    "HomeAssistant": {
        "url": "http://test-ha:8123",
        "token": "test-token",
        "switch_entity": "switch.test_door",
        "battery_entity": "sensor.test_door_battery",
    },
}


class MockResponse:
    """Mock response for requests.get()."""

    def __init__(self, status_code=200, json_data=None, text=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text or json.dumps(json_data) if json_data else ""

    def json(self):
        return self._json


@pytest.fixture(autouse=True)
def setup_mocks():
    """Setup common mocks for all tests."""
    with patch("configparser.ConfigParser") as mock_config:
        mock_config.return_value = MagicMock()
        mock_config.return_value.has_section.return_value = True
        mock_config.return_value.get.side_effect = lambda s, k, **kw: TEST_CONFIG.get(s, {}).get(k, kw.get("fallback"))
        mock_config.return_value.items.return_value = TEST_CONFIG["pins"].items()
        mock_config.return_value.getboolean.side_effect = lambda s, k, **kw: (
            str(TEST_CONFIG.get(s, {}).get(k, "")).lower() == "true"
        )
        mock_config.return_value.getint.side_effect = lambda s, k, **kw: int(
            TEST_CONFIG.get(s, {}).get(k, kw.get("fallback", "0"))
        )
        yield


@pytest.fixture(autouse=True)
def reset_app_globals(monkeypatch):
    """Reset all mutable app-level globals before each test to prevent state leakage.

    Only runs if app.py is already loaded — tests that never import app are unaffected.
    """
    import sys

    if "app" not in sys.modules:
        return

    from collections import defaultdict

    import app as app_module

    monkeypatch.setattr(app_module, "ip_failed_attempts", defaultdict(int))
    monkeypatch.setattr(app_module, "ip_blocked_until", defaultdict(lambda: None))
    monkeypatch.setattr(app_module, "session_failed_attempts", defaultdict(int))
    monkeypatch.setattr(app_module, "session_blocked_until", defaultdict(lambda: None))
    monkeypatch.setattr(app_module, "global_failed_attempts", 0)
    monkeypatch.setattr(app_module, "global_last_reset", app_module.get_current_time())
    # Reset the battery cache so each test triggers a fresh (mocked) fetch.
    monkeypatch.setattr(app_module, "_battery_cache", {"level": None, "ts": 0.0})
    monkeypatch.setattr(app_module, "user_pins", {})
    monkeypatch.setattr(app_module, "oauth", None)
    monkeypatch.setattr(app_module, "test_mode", True)
    monkeypatch.setattr(app_module, "require_pin_for_oidc", False)
    monkeypatch.setattr(app_module, "oidc_user_group", "")


@pytest.fixture
def client():
    """Create test client with test configuration."""
    import tempfile

    # Ensure test logs do not pollute repo logs
    os.environ["DOOROPENER_LOG_DIR"] = tempfile.mkdtemp(prefix="dooropener_test_logs_")

    from app import app as flask_app

    flask_app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
        RATE_LIMIT=50,
        RATE_LIMIT_WINDOW=3600,
    )

    # Reset rate limit counter
    if hasattr(flask_app, "rate_limit_counter"):
        flask_app.rate_limit_counter = {}

    with flask_app.test_client() as client:
        with flask_app.app_context():
            yield client
