"""Pytest configuration and fixtures for DoorOpener tests.

Creates a temporary options.json BEFORE any app imports so that config.py
(and hence app.py) loads test values.
"""
import json
import os
import sys
import tempfile

import pytest

# Add dooropener/ package directory to path (app source lives there)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dooropener")))

# ---------------------------------------------------------------------------
# Build temp options.json and set env vars BEFORE any app/config imports
# ---------------------------------------------------------------------------
TEST_OPTIONS = {
    "ha_url": "http://test-ha:8123",
    "ha_token": "test-token",
    "entity_id": "switch.test_door",
    "battery_entity": "sensor.test_door_battery",
    "port": 6532,
    "test_mode": True,
    "admin_password": "testpass",
    "max_attempts": 5,
    "block_time_minutes": 5,
    "max_global_attempts_per_hour": 50,
    "session_max_attempts": 3,
    "secret_key": "test-secret-key-fixed",
    "session_cookie_secure": False,
    "ha_cert_pem": "",
}

_tmp_dir = tempfile.mkdtemp(prefix="dooropener_test_")
_opts_path = os.path.join(_tmp_dir, "options.json")
with open(_opts_path, "w") as _f:
    json.dump(TEST_OPTIONS, _f)

os.environ["DOOROPENER_OPTIONS_PATH"] = _opts_path
os.environ["DOOROPENER_LOG_DIR"] = os.path.join(_tmp_dir, "logs")
os.environ["USERS_STORE_PATH"] = os.path.join(_tmp_dir, "users.json")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def client():
    """Flask test client."""
    import app as app_module

    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        with app_module.app.app_context():
            yield c


@pytest.fixture(autouse=True)
def reset_state():
    """Reset rate-limiter state and user_pins between tests."""
    import app as app_module

    app_module.rate_limiter.ip_failed.clear()
    app_module.rate_limiter.ip_blocked_until.clear()
    app_module.rate_limiter.session_failed.clear()
    app_module.rate_limiter.session_blocked_until.clear()
    app_module.rate_limiter.global_failed = 0
    app_module.rate_limiter.global_last_reset = app_module.get_current_time()
    app_module.user_pins.clear()
    # Reset test_mode to True (options.json default)
    app_module.test_mode = True
    yield
