"""Configuration loader for DoorOpener.

Reads ``options.json`` (path overridable via ``DOOROPENER_OPTIONS_PATH`` env var)
and exposes all settings as module-level attributes.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

logger = logging.getLogger("dooropener")

# ---------------------------------------------------------------------------
# Timezone
# ---------------------------------------------------------------------------
TZ = os.environ.get("TZ", "UTC")
try:
    TIMEZONE = ZoneInfo(TZ)
except Exception:
    logger.warning("Unknown timezone '%s', falling back to UTC", TZ)
    TIMEZONE = ZoneInfo("UTC")
    TZ = "UTC"


def get_current_time() -> datetime:
    """Return the current time in the configured timezone."""
    return datetime.now(TIMEZONE)


# ---------------------------------------------------------------------------
# Load options.json
# ---------------------------------------------------------------------------
OPTIONS_PATH = os.environ.get(
    "DOOROPENER_OPTIONS_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "options.json"),
)

try:
    with open(OPTIONS_PATH, "r", encoding="utf-8") as _f:
        _opts = json.load(_f)
except FileNotFoundError as _e:
    raise RuntimeError(
        f"Options file not found: {OPTIONS_PATH}. "
        "Copy options.json.example to options.json and configure it."
    ) from _e

# ---------------------------------------------------------------------------
# Home Assistant
# ---------------------------------------------------------------------------
ha_url: str = (_opts.get("ha_url") or "").rstrip("/")
ha_token: str = (_opts.get("ha_token") or "").strip()
entity_id: str = (_opts.get("entity_id") or "").strip()

_entity_parts = entity_id.split(".", 1)
device_name: str = _entity_parts[1] if len(_entity_parts) == 2 else entity_id

battery_entity: str = (
    _opts.get("battery_entity") or f"sensor.{device_name}_battery"
).strip()

ha_ca_bundle: str = (
    _opts.get("ca_bundle") or os.getenv("REQUESTS_CA_BUNDLE", "")
).strip()
if ha_ca_bundle and not os.path.exists(ha_ca_bundle):
    logger.warning(
        "Configured ca_bundle not found: %s. Falling back to system trust store.",
        ha_ca_bundle,
    )
    ha_ca_bundle = ""

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
server_port: int = int(os.environ.get("DOOROPENER_PORT", _opts.get("port", 6532)))
test_mode: bool = bool(_opts.get("test_mode", False))
admin_password: str = (_opts.get("admin_password") or "").strip()

# ---------------------------------------------------------------------------
# Security thresholds
# ---------------------------------------------------------------------------
MAX_ATTEMPTS: int = int(_opts.get("max_attempts", 5))
BLOCK_TIME: timedelta = timedelta(minutes=int(_opts.get("block_time_minutes", 5)))
MAX_GLOBAL_ATTEMPTS_PER_HOUR: int = int(
    _opts.get("max_global_attempts_per_hour", 50)
)
SESSION_MAX_ATTEMPTS: int = int(_opts.get("session_max_attempts", 3))

# ---------------------------------------------------------------------------
# Flask secret key
# ---------------------------------------------------------------------------
_env_secret = os.environ.get("FLASK_SECRET_KEY")
if _env_secret:
    secret_key: str | None = _env_secret
    random_secret_warning: bool = False
else:
    _cfg_secret = (_opts.get("secret_key") or "").strip()
    if _cfg_secret:
        secret_key = _cfg_secret
        random_secret_warning = False
    else:
        secret_key = None  # Will be generated randomly at app startup
        random_secret_warning = True

# ---------------------------------------------------------------------------
# Session cookie security
# ---------------------------------------------------------------------------
_env_secure = os.environ.get("SESSION_COOKIE_SECURE")
if _env_secure is not None:
    session_cookie_secure: bool = _env_secure.lower() == "true"
else:
    session_cookie_secure = bool(_opts.get("session_cookie_secure", False))
