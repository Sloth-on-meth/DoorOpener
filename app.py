#!/usr/bin/env python3
"""
DoorOpener Web Portal v1.14.0
------------------------------
A secure Flask web app to open a door via Home Assistant API, with visual keypad interface,
enhanced multi-layer security, timezone support, and comprehensive brute force protection.
"""

import hmac
import json
import logging
import os
import secrets
import shutil
import time
import traceback
from collections import defaultdict
from configparser import ConfigParser
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

import pytz
import requests
from flask import (
    Flask,
    g,
    jsonify,
    request,
    session,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from users_store import UsersStore

try:
    from authlib.integrations.flask_client import OAuth

    # jwt is re-exported for blueprints.auth as core.jwt; not used directly here.
    from authlib.jose import jwt  # noqa: F401
except Exception:
    OAuth = None

APP_VERSION = "1.14.0"

# --- Timezone Setup ---
# Get timezone from environment variable, default to UTC
TZ = os.environ.get("TZ", "UTC")
try:
    TIMEZONE = pytz.timezone(TZ)
    logging.getLogger("dooropener").info(f"Using timezone: {TZ}")
except pytz.exceptions.UnknownTimeZoneError:
    logging.getLogger("dooropener").warning(f"Unknown timezone '{TZ}', falling back to UTC")
    TIMEZONE = pytz.UTC
    TZ = "UTC"


def get_current_time():
    """Get current time in the configured timezone"""
    return datetime.now(TIMEZONE)


# --- Logging Setup ---
# Use a dedicated logs directory and rotate logs to avoid unbounded growth.
# Allow overriding via DOOROPENER_LOG_DIR for tests or special deployments.
log_dir = os.environ.get("DOOROPENER_LOG_DIR") or os.path.join(os.path.dirname(__file__), "logs")
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception as e:
    logging.getLogger("dooropener").error(f"Could not create log directory: {e}")
log_path = os.path.join(log_dir, "log.txt")

# Configure the root logger once: console + rotating operational log.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(os.path.join(log_dir, "door_access.log"), maxBytes=1_000_000, backupCount=3),
    ],
)

# General-purpose application logger (propagates to the root handlers above).
logger = logging.getLogger("dooropener")
logger.setLevel(logging.INFO)

# Dedicated logger for door attempts (machine-readable audit trail in log.txt).
attempt_logger = logging.getLogger("door_attempts")
attempt_logger.setLevel(logging.INFO)
_attempt_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5)
_attempt_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
attempt_logger.handlers = [_attempt_handler]

# --- Flask App Setup ---
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
# Prefer fixed secret from environment; fallback to temporary random (will be overridden by config.ini later if present)
_env_secret = os.environ.get("FLASK_SECRET_KEY")
if _env_secret:
    app.secret_key = _env_secret
    app.config["RANDOM_SECRET_WARNING"] = False
else:
    app.secret_key = secrets.token_hex(32)
    app.config["RANDOM_SECRET_WARNING"] = True

# Configure secure session cookies
# Allow overriding SESSION_COOKIE_SECURE via env for local HTTP/dev setups
_secure_cookie = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
app.config.update(
    SESSION_COOKIE_SECURE=_secure_cookie,  # Only send over HTTPS when true
    SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS access to cookies
    SESSION_COOKIE_SAMESITE="Lax",  # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),  # Default permanent session duration
)

# --- Configuration ---
config = ConfigParser()
config_path = os.path.join(os.path.dirname(__file__), "config.ini")
config.read(config_path)


def save_config() -> None:
    """Persist the current in-memory config to disk directly.

    Note: If config.ini is mounted read-only, this will raise a PermissionError or OSError.
    """
    with open(config_path, "w", encoding="utf-8") as f:
        config.write(f)


# If no env secret key was provided, allow overriding the temporary random with config.ini
if not _env_secret:
    try:
        _cfg_secret = config.get("server", "secret_key", fallback=None)
        if _cfg_secret:
            app.secret_key = _cfg_secret
            app.config["RANDOM_SECRET_WARNING"] = False
        elif app.config.get("RANDOM_SECRET_WARNING"):
            logging.getLogger("dooropener").warning(
                "FLASK_SECRET_KEY not set and no [server] secret_key in config.ini; "
                "sessions may become invalid across restarts or multiple workers."
            )
    except Exception as e:  # nosec B110 - logging warning is best-effort; failure is non-critical
        logging.getLogger("dooropener").warning(f"Could not read secret_key from config.ini: {e}")

# Per-user PINs from [pins] section (baseline, read-only)
user_pins = dict(config.items("pins")) if config.has_section("pins") else {}

# JSON-backed users store (overrides and new users). Path can be overridden in tests via env.
USERS_STORE_PATH = os.environ.get("USERS_STORE_PATH", os.path.join(os.path.dirname(__file__), "users.json"))
users_store = UsersStore(USERS_STORE_PATH)


def get_effective_user_pins() -> dict:
    """Merge config.ini [pins] with JSON store users (active only)."""
    try:
        return users_store.effective_pins(user_pins)
    except Exception:
        return dict(user_pins)


# Admin Configuration
admin_password = config.get("admin", "admin_password", fallback=None)
if not admin_password:
    raise RuntimeError(
        "No admin password configured. Set [admin] admin_password in config.ini or ensure the config file exists."
    )

# Server Configuration
server_port = int(os.environ.get("DOOROPENER_PORT", config.getint("server", "port", fallback=6532)))
test_mode = config.getboolean("server", "test_mode", fallback=False)
if test_mode:
    logging.getLogger("dooropener").warning(
        "TEST MODE ENABLED — the door will NOT open. "
        "Disable [server] test_mode in config.ini before deploying to production."
    )

# OIDC Configuration
oidc_enabled = config.getboolean("oidc", "enabled", fallback=False)
oidc_issuer = config.get("oidc", "issuer", fallback=None)
oidc_client_id = config.get("oidc", "client_id", fallback=None)
oidc_client_secret = config.get("oidc", "client_secret", fallback=None)
oidc_redirect_uri = config.get("oidc", "redirect_uri", fallback=None)
oidc_admin_group = config.get("oidc", "admin_group", fallback="")
oidc_user_group = config.get("oidc", "user_group", fallback="")
require_pin_for_oidc = config.getboolean("oidc", "require_pin_for_oidc", fallback=False)

oauth = None
if oidc_enabled and OAuth is not None and all([oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri]):
    try:
        oauth = OAuth(app)
        oauth.register(
            name="authentik",
            server_metadata_url=f"{oidc_issuer}/.well-known/openid-configuration",
            client_id=oidc_client_id,
            client_secret=oidc_client_secret,
            client_kwargs={
                "scope": "openid email profile groups",
                # Enable PKCE
                "code_challenge_method": "S256",
            },
        )
        logger.info("OIDC (Authentik) client registered with PKCE support")
    except Exception as e:
        logger.error(f"Failed to register OIDC client: {e}")
        oauth = None

# Home Assistant Configuration
ha_url = config.get("HomeAssistant", "url", fallback="http://homeassistant.local:8123")
ha_token = config.get("HomeAssistant", "token", fallback=None)
if not ha_token:
    raise RuntimeError("No Home Assistant token configured. Set [HomeAssistant] token in config.ini.")
entity_id = config.get("HomeAssistant", "switch_entity")  # Backward compatible; can be lock or switch
battery_entity = config.get(
    "HomeAssistant",
    "battery_entity",
    fallback=f"sensor.{entity_id.split('.')[1]}_battery",
)

# Optional custom CA bundle (PEM) to trust self-signed HA certificates
ha_ca_bundle = config.get("HomeAssistant", "ca_bundle", fallback="").strip()
if ha_ca_bundle and not os.path.exists(ha_ca_bundle):
    logging.getLogger("dooropener").warning(
        f"Configured HomeAssistant ca_bundle not found: {ha_ca_bundle}. Falling back to system trust store."
    )
    ha_ca_bundle = ""

# Extract device name from entity
if "." in entity_id:
    device_name = entity_id.split(".")[1]
else:
    device_name = entity_id

# Headers for HA API requests
ha_headers = {"Authorization": f"Bearer {ha_token}", "Content-Type": "application/json"}

# Short-lived cache of the last battery read, shared across all polling clients.
BATTERY_CACHE_TTL = 30  # seconds
_battery_cache: dict = {"level": None, "ts": 0.0}

# --- Enhanced Security & Rate Limiting ---
ip_failed_attempts = defaultdict(int)
ip_blocked_until = defaultdict(lambda: None)
session_failed_attempts = defaultdict(int)
session_blocked_until = defaultdict(lambda: None)
global_failed_attempts = 0
global_last_reset = get_current_time()

# Per-client last-seen times (monotonic seconds) so idle rate-limit state can be
# evicted. Without this, the dicts above grow unbounded as distinct IPs/sessions
# accumulate keys that are never removed — a slow memory-exhaustion vector.
_rate_limit_last_seen: dict[str, float] = {}
_last_cleanup_mono = time.monotonic()
RATE_LIMIT_CLEANUP_INTERVAL = 300  # seconds between sweeps

# Pushbullet configuration
pushbullet_token = config.get("pushbullet", "api_token", fallback="").strip()

# Rate limiting for problem reports: max 3 per IP per hour
_report_timestamps: dict[str, list] = defaultdict(list)
REPORT_LIMIT = 3
REPORT_WINDOW = timedelta(hours=1)

# Load security settings from config
MAX_ATTEMPTS = config.getint("security", "max_attempts", fallback=5)
BLOCK_TIME = timedelta(minutes=config.getint("security", "block_time_minutes", fallback=5))
MAX_GLOBAL_ATTEMPTS_PER_HOUR = config.getint("security", "max_global_attempts_per_hour", fallback=50)
SESSION_MAX_ATTEMPTS = config.getint("security", "session_max_attempts", fallback=3)

# --- Background image paths ---
STATIC_DIR = os.path.join(app.root_path, "static")
BACKGROUND_PATH = os.path.join(STATIC_DIR, "background.jpg")
BACKGROUND_DEFAULT_PATH = os.path.join(STATIC_DIR, "background_default.jpg")
ALLOWED_IMAGE_TYPES = {"jpg", "png", "gif", "webp"}
MAX_BACKGROUND_SIZE = 10 * 1024 * 1024  # 10 MB

# Preserve the default background on first run so it can be restored later
if os.path.exists(BACKGROUND_PATH) and not os.path.exists(BACKGROUND_DEFAULT_PATH):
    try:
        shutil.copy2(BACKGROUND_PATH, BACKGROUND_DEFAULT_PATH)
    except OSError:
        pass


def get_client_identifier():
    """Get client identifier using multiple factors for better security"""
    # Use request.remote_addr as primary (can't be spoofed easily)
    primary_ip = request.remote_addr

    # Create session-based identifier if available
    session_id = session.get("_session_id")
    if not session_id:
        session_id = secrets.token_hex(16)
        session["_session_id"] = session_id

    # Combine multiple factors for identifier
    user_agent = request.headers.get("User-Agent", "")[:100]  # Limit length
    accept_lang = request.headers.get("Accept-Language", "")[:50]

    # Create composite identifier (harder to spoof than just IP)
    identifier = f"{primary_ip}:{hash(user_agent + accept_lang) % 10000}"

    # Record activity so idle rate-limit state for these keys can be evicted later.
    now_mono = time.monotonic()
    for key in (primary_ip, session_id, identifier):
        if key:
            _rate_limit_last_seen[key] = now_mono

    return primary_ip, session_id, identifier


def _cleanup_rate_limit_state():
    """Evict idle per-client rate-limit entries to bound memory use.

    Throttled to run at most once per RATE_LIMIT_CLEANUP_INTERVAL. Keys idle longer
    than the longest meaningful window (block time and the global hourly window) are
    safe to drop: by then any block has expired and the global counter has reset.
    """
    global _last_cleanup_mono
    now_mono = time.monotonic()
    if now_mono - _last_cleanup_mono < RATE_LIMIT_CLEANUP_INTERVAL:
        return
    _last_cleanup_mono = now_mono

    now = get_current_time()
    ttl_seconds = max(BLOCK_TIME.total_seconds(), 3600) + 600
    cutoff = now_mono - ttl_seconds

    stale_keys = [k for k, seen in _rate_limit_last_seen.items() if seen < cutoff]
    for k in stale_keys:
        _rate_limit_last_seen.pop(k, None)
        ip_failed_attempts.pop(k, None)
        session_failed_attempts.pop(k, None)
        ip_blocked_until.pop(k, None)
        session_blocked_until.pop(k, None)

    # Always drop already-expired block timestamps, even for recently-seen keys.
    for blocked in (ip_blocked_until, session_blocked_until):
        for k in [k for k, v in blocked.items() if v is not None and v < now]:
            del blocked[k]

    # Prune the problem-report sliding window.
    report_cutoff = now - REPORT_WINDOW
    for ip in list(_report_timestamps.keys()):
        recent = [t for t in _report_timestamps[ip] if t > report_cutoff]
        if recent:
            _report_timestamps[ip] = recent
        else:
            del _report_timestamps[ip]


def add_security_headers(response):
    """Add security headers for reverse proxy deployment.
    Note: HSTS should be set by your TLS-terminating reverse proxy.
    """
    # MIME sniffing & legacy XSS
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Modern browser policies
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
        "magnetometer=(), gyroscope=(), fullscreen=(self), "
        "browsing-topics=(), run-ad-auction=(), join-ad-interest-group=(), "
        "private-aggregation=(), attribution-reporting=(), compute-pressure=()"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    nonce = getattr(g, "csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self' https://api.github.com; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )

    # Prevent caching of dynamic/admin JSON endpoints to avoid stale auth state
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def check_global_rate_limit():
    """Check global rate limiting across all requests"""
    global global_failed_attempts, global_last_reset
    now = get_current_time()

    # Reset global counter every hour
    if now - global_last_reset > timedelta(hours=1):
        global_failed_attempts = 0
        global_last_reset = now

    return global_failed_attempts < MAX_GLOBAL_ATTEMPTS_PER_HOUR


def is_request_suspicious():
    """Detect suspicious request patterns"""
    # Check for missing or suspicious headers
    user_agent = request.headers.get("User-Agent", "")
    if not user_agent or len(user_agent) < 10:
        return True

    # Check for common bot patterns
    suspicious_agents = ["curl", "wget", "python-requests", "bot", "crawler"]
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        return True

    return False


def validate_pin_input(pin):
    try:
        if not isinstance(pin, str):
            raise ValueError("PIN must be a string")
        if not pin.isdigit() or not (4 <= len(pin) <= 8):
            return False, None
        return True, pin
    except Exception as e:
        logger.error(f"Error validating PIN input: {e}")
        return False, None


@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)
    # Opportunistic, self-throttled sweep of idle rate-limit state.
    _cleanup_rate_limit_state()


@app.after_request
def after_request(response):
    return add_security_headers(response)


def _fetch_battery_level():
    """Read the battery level from Home Assistant. Returns an int 0-100, or None when
    there is no battery sensor or the value is unavailable/invalid."""
    try:
        url = f"{ha_url}/api/states/{battery_entity}"
        response = requests.get(url, headers=ha_headers, timeout=10, verify=(ha_ca_bundle or True))
        if response.status_code == 404:
            # Entity doesn't exist — lock has no battery sensor, ignore silently
            return None
        if response.status_code != 200:
            logger.debug(f"Battery fetch returned {response.status_code} for {battery_entity}")
            return None
        battery_level = response.json().get("state")
        if battery_level is None:
            return None
        try:
            battery_float = float(battery_level)
        except (ValueError, TypeError):
            logger.debug(f"Invalid battery level format: {battery_level}")
            return None
        if 0 <= battery_float <= 100:
            return int(battery_float)
        logger.debug(f"Battery level out of range: {battery_float}")
        return None
    except Exception as e:
        logger.debug(f"Exception fetching battery: {e}")
        return None


def log_attempt(status, details, *, user="UNKNOWN", primary_ip=None, session_id=None, now=None, extra=None):
    """Write a single structured entry to the door-attempt audit log (log.txt)."""
    entry = {
        "timestamp": (now or get_current_time()).isoformat(),
        "ip": primary_ip if primary_ip is not None else request.remote_addr,
        "session": session_id[:8] if session_id else "unknown",
        "user": user,
        "status": status,
        "details": details,
    }
    if extra:
        entry.update(extra)
    attempt_logger.info(json.dumps(entry))


def _ha_service_url():
    """Return the Home Assistant service URL appropriate for the configured entity."""
    if entity_id.startswith("lock."):
        return f"{ha_url}/api/services/lock/unlock"
    if entity_id.startswith("input_boolean."):
        return f"{ha_url}/api/services/input_boolean/turn_on"
    return f"{ha_url}/api/services/switch/turn_on"


def _enforce_active_block(session_id, identifier, now, primary_ip, user):
    """If the session or IP is currently blocked, log it and return a (response, 429)
    tuple; otherwise return None. Shared by the PIN and OIDC success paths."""
    sess_blocked = session_blocked_until[session_id] and now < session_blocked_until[session_id]
    ip_blocked = ip_blocked_until[identifier] and now < ip_blocked_until[identifier]
    if not (sess_blocked or ip_blocked):
        return None

    remaining = 0
    blocked_until_ts = None
    if sess_blocked:
        remaining = max(remaining, int((session_blocked_until[session_id] - now).total_seconds()))
        blocked_until_ts = session_blocked_until[session_id].timestamp()
    if ip_blocked:
        remaining = max(remaining, int((ip_blocked_until[identifier] - now).total_seconds()))
        ts = ip_blocked_until[identifier].timestamp()
        blocked_until_ts = max(blocked_until_ts or ts, ts)

    log_attempt(
        "BLOCK_ENFORCED",
        f"Access blocked for {remaining} more seconds",
        user=user,
        primary_ip=primary_ip,
        session_id=session_id,
        now=now,
    )
    return (
        jsonify(
            {
                "status": "error",
                "message": "Too many failed attempts. Please try again later.",
                "blocked_until": blocked_until_ts,
            }
        ),
        429,
    )


def _send_open_command(matched_user, primary_ip, session_id, now, *, via_oidc=False):
    """Open the door via Home Assistant (or simulate in test mode), log the result and
    return a Flask JSON response. Shared by the PIN and OIDC pinless success paths."""
    suffix = " via OIDC" if via_oidc else ""
    display_name = matched_user.capitalize() if isinstance(matched_user, str) else "User"

    def _record_success(test):
        detail = f"Door opened (TEST MODE){suffix}" if test else f"Door opened{suffix}"
        log_attempt("SUCCESS", detail, user=matched_user, primary_ip=primary_ip, session_id=session_id, now=now)
        try:
            users_store.touch_user(matched_user)
        except Exception:
            logger.exception("Error updating touch_user for door open")

    if test_mode:
        _record_success(test=True)
        return jsonify(
            {
                "status": "success",
                "message": f"Door open command sent (TEST MODE).\nWelcome home, {display_name}!",
            }
        )

    try:
        response = requests.post(
            _ha_service_url(),
            headers=ha_headers,
            json={"entity_id": entity_id},
            timeout=10,
            verify=(ha_ca_bundle or True),
        )
        response.raise_for_status()
        if response.status_code == 200:
            _record_success(test=False)
            return jsonify(
                {
                    "status": "success",
                    "message": f"Door open command sent.\nWelcome home, {display_name}!",
                }
            )
        reason = f"Home Assistant API error: {response.status_code}"
        log_attempt("FAILURE", reason, user=matched_user, primary_ip=primary_ip, session_id=session_id, now=now)
        return jsonify({"status": "error", "message": reason}), 500
    except requests.RequestException as e:
        logger.error(f"Error communicating with Home Assistant: {e}")
        return jsonify({"status": "error", "message": "Failed to contact Home Assistant"}), 502
    except Exception as e:
        reason = "Internal server error during API call"
        log_attempt(
            "API_FAILURE",
            reason,
            user=matched_user,
            primary_ip=primary_ip,
            session_id=session_id,
            now=now,
            extra={"exception": str(e), "traceback": traceback.format_exc()},
        )
        return jsonify({"status": "error", "message": reason}), 500


# --- Admin helper functions (shared with blueprints.admin) ---


def _backgrounds_are_identical() -> bool:
    """Return True if the current background matches the default (byte-for-byte)."""
    if not os.path.exists(BACKGROUND_DEFAULT_PATH):
        return False
    try:
        with open(BACKGROUND_PATH, "rb") as f1, open(BACKGROUND_DEFAULT_PATH, "rb") as f2:
            return f1.read() == f2.read()
    except OSError:
        return False


def _require_admin_authenticated():
    if not session.get("admin_authenticated"):
        return False
    return True


def _check_admin_csrf():
    """Validate X-CSRF-Token header for mutating admin requests."""
    token = request.headers.get("X-CSRF-Token", "")
    stored = session.get("admin_csrf_token", "")
    if not stored or not token:
        return False
    return hmac.compare_digest(token, stored)


# --- Register route blueprints ---
# Imported here, after all shared state and helpers are defined, so the blueprint
# modules can `import app as core` without hitting a circular-import problem.
from blueprints.admin import admin_bp  # noqa: E402
from blueprints.auth import auth_bp  # noqa: E402
from blueprints.door import door_bp  # noqa: E402

app.register_blueprint(door_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(auth_bp)


if __name__ == "__main__":
    _debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    if _debug:
        logger.warning(
            "FLASK_DEBUG is enabled — the Werkzeug interactive debugger is active. "
            "This allows remote code execution via the browser. NEVER enable in production."
        )
    app.run(
        host="0.0.0.0",  # nosec B104 - intentional; server is designed to listen on all interfaces
        port=server_port,
        debug=_debug,
    )
