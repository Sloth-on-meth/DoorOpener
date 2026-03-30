#!/usr/bin/env python3
"""
DoorOpener Web Portal v1.12.2
------------------------------
A secure Flask web app to open a door via Home Assistant API, with visual keypad interface,
enhanced multi-layer security, timezone support, and comprehensive brute force protection.
"""

import hmac
import json
import logging
import os
import secrets
import tempfile
import time
import traceback
from collections import defaultdict
from configparser import ConfigParser
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler

import pytz
import requests
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from users_store import UsersStore

try:
    from authlib.integrations.flask_client import OAuth
    from authlib.jose import jwt
except Exception:
    OAuth = None

APP_VERSION = "1.12.2"

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

# Dedicated logger for door attempts (audit trail)
attempt_logger = logging.getLogger("door_attempts")
attempt_logger.setLevel(logging.INFO)
file_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
attempt_logger.handlers = [file_handler]

# Add a logger for general errors if not already present
logger = logging.getLogger("dooropener")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

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

# --- Enhanced Security & Rate Limiting ---
ip_failed_attempts = defaultdict(int)
ip_blocked_until = defaultdict(lambda: None)
session_failed_attempts = defaultdict(int)
session_blocked_until = defaultdict(lambda: None)
global_failed_attempts = 0
global_last_reset = get_current_time()
# Load security settings from config
MAX_ATTEMPTS = config.getint("security", "max_attempts", fallback=5)
BLOCK_TIME = timedelta(minutes=config.getint("security", "block_time_minutes", fallback=5))
MAX_GLOBAL_ATTEMPTS_PER_HOUR = config.getint("security", "max_global_attempts_per_hour", fallback=50)
SESSION_MAX_ATTEMPTS = config.getint("security", "session_max_attempts", fallback=3)

# Configure main logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(os.path.join(log_dir, "door_access.log"), maxBytes=1_000_000, backupCount=3),
    ],
)
logger = logging.getLogger(__name__)


@app.route("/service-worker.js")
def service_worker():
    """Serve the service worker at the root scope for PWA installation."""
    try:
        return send_from_directory(
            os.path.join(app.root_path, "static"),
            "service-worker.js",
            mimetype="application/javascript",
        )
    except Exception:
        abort(404)


@app.route("/manifest.webmanifest")
def manifest_file():
    """Serve the web app manifest with the correct MIME type."""
    try:
        return send_from_directory(
            os.path.join(app.root_path, "static"),
            "manifest.webmanifest",
            mimetype="application/manifest+json",
        )
    except Exception:
        abort(404)


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

    return primary_ip, session_id, identifier


def add_security_headers(response):
    """Add security headers for reverse proxy deployment.
    Note: HSTS should be set by your TLS-terminating reverse proxy.
    """
    # MIME sniffing & legacy XSS
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"

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


@app.after_request
def after_request(response):
    return add_security_headers(response)


@app.route("/")
def index():
    easter_egg_enabled = config.getboolean("server", "67mode", fallback=False)
    page_title = config.get("server", "page_title", fallback="").strip()
    notice = config.get("server", "notice", fallback="").strip()
    return render_template(
        "index.html",
        oidc_enabled=bool(oauth),
        require_pin_for_oidc=require_pin_for_oidc,
        easter_egg_enabled=easter_egg_enabled,
        app_version=APP_VERSION,
        csp_nonce=g.csp_nonce,
        page_title=page_title,
        notice=notice,
    )


@app.route("/battery")
def battery():
    """Get battery level from Home Assistant battery sensor entity"""
    try:
        logger.info(f"Battery endpoint called - fetching state for entity: {battery_entity}")
        url = f"{ha_url}/api/states/{battery_entity}"
        response = requests.get(
            url,
            headers=ha_headers,
            timeout=10,
            verify=(ha_ca_bundle or True),
        )
        if response.status_code == 200:
            state_data = response.json()
            battery_level = state_data.get("state")
            logger.info(f"Battery response: {state_data}")

            # Handle different battery level formats
            if battery_level is not None:
                try:
                    # Convert to float and ensure it's a valid percentage
                    battery_float = float(battery_level)
                    if 0 <= battery_float <= 100:
                        return jsonify({"level": int(battery_float)})
                    else:
                        logger.warning(f"Battery level out of range: {battery_float}")
                        return jsonify({"level": None})
                except (ValueError, TypeError):
                    logger.warning(f"Invalid battery level format: {battery_level}")
                    return jsonify({"level": None})
            else:
                logger.warning("Battery level is None")
                return jsonify({"level": None})
        else:
            logger.error(f"Failed to fetch battery state: {response.status_code} {response.text}")
            return jsonify({"level": None})
    except Exception as e:
        logger.error(f"Exception fetching battery: {e}")
        return jsonify({"level": None})


@app.route("/open-door", methods=["POST"])
def open_door():
    try:
        primary_ip, session_id, identifier = get_client_identifier()
        now = get_current_time()
        global global_failed_attempts

        # Check for suspicious requests first
        if is_request_suspicious():
            reason = "Suspicious request detected"
            log_entry = {
                "timestamp": now.isoformat(),
                "ip": primary_ip,
                "session": session_id[:8],
                "user": "UNKNOWN",
                "status": "SUSPICIOUS",
                "details": reason,
            }
            attempt_logger.info(json.dumps(log_entry))
            return jsonify({"status": "error", "message": "Request blocked"}), 403

        # Check global rate limit
        if not check_global_rate_limit():
            reason = "Global rate limit exceeded"
            log_entry = {
                "timestamp": now.isoformat(),
                "ip": primary_ip,
                "session": session_id[:8],
                "user": "UNKNOWN",
                "status": "GLOBAL_BLOCKED",
                "details": reason,
            }
            attempt_logger.info(json.dumps(log_entry))
            return (
                jsonify({"status": "error", "message": "Service temporarily unavailable"}),
                429,
            )

        # Enforce session-based blocking stored in signed cookie (persists across workers)
        sess_block_ts = session.get("blocked_until_ts")
        if sess_block_ts and time.time() < float(sess_block_ts):
            remaining = int(float(sess_block_ts) - time.time())
            reason = f"Session blocked for {remaining} more seconds (persisted)"
            log_entry = {
                "timestamp": now.isoformat(),
                "ip": primary_ip,
                "session": session_id[:8],
                "user": "UNKNOWN",
                "status": "SESSION_BLOCKED",
                "details": reason,
            }
            attempt_logger.info(json.dumps(log_entry))
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Too many failed attempts. Please try again later.",
                        "blocked_until": float(sess_block_ts),
                    }
                ),
                429,
            )

        # Check in-memory session-based blocking (fallback when running single-worker)
        if session_blocked_until[session_id] and now < session_blocked_until[session_id]:
            remaining = (session_blocked_until[session_id] - now).total_seconds()
            reason = f"Session blocked for {int(remaining)} more seconds"
            log_entry = {
                "timestamp": now.isoformat(),
                "ip": primary_ip,
                "session": session_id[:8],
                "user": "UNKNOWN",
                "status": "SESSION_BLOCKED",
                "details": reason,
            }
            attempt_logger.info(json.dumps(log_entry))
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Too many failed attempts. Please try again later.",
                        "blocked_until": session_blocked_until[session_id].timestamp(),
                    }
                ),
                429,
            )

        # Check IP-based blocking (fallback)
        if ip_blocked_until[identifier] and now < ip_blocked_until[identifier]:
            remaining = (ip_blocked_until[identifier] - now).total_seconds()
            reason = f"IP blocked for {int(remaining)} more seconds"
            log_entry = {
                "timestamp": now.isoformat(),
                "ip": primary_ip,
                "session": session_id[:8],
                "user": "UNKNOWN",
                "status": "IP_BLOCKED",
                "details": reason,
            }
            attempt_logger.info(json.dumps(log_entry))
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Too many failed attempts. Please try again later.",
                        "blocked_until": ip_blocked_until[identifier].timestamp(),
                    }
                ),
                429,
            )

        # Determine if OIDC session can open without PIN
        # OIDC must be fully enabled (oauth registered), otherwise treat as unauthenticated
        oidc_auth = bool(oauth) and bool(session.get("oidc_authenticated"))
        oidc_exp = session.get("oidc_exp")

        # Check token expiration
        oidc_session_expired = False
        if oidc_auth and (not oidc_exp or oidc_exp < time.time()):
            # OIDC session has expired, clear all relevant session data
            session.pop("oidc_authenticated", None)
            session.pop("oidc_user", None)
            session.pop("oidc_groups", None)
            session.pop("oidc_exp", None)
            oidc_auth = False  # Reset flag for the rest of the function
            oidc_session_expired = True
            logger.warning(f"OIDC session for IP {primary_ip} has expired. Re-authentication required.")

        oidc_groups = session.get("oidc_groups", [])
        oidc_user = session.get("oidc_user")
        oidc_user_allowed = (not oidc_user_group) or (oidc_user_group in oidc_groups)

        data = request.get_json(force=True, silent=True)
        pin_from_request = data.get("pin") if data else None

        # If session expired and no PIN provided, return a clear error instead of confusing "PIN required"
        if oidc_session_expired and not pin_from_request:
            return jsonify({"status": "error", "message": "Session expired. Please log in again."}), 401

        # If no PIN provided but OIDC user is authenticated and allowed, proceed without PIN
        if (not pin_from_request) and oidc_auth and oidc_user_allowed and not require_pin_for_oidc:
            # Re-check block state right before granting access
            if (session_blocked_until[session_id] and now < session_blocked_until[session_id]) or (
                ip_blocked_until[identifier] and now < ip_blocked_until[identifier]
            ):
                remaining = 0
                if session_blocked_until[session_id] and now < session_blocked_until[session_id]:
                    remaining = max(
                        remaining,
                        int((session_blocked_until[session_id] - now).total_seconds()),
                    )
                if ip_blocked_until[identifier] and now < ip_blocked_until[identifier]:
                    remaining = max(
                        remaining,
                        int((ip_blocked_until[identifier] - now).total_seconds()),
                    )
                reason = f"Access blocked for {remaining} more seconds"
                log_entry = {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": oidc_user or "UNKNOWN",
                    "status": "BLOCK_ENFORCED",
                    "details": reason,
                }
                attempt_logger.info(json.dumps(log_entry))
                # Determine latest block end
                blocked_until_ts = None
                if session_blocked_until[session_id] and now < session_blocked_until[session_id]:
                    blocked_until_ts = session_blocked_until[session_id].timestamp()
                if ip_blocked_until[identifier] and now < ip_blocked_until[identifier]:
                    ts = ip_blocked_until[identifier].timestamp()
                    blocked_until_ts = max(blocked_until_ts or ts, ts)
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

            matched_user = oidc_user or "oidc-user"
            # Reset failed attempts upon authorized OIDC use only if not currently blocked
            if not (session_blocked_until[session_id] and now < session_blocked_until[session_id]) and not (
                ip_blocked_until[identifier] and now < ip_blocked_until[identifier]
            ):
                ip_failed_attempts[identifier] = 0
                session_failed_attempts[session_id] = 0
                if identifier in ip_blocked_until:
                    del ip_blocked_until[identifier]
                if session_id in session_blocked_until:
                    del session_blocked_until[session_id]

            # Test or production flow mirrors the successful PIN path
            if test_mode:
                reason = "Door opened (TEST MODE) via OIDC"
                log_entry = {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": matched_user,
                    "status": "SUCCESS",
                    "details": reason,
                }
                attempt_logger.info(json.dumps(log_entry))
                display_name = matched_user.capitalize() if isinstance(matched_user, str) else "User"
                return jsonify(
                    {
                        "status": "success",
                        "message": f"Door open command sent (TEST MODE).\nWelcome home, {display_name}!",
                    }
                )

            try:
                if entity_id.startswith("lock."):
                    url = f"{ha_url}/api/services/lock/unlock"
                elif entity_id.startswith("input_boolean."):
                    url = f"{ha_url}/api/services/input_boolean/turn_on"
                else:
                    url = f"{ha_url}/api/services/switch/turn_on"
                payload = {"entity_id": entity_id}
                response = requests.post(
                    url,
                    headers=ha_headers,
                    json=payload,
                    timeout=10,
                    verify=(ha_ca_bundle or True),
                )
                response.raise_for_status()
                if response.status_code == 200:
                    reason = "Door opened via OIDC"
                    log_entry = {
                        "timestamp": now.isoformat(),
                        "ip": primary_ip,
                        "session": session_id[:8],
                        "user": matched_user,
                        "status": "SUCCESS",
                        "details": reason,
                    }
                    attempt_logger.info(json.dumps(log_entry))
                    try:
                        users_store.touch_user(matched_user)
                    except Exception:
                        logger.exception("Error updating touch_user for OIDC open")
                    display_name = matched_user.capitalize() if isinstance(matched_user, str) else "User"
                    return jsonify(
                        {
                            "status": "success",
                            "message": f"Door open command sent.\nWelcome home, {display_name}!",
                        }
                    )
                else:
                    reason = f"Home Assistant API error: {response.status_code}"
                    log_entry = {
                        "timestamp": now.isoformat(),
                        "ip": primary_ip,
                        "session": session_id[:8],
                        "user": matched_user,
                        "status": "FAILURE",
                        "details": reason,
                    }
                    attempt_logger.info(json.dumps(log_entry))
                    return jsonify({"status": "error", "message": reason}), 500
            except requests.RequestException as e:
                logger.error(f"Error communicating with Home Assistant: {e}")
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Failed to contact Home Assistant",
                        }
                    ),
                    502,
                )
            except Exception as e:
                reason = "Internal server error during API call"
                log_entry = {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": matched_user,
                    "status": "API_FAILURE",
                    "details": reason,
                    "exception": str(e),
                    "traceback": traceback.format_exc(),
                }
                attempt_logger.info(json.dumps(log_entry))
                return jsonify({"status": "error", "message": reason}), 500

        # If we reach here, require a PIN (either because provided or policy demands it)
        if not data or "pin" not in data:
            logger.warning("No PIN provided in request body")
            return jsonify({"status": "error", "message": "PIN required"}), 400

        # Validate PIN format
        pin_valid, validated_pin = validate_pin_input(pin_from_request)
        if not pin_valid:
            # Increment all counters on invalid input
            ip_failed_attempts[identifier] += 1
            session_failed_attempts[session_id] += 1
            global_failed_attempts += 1

            reason = "Invalid PIN format"  # Error message
            log_entry = {
                "timestamp": now.isoformat(),
                "ip": primary_ip,
                "session": session_id[:8],
                "user": "UNKNOWN",
                "status": "INVALID_FORMAT",
                "details": reason,
            }
            attempt_logger.info(json.dumps(log_entry))
            return jsonify({"status": "error", "message": reason}), 400

        pin_from_request = validated_pin
        matched_user = None

        # Check PIN against user database (effective set)
        for user, user_pin in get_effective_user_pins().items():
            if hmac.compare_digest(pin_from_request, user_pin):
                matched_user = user
                break

        if matched_user:
            # Enforce any active block even on correct PIN before proceeding
            if (session_blocked_until[session_id] and now < session_blocked_until[session_id]) or (
                ip_blocked_until[identifier] and now < ip_blocked_until[identifier]
            ):
                remaining = 0
                if session_blocked_until[session_id] and now < session_blocked_until[session_id]:
                    remaining = max(
                        remaining,
                        int((session_blocked_until[session_id] - now).total_seconds()),
                    )
                if ip_blocked_until[identifier] and now < ip_blocked_until[identifier]:
                    remaining = max(
                        remaining,
                        int((ip_blocked_until[identifier] - now).total_seconds()),
                    )
                reason = f"Access blocked for {remaining} more seconds"
                log_entry = {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": matched_user,
                    "status": "BLOCK_ENFORCED",
                    "details": reason,
                }
                attempt_logger.info(json.dumps(log_entry))
                # Determine latest block end
                blocked_until_ts = None
                if session_blocked_until[session_id] and now < session_blocked_until[session_id]:
                    blocked_until_ts = session_blocked_until[session_id].timestamp()
                if ip_blocked_until[identifier] and now < ip_blocked_until[identifier]:
                    ts = ip_blocked_until[identifier].timestamp()
                    blocked_until_ts = max(blocked_until_ts or ts, ts)
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

            # Reset failed attempts on successful auth (only when no active block)
            ip_failed_attempts[identifier] = 0
            session_failed_attempts[session_id] = 0
            if identifier in ip_blocked_until:
                del ip_blocked_until[identifier]
            if session_id in session_blocked_until:
                del session_blocked_until[session_id]
            session.pop("blocked_until_ts", None)

            # Check if test mode is enabled
            if test_mode:
                # Test mode: simulate successful door opening without API call
                reason = "Door opened (TEST MODE)"
                log_entry = {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": matched_user,
                    "status": "SUCCESS",
                    "details": reason,
                }
                attempt_logger.info(json.dumps(log_entry))
                try:
                    users_store.touch_user(matched_user)
                except Exception:
                    logger.exception("Error updating touch_user for PIN open (test mode)")
                display_name = matched_user.capitalize()
                return jsonify(
                    {
                        "status": "success",
                        "message": f"Door open command sent (TEST MODE).\nWelcome home, {display_name}!",
                    }
                )

            # Production mode: try to open door via Home Assistant
            try:
                if entity_id.startswith("lock."):
                    url = f"{ha_url}/api/services/lock/unlock"
                elif entity_id.startswith("input_boolean."):
                    url = f"{ha_url}/api/services/input_boolean/turn_on"
                else:
                    url = f"{ha_url}/api/services/switch/turn_on"
                payload = {"entity_id": entity_id}
                response = requests.post(
                    url,
                    headers=ha_headers,
                    json=payload,
                    timeout=10,
                    verify=(ha_ca_bundle or True),
                )

                response.raise_for_status()  # Raise an exception for bad status codes

                if response.status_code == 200:
                    reason = "Door opened"
                    log_entry = {
                        "timestamp": now.isoformat(),
                        "ip": primary_ip,
                        "session": session_id[:8],
                        "user": matched_user,
                        "status": "SUCCESS",
                        "details": reason,
                    }
                    attempt_logger.info(json.dumps(log_entry))
                    try:
                        users_store.touch_user(matched_user)
                    except Exception:
                        logger.exception("Error updating touch_user for PIN open (prod)")
                    display_name = matched_user.capitalize()
                    return jsonify(
                        {
                            "status": "success",
                            "message": f"Door open command sent.\nWelcome home, {display_name}!",
                        }
                    )
                else:
                    reason = f"Home Assistant API error: {response.status_code}"
                    log_entry = {
                        "timestamp": now.isoformat(),
                        "ip": primary_ip,
                        "session": session_id[:8],
                        "user": matched_user,
                        "status": "FAILURE",
                        "details": reason,
                    }
                    attempt_logger.info(json.dumps(log_entry))
                    return jsonify({"status": "error", "message": reason}), 500
            except requests.RequestException as e:
                logger.error(f"Error communicating with Home Assistant: {e}")
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Failed to contact Home Assistant",
                        }
                    ),
                    502,
                )
            except Exception as e:
                reason = "Internal server error during API call"
                log_entry = {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": matched_user,
                    "status": "API_FAILURE",
                    "details": reason,
                    "exception": str(e),
                    "traceback": traceback.format_exc(),
                }
                attempt_logger.info(json.dumps(log_entry))
                return jsonify({"status": "error", "message": reason}), 500
        else:
            # Check if the PIN belongs to a disabled store user before treating as wrong PIN
            disabled_user = users_store.find_disabled_user_by_pin(pin_from_request)
            if disabled_user:
                log_entry = {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": disabled_user,
                    "status": "DISABLED_USER",
                    "details": "Access denied: account disabled",
                }
                attempt_logger.info(json.dumps(log_entry))
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Your account has been disabled. Contact the administrator.",
                        }
                    ),
                    403,
                )

            # Failed authentication - increment all counters
            ip_failed_attempts[identifier] += 1
            session_failed_attempts[session_id] += 1
            global_failed_attempts += 1

            # Check session-based blocking first (harder to bypass)
            if session_failed_attempts[session_id] >= SESSION_MAX_ATTEMPTS:
                session_blocked_until[session_id] = now + BLOCK_TIME
                # Also persist in signed session cookie so block applies across workers
                session["blocked_until_ts"] = (get_current_time() + BLOCK_TIME).timestamp()
                reason = f"Invalid PIN. Session blocked for {int(BLOCK_TIME.total_seconds() // 60)} minutes"
            elif ip_failed_attempts[identifier] >= MAX_ATTEMPTS:
                ip_blocked_until[identifier] = now + BLOCK_TIME
                reason = f"Invalid PIN. Access blocked for {int(BLOCK_TIME.total_seconds() // 60)} minutes"
            else:
                reason = "Invalid PIN"

            log_entry = {
                "timestamp": now.isoformat(),
                "ip": primary_ip,
                "session": session_id[:8],
                "user": "UNKNOWN",
                "status": "AUTH_FAILURE",
                "details": reason,
            }
            attempt_logger.info(json.dumps(log_entry))
            # Include blocked_until if a block is now active
            resp = {"status": "error", "message": reason}
            if session_blocked_until[session_id] and now < session_blocked_until[session_id]:
                resp["blocked_until"] = session_blocked_until[session_id].timestamp()
            elif ip_blocked_until[identifier] and now < ip_blocked_until[identifier]:
                resp["blocked_until"] = ip_blocked_until[identifier].timestamp()
            return jsonify(resp), 401

    except Exception as e:
        try:
            primary_ip, session_id, _ = get_client_identifier()
        except Exception:
            primary_ip = request.remote_addr
            session_id = "unknown"

        log_entry = {
            "timestamp": get_current_time().isoformat(),
            "ip": primary_ip,
            "session": session_id[:8] if session_id != "unknown" else "unknown",
            "user": "UNKNOWN",
            "status": "EXCEPTION",
            "details": f"Exception in open_door: {e}",
        }
        attempt_logger.info(json.dumps(log_entry))
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.route("/admin")
def admin():
    return render_template("admin.html", oidc_enabled=bool(oauth), app_version=APP_VERSION, csp_nonce=g.csp_nonce)


# --- OIDC (Authentik) Routes ---
@app.route("/login")
def login_redirect():
    if not oauth:
        # Fallback to local login page
        return redirect(url_for("admin"))

    # Generate a random state and store it in the session
    session["oidc_state"] = secrets.token_hex(16)

    # Generate a random nonce and store it in the session
    session["oidc_nonce"] = secrets.token_hex(16)

    # Start OIDC flow with the generated state and nonce
    _redirect_uri = oidc_redirect_uri or url_for("oidc_callback", _external=True)
    return oauth.authentik.authorize_redirect(
        redirect_uri=_redirect_uri,
        state=session["oidc_state"],
        nonce=session["oidc_nonce"],
    )


@app.route("/oidc/callback")
def oidc_callback():
    if not oauth:
        return redirect(url_for("admin"))
    try:
        # Validate the state parameter to prevent CSRF attacks
        if request.args.get("state") != session.pop("oidc_state", None):
            abort(401, "Invalid state")

        # Authorize the access token from the OIDC provider
        token = oauth.authentik.authorize_access_token()

        # Extract the ID token and claims
        id_token = token.get("id_token")
        claims = {}
        try:
            # Authlib stores parsed claims at token['userinfo'] or use userinfo() call
            claims = token.get("userinfo") or oauth.authentik.parse_id_token(token)
        except Exception:
            try:
                claims = oauth.authentik.userinfo(token=token)
            except Exception:
                claims = {}

        # Validate the nonce value to prevent replay attacks
        if claims.get("nonce") != session.pop("oidc_nonce", None):
            abort(401, "Invalid nonce")

        # Verify the ID token signature and claims
        public_key = config.get("oidc", "public_key", fallback=None)
        if public_key:
            try:
                claims = jwt.decode(id_token, key=public_key)
                # Validate signature, expiration, audience, etc.
                claims.validate()
            except Exception as e:
                logger.error(f"ID token validation error: {e}")
                return abort(401)

        # Validate the audience (aud) claim to ensure the token is intended for this application
        aud = claims.get("aud")
        aud_valid = False
        if isinstance(aud, list):
            aud_valid = oidc_client_id in aud
        else:
            aud_valid = aud == oidc_client_id
        if not aud_valid:
            logger.error(f"Invalid audience: {aud}")
            abort(401, "Invalid audience")

        # Validate issuer (iss) matches configured issuer
        iss = claims.get("iss")
        if iss and oidc_issuer and iss.rstrip("/") != oidc_issuer.rstrip("/"):
            logger.error(f"Invalid issuer: {iss}")
            abort(401, "Invalid issuer")

        # Validate the expiration time (exp) claim to ensure the token is still valid
        # Expiration and not-before with small clock skew allowance
        leeway = 60  # seconds
        now_utc = datetime.now(timezone.utc)
        exp = claims.get("exp")
        if exp:
            expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            if expiration_time + timedelta(seconds=leeway) < now_utc:
                logger.error("ID token has expired")
                abort(401, "Token has expired")
        nbf = claims.get("nbf")
        if nbf:
            not_before = datetime.fromtimestamp(nbf, tz=timezone.utc)
            if not_before - timedelta(seconds=leeway) > now_utc:
                logger.error("ID token not yet valid")
                abort(401, "Token not yet valid")

        # Reset the session to prevent session fixation attacks
        session.clear()

        # Extract user information from the claims
        user = claims.get("email") or claims.get("preferred_username") or claims.get("name") or "oidc-user"
        groups = claims.get("groups") or claims.get("roles") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]

        # Validate groups if they are defined in the configuration
        if oidc_admin_group or oidc_user_group:
            if not groups:
                logger.error("No groups found in ID token")
                abort(403, "Access denied: No groups found")

            # Check if the user is in the admin group
            is_admin = oidc_admin_group in groups if oidc_admin_group else False

            # Check if the user is in the allowed user group
            is_user_allowed = oidc_user_group in groups if oidc_user_group else True

            if not is_user_allowed:
                logger.error(f"User {user} is not in the allowed group")
                abort(403, "Access denied: User not in allowed group")
        else:
            # If no groups are defined in the config, allow access based on OIDC provider
            is_admin = False
            is_user_allowed = True

        # Store OIDC session information
        session["oidc_authenticated"] = True
        session["oidc_user"] = user
        session["oidc_groups"] = groups
        session["oidc_exp"] = claims.get("exp")  # Store token expiration time

        # If the user is an admin, set the admin flags in the session.
        if is_admin:
            session["admin_authenticated"] = True
            session["admin_login_time"] = get_current_time().isoformat()
            session["admin_user"] = user

        # All users are redirected to the home page after login.
        return redirect(url_for("index"))
    except Exception as e:
        logger.error(f"OIDC callback error: {e}")
        return abort(401)


@app.route("/admin/auth", methods=["POST"])
def admin_auth():
    """Authenticate admin password with progressive delays and temporary blocking.
    Uses the same session-based counters as open_door to slow brute force attempts.
    """
    data = request.get_json()
    password = data.get("password", "").strip() if data else ""
    remember_me = data.get("remember_me", False) if data else False

    # Identify client/session for throttling
    primary_ip, session_id, identifier = get_client_identifier()

    # Check if this session is currently blocked
    now = get_current_time()
    if session_blocked_until.get(session_id) and now < session_blocked_until[session_id]:
        remaining = (session_blocked_until[session_id] - now).total_seconds()
        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": "ADMIN",  # role indicator, not a username
                    "status": "ADMIN_SESSION_BLOCKED",
                    "details": f"Admin auth blocked for {int(remaining)}s",
                }
            )
        )
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Too many failed attempts. Please try later.",
                }
            ),
            429,
        )

    if hmac.compare_digest(password, admin_password):
        # Success: clear counters for this session
        session_failed_attempts[session_id] = 0
        if session_id in session_blocked_until:
            del session_blocked_until[session_id]

        session["admin_authenticated"] = True
        session["admin_login_time"] = now.isoformat()
        session["admin_csrf_token"] = secrets.token_hex(32)

        # Set session to be permanent if remember_me is checked
        if remember_me:
            session.permanent = True
            # Set cookie to expire in 30 days
            app.permanent_session_lifetime = timedelta(days=30)
        else:
            session.permanent = False
            # Session expires when browser closes

        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": "ADMIN",
                    "status": "ADMIN_SUCCESS",
                    "details": "Admin login",
                }
            )
        )
        return jsonify({"status": "success"})
    else:
        # Failure: increment counters
        session_failed_attempts[session_id] += 1

        # Block session after SESSION_MAX_ATTEMPTS failures
        if session_failed_attempts[session_id] >= SESSION_MAX_ATTEMPTS:
            session_blocked_until[session_id] = now + BLOCK_TIME
            details = f"Invalid admin password. Session blocked for {int(BLOCK_TIME.total_seconds() // 60)} minutes"
        else:
            details = "Invalid admin password"

        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": "ADMIN",
                    "status": "ADMIN_FAILURE",
                    "details": details,
                }
            )
        )
        return jsonify({"status": "error", "message": "Invalid admin password"}), 403


@app.route("/admin/check-auth", methods=["GET"])
def admin_check_auth():
    """Check if admin is currently authenticated"""
    if session.get("admin_authenticated"):
        login_time = session.get("admin_login_time")
        csrf_token = session.get("admin_csrf_token")
        return jsonify({"authenticated": True, "login_time": login_time, "csrf_token": csrf_token})
    else:
        return jsonify({"authenticated": False})


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    """Logout admin user"""
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    session.pop("admin_authenticated", None)
    session.pop("admin_login_time", None)
    session.pop("admin_csrf_token", None)
    session.permanent = False
    return jsonify({"status": "success", "message": "Logged out successfully"})


@app.route("/admin/notice", methods=["GET"])
def admin_notice_get():
    """Return the current public notice (no auth required — displayed on keypad page)."""
    notice = config.get("server", "notice", fallback="").strip()
    return jsonify({"notice": notice})


@app.route("/admin/notice", methods=["POST"])
def admin_notice_set():
    """Set or clear the public notice. Requires admin auth."""
    if not _require_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json(silent=True) or {}
    notice = data.get("notice", "").strip()
    if not config.has_section("server"):
        config.add_section("server")
    if notice:
        config.set("server", "notice", notice)
    else:
        config.remove_option("server", "notice")
    try:
        save_config()
    except OSError as e:
        return jsonify({"error": f"Could not save config: {e}"}), 500
    return jsonify({"status": "ok", "notice": notice})


@app.route("/auth/status")
def auth_status():
    """Return current authentication status and OIDC capability flags for UI."""
    enabled = bool(oauth)
    authenticated = enabled and bool(session.get("oidc_authenticated"))
    return jsonify(
        {
            "oidc_enabled": enabled,
            "oidc_authenticated": authenticated,
            "user": session.get("oidc_user") if authenticated else None,
            "groups": session.get("oidc_groups", []) if authenticated else [],
            "require_pin_for_oidc": require_pin_for_oidc,
        }
    )


@app.route("/admin/logs")
def admin_logs():
    """Get parsed log data for admin dashboard"""
    # Check if admin is authenticated
    if not session.get("admin_authenticated"):
        return jsonify({"error": "Authentication required"}), 401

    try:
        logs = []
        log_path = os.path.join(os.path.dirname(__file__), "logs", "log.txt")

        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            # Handle log lines that may have timestamp prefix from logging module
                            json_start = line.find("{")
                            if json_start != -1:
                                json_part = line[json_start:]
                                log_data = json.loads(json_part)
                            else:
                                log_data = json.loads(line)

                            logs.append(
                                {
                                    "timestamp": log_data.get("timestamp"),
                                    "ip": log_data.get("ip"),
                                    "user": log_data.get("user") if log_data.get("user") != "UNKNOWN" else None,
                                    "status": log_data.get("status"),
                                    "details": log_data.get("details"),
                                }
                            )
                        except json.JSONDecodeError:
                            # Fallback for old format logs: timestamp - ip - user - status - details
                            try:
                                if " - " in line and not line.startswith("{"):
                                    parts = line.split(" - ", 4)
                                    if len(parts) >= 4:
                                        timestamp = parts[0]
                                        ip = parts[1]
                                        user = parts[2] if parts[2] != "UNKNOWN" else None
                                        status = parts[3]
                                        details = parts[4] if len(parts) > 4 else None

                                        logs.append(
                                            {
                                                "timestamp": timestamp,
                                                "ip": ip,
                                                "user": user,
                                                "status": status,
                                                "details": details,
                                            }
                                        )
                            except Exception as e:
                                logger.error(f"Error parsing old format log line: {line}, error: {e}")
                                continue
                        except Exception as e:
                            logger.error(f"Error parsing JSON log line: {line}, error: {e}")
                            continue
            except Exception as e:
                logger.error(f"Error reading log file: {e}")
        return jsonify({"logs": logs})
    except Exception as e:
        logger.error(f"Exception in admin_logs: {e}")
        return jsonify({"error": "Failed to load logs"}), 500


@app.route("/admin/logs/clear", methods=["POST"])
def admin_logs_clear():
    """Clear logs: either all, or only remove test-mode entries.

    Body: {"mode": "all" | "test_only"}
    """
    if not session.get("admin_authenticated"):
        return jsonify({"error": "Authentication required"}), 401
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    body = request.get_json(silent=True) or {}
    mode = (body.get("mode") or "all").lower()

    try:
        removed = 0
        kept = 0
        if mode == "all":
            # Truncate file
            try:
                with open(log_path, "w", encoding="utf-8"):
                    pass
            except FileNotFoundError:
                # Nothing to clear
                pass
        elif mode == "test_only":
            # Filter out lines that look like TEST MODE entries
            lines = []
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except FileNotFoundError:
                lines = []

            filtered = []
            for line in lines:
                try:
                    json_start = line.find("{")
                    candidate = line[json_start:] if json_start != -1 else line
                    obj = json.loads(candidate)
                    details = str(obj.get("details", ""))
                    # Remove entries that explicitly contain TEST MODE in details
                    if "TEST MODE" in details:
                        removed += 1
                        continue
                    filtered.append(line)
                except Exception:
                    # If unparsable, keep line
                    filtered.append(line)
            kept = len(filtered)

            # Atomic write
            fd, tmp_path = tempfile.mkstemp(prefix="log.", suffix=".txt", dir=os.path.dirname(log_path) or None)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    tmp.writelines(filtered)
                os.replace(tmp_path, log_path)
            finally:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    logger.exception(f"Failed to remove temporary log file temp_path={tmp_path}")
        else:
            return jsonify({"error": "Invalid mode"}), 400

        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": get_current_time().isoformat(),
                    "ip": get_client_identifier()[0],
                    "user": "ADMIN",
                    "status": "ADMIN_LOGS_CLEAR",
                    "details": f"mode={mode}, removed={removed}, kept={kept}",
                }
            )
        )
        return jsonify({"status": "ok", "mode": mode, "removed": removed, "kept": kept})
    except Exception as e:
        logger.error(f"Exception in admin_logs_clear: {e}")
        return jsonify({"error": "Failed to clear logs"}), 500


# --- Admin: User Management Endpoints ---


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


@app.route("/admin/users", methods=["GET"])
def admin_users_list():
    if not _require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    try:
        # Build combined view: config pins (read-only) + store users (editable)
        store_users = users_store.list_users(include_pins=False).get("users", [])
        store_names = {u["username"] for u in store_users}
        config_only = []
        for name in sorted(user_pins.keys()):
            if name in store_names:
                continue
            config_only.append(
                {
                    "username": name,
                    "active": True,
                    "created_at": None,
                    "updated_at": None,
                    "last_used_at": None,
                    "source": "config",
                    "can_edit": False,
                }
            )
        # Mark store users as editable
        for u in store_users:
            u["source"] = "store"
            u["can_edit"] = True
        return jsonify({"users": store_users + config_only})
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        return jsonify({"error": "Failed to list users"}), 500


@app.route("/admin/users", methods=["POST"])
def admin_users_create():
    if not _require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    try:
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        pin = body.get("pin")
        active = bool(body.get("active", True))
        if not username or not pin:
            return jsonify({"error": "username and pin are required"}), 400
        if username in user_pins:
            return (
                jsonify({"error": "User exists in config and cannot be edited via UI"}),
                409,
            )
        users_store.create_user(username, pin, active)
        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": get_current_time().isoformat(),
                    "ip": get_client_identifier()[0],
                    "user": "ADMIN",
                    "status": "ADMIN_USER_CREATE",
                    "details": f"username={username}",
                }
            )
        )
        return jsonify({"status": "created"}), 201
    except KeyError:
        return jsonify({"error": "User already exists"}), 409
    except ValueError as ve:
        logger.warning(f"ValueError creating user '{username}': {ve}")
        return jsonify({"error": "Invalid input"}), 400
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({"error": "Failed to create user"}), 500


@app.route("/admin/users/<username>", methods=["PUT"])
def admin_users_update(username: str):
    if not _require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    if username in user_pins:
        return jsonify({"error": "Config-defined users cannot be edited via UI"}), 409
    try:
        body = request.get_json(silent=True) or {}
        pin = body.get("pin")
        active = body.get("active")
        users_store.update_user(username, pin=pin, active=active)
        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": get_current_time().isoformat(),
                    "ip": get_client_identifier()[0],
                    "user": "ADMIN",
                    "status": "ADMIN_USER_UPDATE",
                    "details": f"username={username}",
                }
            )
        )
        return jsonify({"status": "updated"}), 200
    except KeyError:
        return jsonify({"error": "User not found"}), 404
    except ValueError as ve:
        logger.warning(f"ValueError updating user '{username}': {ve}")
        return jsonify({"error": "Invalid input"}), 400
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return jsonify({"error": "Failed to update user"}), 500


@app.route("/admin/users/<username>", methods=["DELETE"])
def admin_users_delete(username: str):
    if not _require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    if username in user_pins:
        return jsonify({"error": "Config-defined users cannot be deleted via UI"}), 409
    try:
        users_store.delete_user(username)
        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": get_current_time().isoformat(),
                    "ip": get_client_identifier()[0],
                    "user": "ADMIN",
                    "status": "ADMIN_USER_DELETE",
                    "details": f"username={username}",
                }
            )
        )
        return jsonify({"status": "deleted"}), 200
    except KeyError:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({"error": "Failed to delete user"}), 500


@app.route("/admin/users/<username>/migrate", methods=["POST"])
def admin_users_migrate(username: str):
    """Migrate a user from config.ini [pins] to the JSON user store.

    Optionally accepts {"pin": "new_pin"} to set a new PIN during migration.
    If no PIN provided, uses the existing PIN from config.ini.
    Config entry remains but is ignored when user exists in JSON store.
    """
    if not _require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    # Get existing PIN from config
    existing_pin = user_pins.get(username)
    if not existing_pin:
        return jsonify({"error": "User not found in config"}), 404

    # Parse optional new PIN from request
    body = request.get_json(silent=True) or {}
    new_pin = body.get("pin")
    if new_pin is not None:
        if not isinstance(new_pin, str) or not new_pin.isdigit() or not (4 <= len(new_pin) <= 8):
            return jsonify({"error": "PIN must be 4-8 digits"}), 400
        pin_to_use = new_pin
    else:
        pin_to_use = existing_pin

    # Validate PIN format
    if not isinstance(pin_to_use, str) or not pin_to_use.isdigit() or not (4 <= len(pin_to_use) <= 8):
        return jsonify({"error": "PIN must be 4-8 digits"}), 400

    # Create user in JSON store
    try:
        users_store.create_user(username, pin_to_use, True)

        # Remove from config.ini after successful migration
        try:
            if config.has_option("pins", username):
                config.remove_option("pins", username)
                save_config()
                # Update in-memory user_pins
                user_pins.pop(username, None)
        except Exception as config_err:
            logger.warning(f"Failed to remove {username} from config.ini: {config_err}")

        attempt_logger.info(
            json.dumps(
                {
                    "timestamp": get_current_time().isoformat(),
                    "ip": request.remote_addr or "unknown",
                    "user": "ADMIN",
                    "status": "ADMIN_USER_MIGRATE",
                    "details": f"username={username}",
                }
            )
        )
        return jsonify({"status": "migrated"})
    except Exception as e:
        logger.error(f"Error creating user in store: {e}")
        return jsonify({"error": "Failed to migrate user"}), 500


@app.route("/admin/users/migrate-all", methods=["POST"])
def admin_users_migrate_all():
    """Migrate all config-only users into the JSON store.

    Each user is migrated individually with safe config update and rollback on failure.
    Returns summary of successes and failures.
    """
    if not _require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not _check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    if not user_pins:
        return jsonify({"migrated": 0, "failed": []}), 200

    migrated = 0
    failed = []
    # Copy list of usernames to avoid mutation during loop
    candidates = list(user_pins.keys())

    for username in candidates:
        existing_pin = user_pins.get(username)
        if not isinstance(existing_pin, str):
            failed.append({"username": username, "error": "invalid_pin"})
            continue
        # Validate format
        if not (existing_pin.isdigit() and 4 <= len(existing_pin) <= 8):
            failed.append({"username": username, "error": "invalid_format"})
            continue
        # Skip if user already exists in JSON store
        if users_store.user_exists(username):
            continue

        # Create in JSON store
        try:
            users_store.create_user(username, existing_pin, True)

            # Remove from config.ini after successful migration
            try:
                if config.has_option("pins", username):
                    config.remove_option("pins", username)
                    save_config()
                    # Update in-memory user_pins
                    user_pins.pop(username, None)
            except Exception as config_err:
                logger.warning(f"Failed to remove {username} from config.ini: {config_err}")

            attempt_logger.info(
                json.dumps(
                    {
                        "timestamp": get_current_time().isoformat(),
                        "ip": request.remote_addr or "unknown",
                        "user": "ADMIN",
                        "status": "ADMIN_USER_MIGRATE",
                        "details": f"username={username}",
                    }
                )
            )
            migrated += 1
        except Exception as e:
            # Log full exception details server-side for later troubleshooting
            logger.error(f"Failed to migrate user {username}: {e}", exc_info=True)
            failed.append(
                {
                    "username": username,
                    "error": "store_write_failed",
                    "detail": "internal_error",
                }
            )

    status = 200 if not failed else 207  # multi-status semantics
    return jsonify({"migrated": migrated, "failed": failed}), status


@app.route("/oidc/logout")
def oidc_logout():
    """Logout from OIDC and clear session"""
    if oauth:
        try:
            # Clear the local session
            session.clear()

            # Fetch the .well-known configuration
            well_known_url = f"{oidc_issuer}/.well-known/openid-configuration"
            response = requests.get(well_known_url, timeout=10)
            if response.status_code == 200:
                config = response.json()
                logout_url = config.get("end_session_endpoint")
                if logout_url:
                    # Redirect to the OIDC provider's logout endpoint
                    return redirect(f"{logout_url}?redirect_uri={url_for('index', _external=True)}")
                else:
                    logger.error("Logout URL not found in .well-known configuration")
                    return (
                        jsonify({"status": "error", "message": "Logout URL not found"}),
                        500,
                    )
            else:
                logger.error(f"Failed to fetch .well-known configuration: {response.status_code}")
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Failed to fetch OIDC configuration",
                        }
                    ),
                    500,
                )
        except Exception as e:
            logger.error(f"Error during OIDC logout: {e}")
            return jsonify({"status": "error", "message": "Failed to logout"}), 500
    else:
        # If OIDC is not enabled, just clear the session
        session.clear()
        return redirect(url_for("index"))


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",  # nosec B104 - intentional; server is designed to listen on all interfaces
        port=server_port,
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
