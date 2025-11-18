#!/usr/bin/env python3
"""
DoorOpener Web Portal v2.0
---------------------------
A secure Flask web app to open a door via Home Assistant API, with visual keypad interface,
enhanced multi-layer security, timezone support, and comprehensive brute force protection.
"""
import os
import json
import time
import logging
from logging.handlers import RotatingFileHandler
import requests
import secrets
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    abort,
    redirect,
    url_for,
    send_from_directory,
)
from users_store import UsersStore
from werkzeug.middleware.proxy_fix import ProxyFix
import pytz

try:
    from authlib.integrations.flask_client import OAuth
    from authlib.jose import jwt
except Exception:
    OAuth = None

# --- Timezone Setup ---
# Get timezone from environment variable, default to UTC
TZ = os.environ.get("TZ", "UTC")
try:
    TIMEZONE = pytz.timezone(TZ)
    print(f"Using timezone: {TZ}")
except pytz.exceptions.UnknownTimeZoneError:
    print(f"Unknown timezone '{TZ}', falling back to UTC")
    TIMEZONE = pytz.UTC
    TZ = "UTC"


def get_current_time():
    """Get current time in the configured timezone"""
    return datetime.now(TIMEZONE)


# --- Logging Setup ---
# Use a dedicated logs directory and rotate logs to avoid unbounded growth.
# Allow overriding via DOOROPENER_LOG_DIR for tests or special deployments.
log_dir = os.environ.get("DOOROPENER_LOG_DIR") or os.path.join(
    os.path.dirname(__file__), "logs"
)
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
# Prefer fixed secret from environment; fallback to temporary random (will be overridden by options.json later if present)
_env_secret = os.environ.get("FLASK_SECRET_KEY")
if _env_secret:
    app.secret_key = _env_secret
    app.config["RANDOM_SECRET_WARNING"] = False
else:
    app.secret_key = secrets.token_hex(32)
    app.config["RANDOM_SECRET_WARNING"] = True

# Configure session cookies (will be overridden from options.json below if present)
_env_secure = os.environ.get("SESSION_COOKIE_SECURE")
_secure_cookie = (_env_secure.lower() == "true") if _env_secure is not None else False
app.config.update(
    SESSION_COOKIE_SECURE=_secure_cookie,     # default False on HTTP; True only if explicitly set
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

OPTIONS_PATH = os.path.join(os.path.dirname(__file__), "options.json")
try:
    with open(OPTIONS_PATH, "r", encoding="utf-8") as _f:
        _opts = json.load(_f)
except FileNotFoundError as _e:
    raise RuntimeError(f"Add-on options not found: {OPTIONS_PATH}. Is this running under HA Supervisor?") from _e

ha_url         = (_opts.get("ha_url") or "").rstrip("/")
ha_token       = (_opts.get("ha_token") or "").strip()
entity_id      = (_opts.get("entity_id") or "").strip()
battery_entity = (_opts.get("battery_entity") or f"sensor.{entity_id.split('.')[1]}_battery").strip()

server_port                  = int(os.environ.get("DOOROPENER_PORT", _opts.get("port", 6532)))
tz_name                      = _opts.get("tz", "UTC")
test_mode                    = bool(_opts.get("test_mode", False))
admin_password               = (_opts.get("admin_password") or "4384339380437neghrjlkmfef").strip()
MAX_ATTEMPTS                 = int(_opts.get("max_attempts", 5))
BLOCK_TIME                   = int(_opts.get("block_time_minutes", 5))
MAX_GLOBAL_ATTEMPTS_PER_HOUR = int(_opts.get("max_global_attempts_per_hour", 50))
SESSION_MAX_ATTEMPTS         = int(_opts.get("session_max_attempts", 3))

# OIDC Configuration
oidc_enabled         = bool(_opts.get("oidc_enabled", False))
oidc_issuer          = _opts.get("oidc_issuer", None)
oidc_client_id       = _opts.get("oidc_client_id", None)
oidc_client_secret   = _opts.get("oidc_client_secret", None)
oidc_redirect_uri    = _opts.get("oidc_redirect_uri", None)
oidc_admin_group     = _opts.get("oidc_admin_group", "")
oidc_user_group      = _opts.get("oidc_user_group", "")
require_pin_for_oidc = bool(_opts.get("oidc_require_pin", False))

# If no env secret key was provided, allow overriding the temporary random with options.json
if not _env_secret:
    try:
        _cfg_secret = (_opts.get("secret_key") or "").strip()
        if _cfg_secret:
            app.secret_key = _cfg_secret
            app.config["RANDOM_SECRET_WARNING"] = False
        elif app.config.get("RANDOM_SECRET_WARNING"):
            logging.getLogger("dooropener").warning(
                "FLASK_SECRET_KEY not set and no secret_key provided in options; "
                "sessions may become invalid across restarts or multiple workers."
            )
    except Exception:
        pass

# Override cookie “secure” flag from options.json if provided
try:
    _cfg_secure = bool(_opts.get("session_cookie_secure", False))
except Exception:
    _cfg_secure = None
if _cfg_secure is not None:
    app.config["SESSION_COOKIE_SECURE"] = _cfg_secure
    logging.getLogger("dooropener").info(
        "SESSION_COOKIE_SECURE set from options.json: %s", _cfg_secure
    )
app.config.setdefault("SESSION_COOKIE_PATH", "/")

# Per-user PINs from [pins] section (baseline, read-only)
user_pins = {}

# JSON-backed users store (overrides and new users). Path can be overridden in tests via env.
USERS_STORE_PATH = os.environ.get(
    "USERS_STORE_PATH", os.path.join(os.path.dirname(__file__), "users.json")
)
users_store = UsersStore(USERS_STORE_PATH)


def get_effective_user_pins() -> dict:
    try:
        return users_store.effective_pins(user_pins)
    except Exception:
        return dict(user_pins)

oauth = None
if (
    oidc_enabled
    and OAuth is not None
    and all([oidc_issuer, oidc_client_id, oidc_client_secret, oidc_redirect_uri])
):
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


# Optional custom CA bundle (PEM) to trust self-signed HA certificates
ha_ca_bundle = (_opts.get("ca_bundle") or os.getenv("REQUESTS_CA_BUNDLE", "")).strip()

# === END MIGRATION ===
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

# Use a single requests.Session for all HA calls and make it trust the configured CA bundle.
# ha_ca_bundle is already read from [HomeAssistant].ca_bundle above.
ha_session = requests.Session()
ha_session.verify = ha_ca_bundle if ha_ca_bundle else True
ha_session.headers.update(ha_headers)

# --- Enhanced Security & Rate Limiting ---
ip_failed_attempts = defaultdict(int)
ip_blocked_until = defaultdict(lambda: None)
session_failed_attempts = defaultdict(int)
session_blocked_until = defaultdict(lambda: None)
global_failed_attempts = 0
global_last_reset = get_current_time()


# Configure main logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(
            os.path.join(log_dir, "door_access.log"), maxBytes=1_000_000, backupCount=3
        ),
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
        "magnetometer=(), gyroscope=(), fullscreen=(self)"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    # Strict CSP for simple app: allow only same-origin resources, inline styles/scripts as used by templates,
    # and local API calls. Disallow base-uri/object/embed; prevent framing.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )

    # Prevent caching of dynamic/admin JSON endpoints to avoid stale auth state
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def get_delay_seconds(attempt_count):
    """Calculate progressive delay: 1s, 2s, 4s, 8s, 16s"""
    return min(2 ** (attempt_count - 1), 16) if attempt_count > 0 else 0


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

    # Check for rapid requests (basic timing check)
    if not hasattr(request, "start_time"):
        request.start_time = get_current_time()

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


@app.after_request
def after_request(response):
    return add_security_headers(response)


@app.route("/")
def index():
    return render_template(
        "index.html",
        oidc_enabled=bool(oauth),
        require_pin_for_oidc=require_pin_for_oidc,
    )


@app.route("/battery")
def battery():
    """Get battery level from Home Assistant battery sensor entity"""
    try:
        logger.info(
            f"Battery endpoint called - fetching state for entity: {battery_entity}"
        )
        url = f"{ha_url}/api/states/{battery_entity}"
        response = ha_session.get(url, timeout=10)
        
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
            logger.error(
                f"Failed to fetch battery state: {response.status_code} {response.text}"
            )
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
                jsonify(
                    {"status": "error", "message": "Service temporarily unavailable"}
                ),
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
        if (
            session_blocked_until[session_id]
            and now < session_blocked_until[session_id]
        ):
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
        if oidc_auth and (not oidc_exp or oidc_exp < time.time()):
            # OIDC session has expired, clear all relevant session data
            session.pop("oidc_authenticated", None)
            session.pop("oidc_user", None)
            session.pop("oidc_groups", None)
            session.pop("oidc_exp", None)
            oidc_auth = False  # Reset flag for the rest of the function
            logger.warning(
                f"OIDC session for IP {primary_ip} has expired. Re-authentication required."
            )
            # Optional: Could return an error directly, but we let it fall through to the PIN check

        oidc_groups = session.get("oidc_groups", [])
        oidc_user = session.get("oidc_user")
        oidc_user_allowed = (not oidc_user_group) or (oidc_user_group in oidc_groups)

        data = request.get_json(force=True, silent=True)
        pin_from_request = data.get("pin") if data else None

        # If no PIN provided but OIDC user is authenticated and allowed, proceed without PIN
        if (
            (not pin_from_request)
            and oidc_auth
            and oidc_user_allowed
            and not require_pin_for_oidc
        ):
            # Re-check block state right before granting access
            if (
                session_blocked_until[session_id]
                and now < session_blocked_until[session_id]
            ) or (ip_blocked_until[identifier] and now < ip_blocked_until[identifier]):
                remaining = 0
                if (
                    session_blocked_until[session_id]
                    and now < session_blocked_until[session_id]
                ):
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
                if (
                    session_blocked_until[session_id]
                    and now < session_blocked_until[session_id]
                ):
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
            if not (
                session_blocked_until[session_id]
                and now < session_blocked_until[session_id]
            ) and not (
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
                display_name = (
                    matched_user.capitalize()
                    if isinstance(matched_user, str)
                    else "User"
                )
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
                response = ha_session.post(url, json=payload, timeout=10)
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
                        pass
                    display_name = (
                        matched_user.capitalize()
                        if isinstance(matched_user, str)
                        else "User"
                    )
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
                import traceback

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
            if pin_from_request == user_pin:
                matched_user = user
                break

        if matched_user:
            # Enforce any active block even on correct PIN before proceeding
            if (
                session_blocked_until[session_id]
                and now < session_blocked_until[session_id]
            ) or (ip_blocked_until[identifier] and now < ip_blocked_until[identifier]):
                remaining = 0
                if (
                    session_blocked_until[session_id]
                    and now < session_blocked_until[session_id]
                ):
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
                if (
                    session_blocked_until[session_id]
                    and now < session_blocked_until[session_id]
                ):
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
                    pass
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
                response = ha_session.post(url, json=payload, timeout=10)

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
                        pass
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
                import traceback

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
            # Failed authentication - increment all counters
            ip_failed_attempts[identifier] += 1
            session_failed_attempts[session_id] += 1
            global_failed_attempts += 1

            # Check session-based blocking first (harder to bypass)
            if session_failed_attempts[session_id] >= SESSION_MAX_ATTEMPTS:
                session_blocked_until[session_id] = now + BLOCK_TIME
                # Also persist in signed session cookie so block applies across workers
                session["blocked_until_ts"] = (
                    get_current_time() + BLOCK_TIME
                ).timestamp()
                reason = f"Invalid PIN. Session blocked for {int(BLOCK_TIME.total_seconds()//60)} minutes"
            elif ip_failed_attempts[identifier] >= MAX_ATTEMPTS:
                ip_blocked_until[identifier] = now + BLOCK_TIME
                reason = f"Invalid PIN. Access blocked for {int(BLOCK_TIME.total_seconds()//60)} minutes"
            else:
                # Apply progressive delay based on session attempts (more secure)
                delay = get_delay_seconds(session_failed_attempts[session_id])
                if delay > 0:
                    time.sleep(delay)
                remaining_attempts = min(
                    SESSION_MAX_ATTEMPTS - session_failed_attempts[session_id],
                    MAX_ATTEMPTS - ip_failed_attempts[identifier],
                )
                reason = f"Invalid PIN. {remaining_attempts} attempts remaining"

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
            if (
                session_blocked_until[session_id]
                and now < session_blocked_until[session_id]
            ):
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
    return render_template("admin.html", oidc_enabled=bool(oauth))


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
        public_key = _opts.get("oidc+public_key", None)
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
        user = (
            claims.get("email")
            or claims.get("preferred_username")
            or claims.get("name")
            or "oidc-user"
        )
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
    if (
        session_blocked_until.get(session_id)
        and now < session_blocked_until[session_id]
    ):
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

    if password == admin_password:
        # Success: clear counters for this session
        session_failed_attempts[session_id] = 0
        if session_id in session_blocked_until:
            del session_blocked_until[session_id]

        session["admin_authenticated"] = True
        session["admin_login_time"] = now.isoformat()

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
        # Failure: increment counters and apply progressive delay
        session_failed_attempts[session_id] += 1
        delay = get_delay_seconds(session_failed_attempts[session_id])
        if delay > 0:
            time.sleep(delay)

        # Block session after SESSION_MAX_ATTEMPTS failures
        if session_failed_attempts[session_id] >= SESSION_MAX_ATTEMPTS:
            session_blocked_until[session_id] = now + BLOCK_TIME
            details = f"Invalid admin password. Session blocked for {int(BLOCK_TIME.total_seconds()//60)} minutes"
        else:
            remaining = SESSION_MAX_ATTEMPTS - session_failed_attempts[session_id]
            details = f"Invalid admin password. {remaining} attempts remaining"

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
        return jsonify({"authenticated": True, "login_time": login_time})
    else:
        return jsonify({"authenticated": False})


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    """Logout admin user"""
    session.pop("admin_authenticated", None)
    session.pop("admin_login_time", None)
    session.permanent = False
    return jsonify({"status": "success", "message": "Logged out successfully"})


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
                with open(log_path, "r") as f:
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
                                    "user": log_data.get("user")
                                    if log_data.get("user") != "UNKNOWN"
                                    else None,
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
                                        user = (
                                            parts[2] if parts[2] != "UNKNOWN" else None
                                        )
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
                                logger.error(
                                    f"Error parsing old format log line: {line}, error: {e}"
                                )
                                continue
                        except Exception as e:
                            logger.error(
                                f"Error parsing JSON log line: {line}, error: {e}"
                            )
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
    # Check if admin is authenticated
    if not session.get("admin_authenticated"):
        return jsonify({"error": "Authentication required"}), 401

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
            import tempfile

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
            fd, tmp_path = tempfile.mkstemp(
                prefix="log.", suffix=".txt", dir=os.path.dirname(log_path) or None
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    tmp.writelines(filtered)
                os.replace(tmp_path, log_path)
            finally:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
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
                logout_url = _opts.get("oidc_end_session_endpoint")
                if logout_url:
                    # Redirect to the OIDC provider's logout endpoint
                    return redirect(
                        f"{logout_url}?redirect_uri={url_for('index', _external=True)}"
                    )
                else:
                    logger.error("Logout URL not found in .well-known configuration")
                    return (
                        jsonify({"status": "error", "message": "Logout URL not found"}),
                        500,
                    )
            else:
                logger.error(
                    f"Failed to fetch .well-known configuration: {response.status_code}"
                )
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


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=server_port,
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
