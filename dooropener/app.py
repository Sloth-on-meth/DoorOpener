#!/usr/bin/env python3
"""
DoorOpener Web Portal v2.0
---------------------------
Secure Flask web app to open a door via Home Assistant API with visual
keypad interface and comprehensive brute-force protection.
"""

import gzip
import hmac
import json
import logging
import os
from datetime import timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler

import secrets
from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_from_directory,
    session,
)
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from ha_client import HAClient
from security import (
    RateLimiter,
    add_security_headers,
    get_client_identifier,
    is_request_suspicious,
    validate_pin_input,
)
from config import get_current_time
from users_store import UsersStore

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_dir = os.environ.get("DOOROPENER_LOG_DIR") or os.path.join(
    os.path.dirname(__file__), "logs"
)
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception as e:
    logging.getLogger("dooropener").error("Could not create log directory: %s", e)

log_path = os.path.join(log_dir, "log.txt")

attempt_logger = logging.getLogger("door_attempts")
attempt_logger.setLevel(logging.INFO)
_file_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5)
_file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
attempt_logger.handlers = [_file_handler]

logger = logging.getLogger("dooropener")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _sh = logging.StreamHandler()
    _sh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(_sh)

# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

if config.secret_key:
    app.secret_key = config.secret_key
else:
    app.secret_key = secrets.token_hex(32)

app.config["RANDOM_SECRET_WARNING"] = config.random_secret_warning
if config.random_secret_warning:
    logger.warning(
        "FLASK_SECRET_KEY not set and no secret_key in options; "
        "sessions may become invalid across restarts or workers."
    )

app.config.update(
    SESSION_COOKIE_SECURE=config.session_cookie_secure,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

# ---------------------------------------------------------------------------
# Shared objects
# ---------------------------------------------------------------------------
rate_limiter = RateLimiter()
ha_client = HAClient()

USERS_STORE_PATH = os.environ.get(
    "USERS_STORE_PATH", os.path.join(os.path.dirname(__file__), "users.json")
)
users_store = UsersStore(USERS_STORE_PATH)


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------
def _audit(ip, sid, user, status, details):
    attempt_logger.info(
        json.dumps(
            {
                "timestamp": get_current_time().isoformat(),
                "ip": ip,
                "session": sid[:8] if sid else "unknown",
                "user": user,
                "status": status,
                "details": details,
            }
        )
    )


def _touch(username):
    try:
        users_store.touch_user(username)
    except Exception:  # nosec B110
        pass


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.after_request
def after_request(response):
    response = add_security_headers(response)
    # Gzip compression for text responses > 512 bytes
    if (
        response.status_code == 200
        and "gzip" in request.headers.get("Accept-Encoding", "")
        and response.content_type
        and any(t in response.content_type for t in ("text/", "application/json", "javascript"))
        and response.content_length
        and response.content_length > 512
    ):
        data = response.get_data()
        compressed = gzip.compress(data, compresslevel=6)
        if len(compressed) < len(data):
            response.set_data(compressed)
            response.headers["Content-Encoding"] = "gzip"
            response.headers["Content-Length"] = len(compressed)
            response.headers["Vary"] = "Accept-Encoding"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/service-worker.js")
def service_worker():
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
    try:
        return send_from_directory(
            os.path.join(app.root_path, "static"),
            "manifest.webmanifest",
            mimetype="application/manifest+json",
        )
    except Exception:
        abort(404)


# ---------------------------------------------------------------------------
# Battery (rate-limited: max 1 request per 10s per client)
# ---------------------------------------------------------------------------
_battery_request_ts: dict[str, float] = {}

@app.route("/battery")
def battery():
    import time as _time
    client_ip = request.remote_addr
    now = _time.monotonic()
    last = _battery_request_ts.get(client_ip, 0.0)
    if now - last < 10:
        level = ha_client.get_battery_level()  # cheap — returns from cache
        return jsonify({"level": level})
    _battery_request_ts[client_ip] = now
    level = ha_client.get_battery_level()
    return jsonify({"level": level})


# ---------------------------------------------------------------------------
# Open door
# ---------------------------------------------------------------------------
@app.route("/open-door", methods=["POST"])
def open_door():
    try:
        primary_ip, session_id, identifier = get_client_identifier()

        # Suspicious request check
        if is_request_suspicious():
            _audit(primary_ip, session_id, "UNKNOWN", "SUSPICIOUS",
                   "Suspicious request detected")
            return jsonify({"status": "error", "message": "Request blocked"}), 403

        # Global rate limit
        if not rate_limiter.check_global_rate_limit():
            _audit(primary_ip, session_id, "UNKNOWN", "GLOBAL_BLOCKED",
                   "Global rate limit exceeded")
            return jsonify({"status": "error",
                            "message": "Service temporarily unavailable"}), 429

        # Block checks (persistent cookie + in-memory)
        blocked, remaining = rate_limiter.is_blocked(identifier, session_id)
        if blocked:
            ts = rate_limiter.blocked_until_ts(identifier, session_id)
            _audit(primary_ip, session_id, "UNKNOWN", "BLOCKED",
                   f"Blocked for {int(remaining)}s")
            return jsonify({
                "status": "error",
                "message": "Too many failed attempts. Please try again later.",
                "blocked_until": ts,
            }), 429

        # Parse request
        data = request.get_json(force=True, silent=True)
        if not data or "pin" not in data:
            logger.warning("No PIN provided in request body")
            return jsonify({"status": "error", "message": "PIN required"}), 400

        pin_valid, validated_pin = validate_pin_input(data.get("pin"))
        if not pin_valid:
            rate_limiter.record_failure(identifier, session_id)
            _audit(primary_ip, session_id, "UNKNOWN", "INVALID_FORMAT",
                   "Invalid PIN format")
            return jsonify({"status": "error", "message": "Invalid PIN format"}), 400

        # Match PIN (O(1) via cached reverse map)
        matched_user = users_store.lookup_pin(validated_pin)

        if not matched_user:
            reason_key, remaining_attempts = rate_limiter.record_failure(
                identifier, session_id
            )
            if reason_key == "session_blocked":
                msg = f"Invalid PIN. Session blocked for {int(config.BLOCK_TIME.total_seconds()//60)} minutes"
            elif reason_key == "ip_blocked":
                msg = f"Invalid PIN. Access blocked for {int(config.BLOCK_TIME.total_seconds()//60)} minutes"
            else:
                msg = f"Invalid PIN. {remaining_attempts} attempts remaining"

            _audit(primary_ip, session_id, "UNKNOWN", "AUTH_FAILURE", msg)
            resp: dict = {"status": "error", "message": msg}
            ts = rate_limiter.blocked_until_ts(identifier, session_id)
            if ts:
                resp["blocked_until"] = ts
            return jsonify(resp), 401

        # Correct PIN - but enforce active block even on correct PIN
        blocked, remaining = rate_limiter.is_blocked(identifier, session_id)
        if blocked:
            ts = rate_limiter.blocked_until_ts(identifier, session_id)
            _audit(primary_ip, session_id, matched_user, "BLOCK_ENFORCED",
                   f"Access blocked for {int(remaining)}s")
            return jsonify({
                "status": "error",
                "message": "Too many failed attempts. Please try again later.",
                "blocked_until": ts,
            }), 429

        # Success - reset counters
        rate_limiter.record_success(identifier, session_id)
        display_name = matched_user.capitalize() if isinstance(matched_user, str) else "User"

        if config.test_mode:
            _audit(primary_ip, session_id, matched_user, "SUCCESS",
                   "Door opened (TEST MODE)")
            _touch(matched_user)
            return jsonify({
                "status": "success",
                "message": f"Door open command sent (TEST MODE).\nWelcome home, {display_name}!",
            })

        # Production - trigger HA entity
        result = ha_client.trigger_entity()
        if result["success"]:
            _audit(primary_ip, session_id, matched_user, "SUCCESS", "Door opened")
            _touch(matched_user)
            return jsonify({
                "status": "success",
                "message": f"Door open command sent.\nWelcome home, {display_name}!",
            })
        else:
            _audit(primary_ip, session_id, matched_user, "FAILURE",
                   result.get("error", "HA error"))
            return jsonify({"status": "error",
                            "message": result["error"]}), result["status_code"]

    except Exception as e:
        try:
            _ip, _sid, _ = get_client_identifier()
        except Exception:
            _ip, _sid = request.remote_addr, "unknown"
        _audit(_ip, _sid, "UNKNOWN", "EXCEPTION", f"Exception in open_door: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@app.route("/admin")
def admin():
    return render_template("admin.html")


@app.route("/admin/auth", methods=["POST"])
def admin_auth():
    data = request.get_json()
    password = data.get("password", "").strip() if data else ""
    remember_me = data.get("remember_me", False) if data else False
    primary_ip, session_id, identifier = get_client_identifier()
    now = get_current_time()

    if (
        rate_limiter.session_blocked_until.get(session_id)
        and now < rate_limiter.session_blocked_until.get(session_id)
    ):
        remaining = (rate_limiter.session_blocked_until[session_id] - now).total_seconds()
        _audit(primary_ip, session_id, "ADMIN", "ADMIN_SESSION_BLOCKED",
               f"Admin auth blocked for {int(remaining)}s")
        return jsonify({"status": "error",
                        "message": "Too many failed attempts. Please try later."}), 429

    if hmac.compare_digest(password, config.admin_password):
        rate_limiter.session_failed.pop(session_id, None)
        rate_limiter.session_blocked_until.pop(session_id, None)
        session["admin_authenticated"] = True
        session["admin_login_time"] = now.isoformat()
        if remember_me:
            session.permanent = True
        else:
            session.permanent = False
        _audit(primary_ip, session_id, "ADMIN", "ADMIN_SUCCESS", "Admin login")
        return jsonify({"status": "success"})

    # Failure
    rate_limiter.session_failed[session_id] = rate_limiter.session_failed.get(session_id, 0) + 1
    if rate_limiter.session_failed[session_id] >= config.SESSION_MAX_ATTEMPTS:
        rate_limiter.session_blocked_until[session_id] = now + config.BLOCK_TIME
        details = (f"Invalid admin password. Session blocked for "
                    f"{int(config.BLOCK_TIME.total_seconds()//60)} minutes")
    else:
        remaining = config.SESSION_MAX_ATTEMPTS - rate_limiter.session_failed[session_id]
        details = f"Invalid admin password. {remaining} attempts remaining"
    _audit(primary_ip, session_id, "ADMIN", "ADMIN_FAILURE", details)
    return jsonify({"status": "error", "message": "Invalid admin password"}), 403


@app.route("/admin/check-auth", methods=["GET"])
def admin_check_auth():
    if session.get("admin_authenticated"):
        return jsonify({"authenticated": True,
                        "login_time": session.get("admin_login_time")})
    return jsonify({"authenticated": False})


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_authenticated", None)
    session.pop("admin_login_time", None)
    session.permanent = False
    return jsonify({"status": "success", "message": "Logged out successfully"})


# ---------------------------------------------------------------------------
# Admin auth decorator
# ---------------------------------------------------------------------------
def require_admin(f):
    """Decorator that returns 401 unless the session is admin-authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------
@app.route("/admin/logs")
@require_admin
def admin_logs():
    try:
        logs = _parse_log_file()
        return jsonify({"logs": logs})
    except Exception as e:
        logger.error("Exception in admin_logs: %s", e)
        return jsonify({"error": "Failed to load logs"}), 500


def _parse_log_file(max_entries: int = 500):
    """Parse the log file, returning at most *max_entries* most recent entries."""
    logs = []
    path = os.path.join(log_dir, "log.txt")
    if not os.path.exists(path):
        return logs

    # Read only the tail of the file to avoid loading megabytes into memory
    try:
        size = os.path.getsize(path)
    except OSError:
        return logs

    # Estimate ~200 bytes per line; read enough for max_entries + margin
    read_bytes = min(size, max_entries * 250)
    with open(path, "rb") as f:
        if read_bytes < size:
            f.seek(size - read_bytes)
            f.readline()  # skip partial first line
        lines = f.read().decode("utf-8", errors="replace").splitlines()

    for line in lines:
        try:
            json_start = line.find("{")
            if json_start != -1:
                obj = json.loads(line[json_start:])
            else:
                obj = json.loads(line)
            logs.append({
                "timestamp": obj.get("timestamp"),
                "ip": obj.get("ip"),
                "user": obj.get("user") if obj.get("user") != "UNKNOWN" else None,
                "status": obj.get("status"),
                "details": obj.get("details"),
            })
        except json.JSONDecodeError:
            if " - " in line and not line.startswith("{"):
                parts = line.split(" - ", 4)
                if len(parts) >= 4:
                    logs.append({
                        "timestamp": parts[0],
                        "ip": parts[1],
                        "user": parts[2] if parts[2] != "UNKNOWN" else None,
                        "status": parts[3],
                        "details": parts[4] if len(parts) > 4 else None,
                    })
        except Exception:  # nosec B112
            continue
    return logs[-max_entries:]


@app.route("/admin/logs/clear", methods=["POST"])
@require_admin
def admin_logs_clear():

    body = request.get_json(silent=True) or {}
    mode = (body.get("mode") or "all").lower()

    try:
        removed = 0
        kept = 0
        if mode == "all":
            try:
                with open(log_path, "w", encoding="utf-8"):
                    pass
            except FileNotFoundError:
                pass
        elif mode == "test_only":
            import tempfile as _tf

            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except FileNotFoundError:
                lines = []

            filtered = []
            for line in lines:
                try:
                    js = line.find("{")
                    obj = json.loads(line[js:] if js != -1 else line)
                    if "TEST MODE" in str(obj.get("details", "")):
                        removed += 1
                        continue
                except Exception:  # nosec B110
                    pass
                filtered.append(line)
            kept = len(filtered)

            fd, tmp = _tf.mkstemp(prefix="log.", suffix=".txt",
                                   dir=os.path.dirname(log_path) or None)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as t:
                    t.writelines(filtered)
                os.replace(tmp, log_path)
            finally:
                try:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                except Exception:  # nosec B110
                    pass
        else:
            return jsonify({"error": "Invalid mode"}), 400

        ip, sid, _ = get_client_identifier()
        _audit(ip, sid,
               "ADMIN", "ADMIN_LOGS_CLEAR",
               f"mode={mode}, removed={removed}, kept={kept}")
        return jsonify({"status": "ok", "mode": mode,
                        "removed": removed, "kept": kept})
    except Exception as e:
        logger.error("Exception in admin_logs_clear: %s", e)
        return jsonify({"error": "Failed to clear logs"}), 500


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------
@app.route("/admin/users", methods=["GET"])
@require_admin
def admin_users_list():
    try:
        store_users = users_store.list_users(include_pins=False).get("users", [])
        for u in store_users:
            u["can_edit"] = True
        return jsonify({"users": store_users})
    except Exception as e:
        logger.error("Error listing users: %s", e)
        return jsonify({"error": "Failed to list users"}), 500


@app.route("/admin/users", methods=["POST"])
@require_admin
def admin_users_create():
    try:
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        pin = body.get("pin")
        active = bool(body.get("active", True))
        if not username or not pin:
            return jsonify({"error": "username and pin are required"}), 400
        users_store.create_user(username, pin, active)
        ip, sid, _ = get_client_identifier()
        _audit(ip, sid, "ADMIN", "ADMIN_USER_CREATE", f"username={username}")
        return jsonify({"status": "created"}), 201
    except KeyError:
        return jsonify({"error": "User already exists"}), 409
    except ValueError as ve:
        logger.warning("ValueError creating user '%s': %s", username, ve)
        return jsonify({"error": "Invalid input"}), 400
    except Exception as e:
        logger.error("Error creating user: %s", e)
        return jsonify({"error": "Failed to create user"}), 500


@app.route("/admin/users/<username>", methods=["PUT"])
@require_admin
def admin_users_update(username: str):
    try:
        body = request.get_json(silent=True) or {}
        users_store.update_user(username, pin=body.get("pin"), active=body.get("active"))
        ip, sid, _ = get_client_identifier()
        _audit(ip, sid, "ADMIN", "ADMIN_USER_UPDATE", f"username={username}")
        return jsonify({"status": "updated"}), 200
    except KeyError:
        return jsonify({"error": "User not found"}), 404
    except ValueError as ve:
        logger.warning("ValueError updating user '%s': %s", username, ve)
        return jsonify({"error": "Invalid input"}), 400
    except Exception as e:
        logger.error("Error updating user: %s", e)
        return jsonify({"error": "Failed to update user"}), 500


@app.route("/admin/users/<username>", methods=["DELETE"])
@require_admin
def admin_users_delete(username: str):
    try:
        users_store.delete_user(username)
        ip, sid, _ = get_client_identifier()
        _audit(ip, sid, "ADMIN", "ADMIN_USER_DELETE", f"username={username}")
        return jsonify({"status": "deleted"}), 200
    except KeyError:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logger.error("Error deleting user: %s", e)
        return jsonify({"error": "Failed to delete user"}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",  # nosec B104
        port=config.server_port,
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
