"""Admin dashboard routes: auth, notice, test-mode, background, logs, user management."""

import hmac
import json
import os
import secrets
import shutil
import tempfile
from datetime import timedelta

import filetype
from flask import Blueprint, g, jsonify, render_template, request, session

import app as core

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
def admin():
    is_authenticated = bool(session.get("admin_authenticated"))
    return render_template(
        "admin.html",
        oidc_enabled=bool(core.oauth),
        app_version=core.APP_VERSION,
        csp_nonce=g.csp_nonce,
        is_authenticated=is_authenticated,
        test_mode=core.test_mode,
    )


@admin_bp.route("/admin/auth", methods=["POST"])
def admin_auth():
    """Authenticate admin password with progressive delays and temporary blocking.
    Uses the same session-based counters as open_door to slow brute force attempts.
    """
    data = request.get_json()
    password = data.get("password", "").strip() if data else ""
    remember_me = data.get("remember_me", False) if data else False

    # Identify client/session for throttling
    primary_ip, session_id, identifier = core.get_client_identifier()

    # Check if this session is currently blocked
    now = core.get_current_time()
    if core.session_blocked_until.get(session_id) and now < core.session_blocked_until[session_id]:
        remaining = (core.session_blocked_until[session_id] - now).total_seconds()
        core.attempt_logger.info(
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

    # Check if this IP is currently blocked (catches multi-session brute force)
    if core.ip_blocked_until.get(primary_ip) and now < core.ip_blocked_until[primary_ip]:
        remaining = (core.ip_blocked_until[primary_ip] - now).total_seconds()
        core.attempt_logger.info(
            json.dumps(
                {
                    "timestamp": now.isoformat(),
                    "ip": primary_ip,
                    "session": session_id[:8],
                    "user": "ADMIN",
                    "status": "ADMIN_IP_BLOCKED",
                    "details": f"Admin auth IP-blocked for {int(remaining)}s",
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

    if hmac.compare_digest(password, core.admin_password):
        # Success: clear counters for this session and IP
        core.session_failed_attempts[session_id] = 0
        if session_id in core.session_blocked_until:
            del core.session_blocked_until[session_id]
        core.ip_failed_attempts[primary_ip] = 0
        if primary_ip in core.ip_blocked_until:
            del core.ip_blocked_until[primary_ip]

        session["admin_authenticated"] = True
        session["admin_login_time"] = now.isoformat()
        session["admin_csrf_token"] = secrets.token_hex(32)

        # Set session to be permanent if remember_me is checked
        if remember_me:
            session.permanent = True
            # Set cookie to expire in 30 days
            core.app.permanent_session_lifetime = timedelta(days=30)
        else:
            session.permanent = False
            # Session expires when browser closes

        core.attempt_logger.info(
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
        # Failure: increment session and IP counters
        core.session_failed_attempts[session_id] += 1
        core.ip_failed_attempts[primary_ip] += 1

        # Block session after SESSION_MAX_ATTEMPTS failures
        block_minutes = int(core.BLOCK_TIME.total_seconds() // 60)
        if core.session_failed_attempts[session_id] >= core.SESSION_MAX_ATTEMPTS:
            core.session_blocked_until[session_id] = now + core.BLOCK_TIME
            details = f"Invalid admin password. Session blocked for {block_minutes} minutes"
        elif core.ip_failed_attempts[primary_ip] >= core.SESSION_MAX_ATTEMPTS:
            core.ip_blocked_until[primary_ip] = now + core.BLOCK_TIME
            details = f"Invalid admin password. IP blocked for {block_minutes} minutes"
        else:
            details = "Invalid admin password"

        core.attempt_logger.info(
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


@admin_bp.route("/admin/check-auth", methods=["GET"])
def admin_check_auth():
    """Check if admin is currently authenticated"""
    if session.get("admin_authenticated"):
        login_time = session.get("admin_login_time")
        csrf_token = session.get("admin_csrf_token")
        return jsonify({"authenticated": True, "login_time": login_time, "csrf_token": csrf_token})
    else:
        return jsonify({"authenticated": False})


@admin_bp.route("/admin/logout", methods=["POST"])
def admin_logout():
    """Logout admin user"""
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    session.pop("admin_authenticated", None)
    session.pop("admin_login_time", None)
    session.pop("admin_csrf_token", None)
    session.permanent = False
    return jsonify({"status": "success", "message": "Logged out successfully"})


@admin_bp.route("/admin/notice", methods=["GET"])
def admin_notice_get():
    """Return the current public notice (no auth required — displayed on keypad page)."""
    notice = core.config.get("server", "notice", fallback="").strip()
    return jsonify({"notice": notice})


@admin_bp.route("/admin/notice", methods=["POST"])
def admin_notice_set():
    """Set or clear the public notice. Requires admin auth."""
    if not core._require_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json(silent=True) or {}
    notice = data.get("notice", "").strip()
    if not core.config.has_section("server"):
        core.config.add_section("server")
    if notice:
        core.config.set("server", "notice", notice)
    else:
        core.config.remove_option("server", "notice")
    try:
        core.save_config()
    except OSError as e:
        core.logger.error(f"Failed to save config: {e}")
        return jsonify({"error": "Could not save config"}), 500
    return jsonify({"status": "ok", "notice": notice})


@admin_bp.route("/admin/test-mode", methods=["GET"])
def admin_test_mode_get():
    """Return current test_mode state. Requires admin auth."""
    if not core._require_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"test_mode": core.test_mode})


@admin_bp.route("/admin/test-mode", methods=["POST"])
def admin_test_mode_set():
    """Enable or disable test_mode. Requires admin auth."""
    if not core._require_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    data = request.get_json(silent=True) or {}
    if "enabled" not in data:
        return jsonify({"error": "Missing 'enabled' field"}), 400
    new_value = bool(data["enabled"])
    if not core.config.has_section("server"):
        core.config.add_section("server")
    core.config.set("server", "test_mode", "true" if new_value else "false")
    try:
        core.save_config()
    except OSError as e:
        core.logger.error(f"Failed to save config: {e}")
        return jsonify({"error": "Could not save config"}), 500
    core.test_mode = new_value
    if core.test_mode:
        core.logger.warning("TEST MODE ENABLED via admin panel — the door will NOT open.")
    else:
        core.logger.info("Test mode disabled via admin panel.")
    return jsonify({"status": "ok", "test_mode": core.test_mode})


@admin_bp.route("/admin/background", methods=["GET"])
def admin_background_get():
    """Return whether a custom background is currently set. Requires admin auth."""
    if not core._require_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    has_custom = os.path.exists(core.BACKGROUND_DEFAULT_PATH) and not core._backgrounds_are_identical()
    return jsonify({"custom": has_custom})


@admin_bp.route("/admin/background", methods=["POST"])
def admin_background_upload():
    """Upload a new background image. Requires admin auth."""
    if not core._require_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    # Read the file data
    data = f.read(core.MAX_BACKGROUND_SIZE + 1)
    if len(data) > core.MAX_BACKGROUND_SIZE:
        return jsonify({"error": "File too large (max 10 MB)"}), 413

    # Validate it's actually an image using magic-byte detection
    kind = filetype.guess(data)
    if kind is None or kind.extension not in core.ALLOWED_IMAGE_TYPES:
        return jsonify({"error": "Invalid image type. Allowed: JPEG, PNG, GIF, WebP"}), 415
    img_type = kind.extension

    # Write atomically via temp file
    try:
        fd, tmp_path = tempfile.mkstemp(dir=core.STATIC_DIR)
        try:
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(data)
            os.replace(tmp_path, core.BACKGROUND_PATH)
        except Exception:
            os.unlink(tmp_path)
            raise
    except OSError as e:
        core.logger.error(f"Failed to save background image: {e}")
        return jsonify({"error": "Could not save background"}), 500

    core.logger.info(f"Background image updated by admin ({len(data)} bytes, type={img_type})")
    return jsonify({"status": "ok"})


@admin_bp.route("/admin/background", methods=["DELETE"])
def admin_background_reset():
    """Reset the background image to the original default. Requires admin auth."""
    if not core._require_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    if not os.path.exists(core.BACKGROUND_DEFAULT_PATH):
        return jsonify({"error": "No default background to restore"}), 404

    try:
        shutil.copy2(core.BACKGROUND_DEFAULT_PATH, core.BACKGROUND_PATH)
    except OSError as e:
        core.logger.error(f"Failed to restore default background: {e}")
        return jsonify({"error": "Could not restore default"}), 500

    core.logger.info("Background image reset to default by admin")
    return jsonify({"status": "ok"})


@admin_bp.route("/admin/logs")
def admin_logs():
    """Get parsed log data for admin dashboard"""
    # Check if admin is authenticated
    if not session.get("admin_authenticated"):
        return jsonify({"error": "Authentication required"}), 401

    try:
        logs = []
        log_path = core.log_path

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
                                core.logger.error(f"Error parsing old format log line: {line}, error: {e}")
                                continue
                        except Exception as e:
                            core.logger.error(f"Error parsing JSON log line: {line}, error: {e}")
                            continue
            except Exception as e:
                core.logger.error(f"Error reading log file: {e}")
        return jsonify({"logs": logs})
    except Exception as e:
        core.logger.error(f"Exception in admin_logs: {e}")
        return jsonify({"error": "Failed to load logs"}), 500


@admin_bp.route("/admin/logs/clear", methods=["POST"])
def admin_logs_clear():
    """Clear logs: either all, or only remove test-mode entries.

    Body: {"mode": "all" | "test_only"}
    """
    if not session.get("admin_authenticated"):
        return jsonify({"error": "Authentication required"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    body = request.get_json(silent=True) or {}
    mode = (body.get("mode") or "all").lower()

    try:
        removed = 0
        kept = 0
        if mode == "all":
            # Truncate file
            try:
                with open(core.log_path, "w", encoding="utf-8"):
                    pass
            except FileNotFoundError:
                # Nothing to clear
                pass
        elif mode == "test_only":
            # Filter out lines that look like TEST MODE entries
            lines = []
            try:
                with open(core.log_path, "r", encoding="utf-8") as f:
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
            fd, tmp_path = tempfile.mkstemp(prefix="log.", suffix=".txt", dir=os.path.dirname(core.log_path) or None)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                    tmp.writelines(filtered)
                os.replace(tmp_path, core.log_path)
            finally:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    core.logger.exception(f"Failed to remove temporary log file temp_path={tmp_path}")
        else:
            return jsonify({"error": "Invalid mode"}), 400

        core.attempt_logger.info(
            json.dumps(
                {
                    "timestamp": core.get_current_time().isoformat(),
                    "ip": core.get_client_identifier()[0],
                    "user": "ADMIN",
                    "status": "ADMIN_LOGS_CLEAR",
                    "details": f"mode={mode}, removed={removed}, kept={kept}",
                }
            )
        )
        return jsonify({"status": "ok", "mode": mode, "removed": removed, "kept": kept})
    except Exception as e:
        core.logger.error(f"Exception in admin_logs_clear: {e}")
        return jsonify({"error": "Failed to clear logs"}), 500


# --- Admin: User Management Endpoints ---


@admin_bp.route("/admin/users", methods=["GET"])
def admin_users_list():
    if not core._require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    try:
        # Build combined view: config pins (read-only) + store users (editable)
        store_users = core.users_store.list_users(include_pins=False).get("users", [])
        store_names = {u["username"] for u in store_users}
        config_only = []
        for name in sorted(core.user_pins.keys()):
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
        core.logger.error(f"Error listing users: {e}")
        return jsonify({"error": "Failed to list users"}), 500


@admin_bp.route("/admin/users", methods=["POST"])
def admin_users_create():
    if not core._require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    try:
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        pin = body.get("pin")
        active = bool(body.get("active", True))
        if not username or not pin:
            return jsonify({"error": "username and pin are required"}), 400
        if username in core.user_pins:
            return (
                jsonify({"error": "User exists in config and cannot be edited via UI"}),
                409,
            )
        # Duplicate PIN check across config pins and store users
        if any(cfg_pin == pin for cfg_pin in core.user_pins.values()):
            return jsonify({"error": "PIN already in use by another user"}), 409
        if core.users_store.pin_exists(pin):
            return jsonify({"error": "PIN already in use by another user"}), 409
        core.users_store.create_user(username, pin, active)
        core.attempt_logger.info(
            json.dumps(
                {
                    "timestamp": core.get_current_time().isoformat(),
                    "ip": core.get_client_identifier()[0],
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
        core.logger.warning(f"ValueError creating user '{username}': {ve}")
        return jsonify({"error": "Invalid input"}), 400
    except Exception as e:
        core.logger.error(f"Error creating user: {e}")
        return jsonify({"error": "Failed to create user"}), 500


@admin_bp.route("/admin/users/<username>", methods=["PUT"])
def admin_users_update(username: str):
    if not core._require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    if username in core.user_pins:
        return jsonify({"error": "Config-defined users cannot be edited via UI"}), 409
    try:
        body = request.get_json(silent=True) or {}
        pin = body.get("pin")
        active = body.get("active")
        if pin is not None:
            if any(cfg_pin == pin for cfg_user, cfg_pin in core.user_pins.items() if cfg_user != username):
                return jsonify({"error": "PIN already in use by another user"}), 409
            if core.users_store.pin_exists(pin, exclude_username=username):
                return jsonify({"error": "PIN already in use by another user"}), 409
        core.users_store.update_user(username, pin=pin, active=active)
        core.attempt_logger.info(
            json.dumps(
                {
                    "timestamp": core.get_current_time().isoformat(),
                    "ip": core.get_client_identifier()[0],
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
        core.logger.warning(f"ValueError updating user '{username}': {ve}")
        return jsonify({"error": "Invalid input"}), 400
    except Exception as e:
        core.logger.error(f"Error updating user: {e}")
        return jsonify({"error": "Failed to update user"}), 500


@admin_bp.route("/admin/users/<username>", methods=["DELETE"])
def admin_users_delete(username: str):
    if not core._require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    if username in core.user_pins:
        return jsonify({"error": "Config-defined users cannot be deleted via UI"}), 409
    try:
        core.users_store.delete_user(username)
        core.attempt_logger.info(
            json.dumps(
                {
                    "timestamp": core.get_current_time().isoformat(),
                    "ip": core.get_client_identifier()[0],
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
        core.logger.error(f"Error deleting user: {e}")
        return jsonify({"error": "Failed to delete user"}), 500


@admin_bp.route("/admin/users/<username>/migrate", methods=["POST"])
def admin_users_migrate(username: str):
    """Migrate a user from config.ini [pins] to the JSON user store.

    Optionally accepts {"pin": "new_pin"} to set a new PIN during migration.
    If no PIN provided, uses the existing PIN from config.ini.
    Config entry remains but is ignored when user exists in JSON store.
    """
    if not core._require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    # Get existing PIN from config
    existing_pin = core.user_pins.get(username)
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
        core.users_store.create_user(username, pin_to_use, True)

        # Remove from config.ini after successful migration
        try:
            if core.config.has_option("pins", username):
                core.config.remove_option("pins", username)
                core.save_config()
                # Update in-memory user_pins
                core.user_pins.pop(username, None)
        except Exception as config_err:
            core.logger.warning(f"Failed to remove {username} from config.ini: {config_err}")

        core.attempt_logger.info(
            json.dumps(
                {
                    "timestamp": core.get_current_time().isoformat(),
                    "ip": request.remote_addr or "unknown",
                    "user": "ADMIN",
                    "status": "ADMIN_USER_MIGRATE",
                    "details": f"username={username}",
                }
            )
        )
        return jsonify({"status": "migrated"})
    except Exception as e:
        core.logger.error(f"Error creating user in store: {e}")
        return jsonify({"error": "Failed to migrate user"}), 500


@admin_bp.route("/admin/users/migrate-all", methods=["POST"])
def admin_users_migrate_all():
    """Migrate all config-only users into the JSON store.

    Each user is migrated individually with safe config update and rollback on failure.
    Returns summary of successes and failures.
    """
    if not core._require_admin_authenticated():
        return jsonify({"error": "Authentication required"}), 401
    if not core._check_admin_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403
    if not core.user_pins:
        return jsonify({"migrated": 0, "failed": []}), 200

    migrated = 0
    failed = []
    # Copy list of usernames to avoid mutation during loop
    candidates = list(core.user_pins.keys())

    for username in candidates:
        existing_pin = core.user_pins.get(username)
        if not isinstance(existing_pin, str):
            failed.append({"username": username, "error": "invalid_pin"})
            continue
        # Validate format
        if not (existing_pin.isdigit() and 4 <= len(existing_pin) <= 8):
            failed.append({"username": username, "error": "invalid_format"})
            continue
        # Skip if user already exists in JSON store
        if core.users_store.user_exists(username):
            continue

        # Create in JSON store
        try:
            core.users_store.create_user(username, existing_pin, True)

            # Remove from config.ini after successful migration
            try:
                if core.config.has_option("pins", username):
                    core.config.remove_option("pins", username)
                    core.save_config()
                    # Update in-memory user_pins
                    core.user_pins.pop(username, None)
            except Exception as config_err:
                core.logger.warning(f"Failed to remove {username} from config.ini: {config_err}")

            core.attempt_logger.info(
                json.dumps(
                    {
                        "timestamp": core.get_current_time().isoformat(),
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
            core.logger.error(f"Failed to migrate user {username}: {e}", exc_info=True)
            failed.append(
                {
                    "username": username,
                    "error": "store_write_failed",
                    "detail": "internal_error",
                }
            )

    status = 200 if not failed else 207  # multi-status semantics
    return jsonify({"migrated": migrated, "failed": failed}), status
