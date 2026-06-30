"""Keypad-facing routes: PWA assets, the keypad page, battery, door opening, reporting."""

import hmac
import os
import time

import requests
from flask import Blueprint, abort, g, jsonify, render_template, request, send_from_directory, session

import app as core

door_bp = Blueprint("door", __name__)


@door_bp.route("/service-worker.js")
def service_worker():
    """Serve the service worker at the root scope for PWA installation."""
    try:
        return send_from_directory(
            os.path.join(core.app.root_path, "static"),
            "service-worker.js",
            mimetype="application/javascript",
        )
    except Exception:
        abort(404)


@door_bp.route("/manifest.webmanifest")
def manifest_file():
    """Serve the web app manifest with the correct MIME type."""
    try:
        return send_from_directory(
            os.path.join(core.app.root_path, "static"),
            "manifest.webmanifest",
            mimetype="application/manifest+json",
        )
    except Exception:
        abort(404)


@door_bp.route("/")
def index():
    easter_egg_enabled = core.config.getboolean("server", "67mode", fallback=False)
    page_title = core.config.get("server", "page_title", fallback="").strip()
    notice = core.config.get("server", "notice", fallback="").strip()
    return render_template(
        "index.html",
        oidc_enabled=bool(core.oauth),
        require_pin_for_oidc=core.require_pin_for_oidc,
        easter_egg_enabled=easter_egg_enabled,
        app_version=core.APP_VERSION,
        csp_nonce=g.csp_nonce,
        page_title=page_title,
        notice=notice,
        test_mode=core.test_mode,
        pushbullet_enabled=bool(core.pushbullet_token),
    )


@door_bp.route("/battery")
def battery():
    """Get battery level from Home Assistant, cached briefly.

    The keypad page polls this every 60s per open client; the cache collapses N
    concurrent clients into at most one upstream read per BATTERY_CACHE_TTL window.
    """
    now_mono = time.monotonic()
    if now_mono - core._battery_cache["ts"] < core.BATTERY_CACHE_TTL:
        return jsonify({"level": core._battery_cache["level"]})
    level = core._fetch_battery_level()
    core._battery_cache["level"] = level
    core._battery_cache["ts"] = now_mono
    return jsonify({"level": level})


@door_bp.route("/open-door", methods=["POST"])
def open_door():
    try:
        primary_ip, session_id, identifier = core.get_client_identifier()
        now = core.get_current_time()

        # Check for suspicious requests first
        if core.is_request_suspicious():
            core.log_attempt(
                "SUSPICIOUS", "Suspicious request detected", primary_ip=primary_ip, session_id=session_id, now=now
            )
            return jsonify({"status": "error", "message": "Request blocked"}), 403

        # Check global rate limit
        if not core.check_global_rate_limit():
            core.log_attempt(
                "GLOBAL_BLOCKED", "Global rate limit exceeded", primary_ip=primary_ip, session_id=session_id, now=now
            )
            return (
                jsonify({"status": "error", "message": "Service temporarily unavailable"}),
                429,
            )

        # Enforce session-based blocking stored in signed cookie (persists across workers)
        sess_block_ts = session.get("blocked_until_ts")
        if sess_block_ts and time.time() < float(sess_block_ts):
            remaining = int(float(sess_block_ts) - time.time())
            core.log_attempt(
                "SESSION_BLOCKED",
                f"Session blocked for {remaining} more seconds (persisted)",
                primary_ip=primary_ip,
                session_id=session_id,
                now=now,
            )
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
        if core.session_blocked_until[session_id] and now < core.session_blocked_until[session_id]:
            remaining = (core.session_blocked_until[session_id] - now).total_seconds()
            core.log_attempt(
                "SESSION_BLOCKED",
                f"Session blocked for {int(remaining)} more seconds",
                primary_ip=primary_ip,
                session_id=session_id,
                now=now,
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Too many failed attempts. Please try again later.",
                        "blocked_until": core.session_blocked_until[session_id].timestamp(),
                    }
                ),
                429,
            )

        # Check IP-based blocking (fallback)
        if core.ip_blocked_until[identifier] and now < core.ip_blocked_until[identifier]:
            remaining = (core.ip_blocked_until[identifier] - now).total_seconds()
            core.log_attempt(
                "IP_BLOCKED",
                f"IP blocked for {int(remaining)} more seconds",
                primary_ip=primary_ip,
                session_id=session_id,
                now=now,
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Too many failed attempts. Please try again later.",
                        "blocked_until": core.ip_blocked_until[identifier].timestamp(),
                    }
                ),
                429,
            )

        # Determine if OIDC session can open without PIN
        # OIDC must be fully enabled (oauth registered), otherwise treat as unauthenticated
        oidc_auth = bool(core.oauth) and bool(session.get("oidc_authenticated"))
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
            core.logger.warning(f"OIDC session for IP {primary_ip} has expired. Re-authentication required.")

        oidc_groups = session.get("oidc_groups", [])
        oidc_user = session.get("oidc_user")
        oidc_user_allowed = (not core.oidc_user_group) or (core.oidc_user_group in oidc_groups)

        data = request.get_json(force=True, silent=True)
        pin_from_request = data.get("pin") if data else None

        # If session expired and no PIN provided, return a clear error instead of confusing "PIN required"
        if oidc_session_expired and not pin_from_request:
            return jsonify({"status": "error", "message": "Session expired. Please log in again."}), 401

        # If no PIN provided but OIDC user is authenticated and allowed, proceed without PIN
        if (not pin_from_request) and oidc_auth and oidc_user_allowed and not core.require_pin_for_oidc:
            # Re-check block state right before granting access
            blocked = core._enforce_active_block(session_id, identifier, now, primary_ip, oidc_user or "UNKNOWN")
            if blocked is not None:
                return blocked

            matched_user = oidc_user or "oidc-user"
            # Reset failed attempts upon authorized OIDC use (no active block reached here)
            core.ip_failed_attempts[identifier] = 0
            core.session_failed_attempts[session_id] = 0
            if identifier in core.ip_blocked_until:
                del core.ip_blocked_until[identifier]
            if session_id in core.session_blocked_until:
                del core.session_blocked_until[session_id]

            return core._send_open_command(matched_user, primary_ip, session_id, now, via_oidc=True)

        # If we reach here, require a PIN (either because provided or policy demands it)
        if not data or "pin" not in data:
            core.logger.warning("No PIN provided in request body")
            return jsonify({"status": "error", "message": "PIN required"}), 400

        # Validate PIN format
        pin_valid, validated_pin = core.validate_pin_input(pin_from_request)
        if not pin_valid:
            # Increment all counters on invalid input
            core.ip_failed_attempts[identifier] += 1
            core.session_failed_attempts[session_id] += 1
            core.global_failed_attempts += 1

            reason = "Invalid PIN format"  # Error message
            core.log_attempt("INVALID_FORMAT", reason, primary_ip=primary_ip, session_id=session_id, now=now)
            return jsonify({"status": "error", "message": reason}), 400

        pin_from_request = validated_pin
        matched_user = None

        # Check PIN against user database (effective set)
        for user, user_pin in core.get_effective_user_pins().items():
            if hmac.compare_digest(pin_from_request, user_pin):
                matched_user = user
                break

        if matched_user:
            # Enforce any active block even on correct PIN before proceeding
            blocked = core._enforce_active_block(session_id, identifier, now, primary_ip, matched_user)
            if blocked is not None:
                return blocked

            # Reset failed attempts on successful auth (no active block reached here)
            core.ip_failed_attempts[identifier] = 0
            core.session_failed_attempts[session_id] = 0
            if identifier in core.ip_blocked_until:
                del core.ip_blocked_until[identifier]
            if session_id in core.session_blocked_until:
                del core.session_blocked_until[session_id]
            session.pop("blocked_until_ts", None)

            return core._send_open_command(matched_user, primary_ip, session_id, now)
        else:
            # Check if the PIN belongs to a disabled store user before treating as wrong PIN
            disabled_user = core.users_store.find_disabled_user_by_pin(pin_from_request)
            if disabled_user:
                core.log_attempt(
                    "DISABLED_USER",
                    "Access denied: account disabled",
                    user=disabled_user,
                    primary_ip=primary_ip,
                    session_id=session_id,
                    now=now,
                )
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
            core.ip_failed_attempts[identifier] += 1
            core.session_failed_attempts[session_id] += 1
            core.global_failed_attempts += 1

            # Check session-based blocking first (harder to bypass)
            if core.session_failed_attempts[session_id] >= core.SESSION_MAX_ATTEMPTS:
                core.session_blocked_until[session_id] = now + core.BLOCK_TIME
                # Also persist in signed session cookie so block applies across workers
                session["blocked_until_ts"] = (core.get_current_time() + core.BLOCK_TIME).timestamp()
                reason = f"Invalid PIN. Session blocked for {int(core.BLOCK_TIME.total_seconds() // 60)} minutes"
            elif core.ip_failed_attempts[identifier] >= core.MAX_ATTEMPTS:
                core.ip_blocked_until[identifier] = now + core.BLOCK_TIME
                reason = f"Invalid PIN. Access blocked for {int(core.BLOCK_TIME.total_seconds() // 60)} minutes"
            else:
                reason = "Invalid PIN"

            core.log_attempt("AUTH_FAILURE", reason, primary_ip=primary_ip, session_id=session_id, now=now)
            # Include blocked_until if a block is now active
            resp = {"status": "error", "message": reason}
            if core.session_blocked_until[session_id] and now < core.session_blocked_until[session_id]:
                resp["blocked_until"] = core.session_blocked_until[session_id].timestamp()
            elif core.ip_blocked_until[identifier] and now < core.ip_blocked_until[identifier]:
                resp["blocked_until"] = core.ip_blocked_until[identifier].timestamp()
            return jsonify(resp), 401

    except Exception as e:
        try:
            primary_ip, session_id, _ = core.get_client_identifier()
        except Exception:
            primary_ip = request.remote_addr
            session_id = "unknown"

        core.log_attempt(
            "EXCEPTION",
            f"Exception in open_door: {e}",
            primary_ip=primary_ip,
            session_id=session_id if session_id != "unknown" else None,
        )
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@door_bp.route("/report-problem", methods=["POST"])
def report_problem():
    """Send a problem report to the admin via Pushbullet."""
    if not core.pushbullet_token:
        return jsonify({"error": "Notifications not configured"}), 503

    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message is required"}), 400
    if len(message) > 500:
        return jsonify({"error": "Message too long (max 500 characters)"}), 400

    ip = request.remote_addr or "unknown"
    now = core.get_current_time()
    cutoff = now - core.REPORT_WINDOW
    core._report_timestamps[ip] = [t for t in core._report_timestamps[ip] if t > cutoff]
    if len(core._report_timestamps[ip]) >= core.REPORT_LIMIT:
        return jsonify({"error": "Too many reports — please wait before sending another"}), 429
    core._report_timestamps[ip].append(now)

    try:
        resp = requests.post(
            "https://api.pushbullet.com/v2/pushes",
            headers={"Access-Token": core.pushbullet_token, "Content-Type": "application/json"},
            json={"type": "note", "title": "DoorOpener: Problem Report", "body": message},
            timeout=8,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        core.logger.error(f"Pushbullet report failed: {e}")
        return jsonify({"error": "Failed to send notification"}), 502

    core.logger.info(f"Problem report sent from {ip}: {message[:80]}")
    return jsonify({"status": "ok"})


@door_bp.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200
