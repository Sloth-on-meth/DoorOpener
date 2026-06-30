"""OIDC / authentication routes (Authentik SSO)."""

import secrets
from datetime import datetime, timedelta, timezone

import requests
from flask import Blueprint, abort, jsonify, redirect, request, session, url_for

import app as core

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login")
def login_redirect():
    if not core.oauth:
        # Fallback to local login page
        return redirect(url_for("admin.admin"))

    # Generate a random state and store it in the session
    session["oidc_state"] = secrets.token_hex(16)

    # Generate a random nonce and store it in the session
    session["oidc_nonce"] = secrets.token_hex(16)

    # Start OIDC flow with the generated state and nonce
    _redirect_uri = core.oidc_redirect_uri or url_for("auth.oidc_callback", _external=True)
    return core.oauth.authentik.authorize_redirect(
        redirect_uri=_redirect_uri,
        state=session["oidc_state"],
        nonce=session["oidc_nonce"],
    )


@auth_bp.route("/oidc/callback")
def oidc_callback():
    if not core.oauth:
        return redirect(url_for("admin.admin"))
    try:
        # Validate the state parameter to prevent CSRF attacks
        if request.args.get("state") != session.pop("oidc_state", None):
            abort(401, "Invalid state")

        # Authorize the access token from the OIDC provider
        token = core.oauth.authentik.authorize_access_token()

        # Extract the ID token and claims
        id_token = token.get("id_token")
        claims = {}
        try:
            # Authlib stores parsed claims at token['userinfo'] or use userinfo() call
            claims = token.get("userinfo") or core.oauth.authentik.parse_id_token(token)
        except Exception:
            try:
                claims = core.oauth.authentik.userinfo(token=token)
            except Exception:
                claims = {}

        # Validate the nonce value to prevent replay attacks
        if claims.get("nonce") != session.pop("oidc_nonce", None):
            abort(401, "Invalid nonce")

        # Verify the ID token signature and claims
        public_key = core.config.get("oidc", "public_key", fallback=None)
        if public_key:
            try:
                claims = core.jwt.decode(id_token, key=public_key)
                # Validate signature, expiration, audience, etc.
                claims.validate()
            except Exception as e:
                core.logger.error(f"ID token validation error: {e}")
                return abort(401)

        # Validate the audience (aud) claim to ensure the token is intended for this application
        aud = claims.get("aud")
        aud_valid = False
        if isinstance(aud, list):
            aud_valid = core.oidc_client_id in aud
        else:
            aud_valid = aud == core.oidc_client_id
        if not aud_valid:
            core.logger.error(f"Invalid audience: {aud}")
            abort(401, "Invalid audience")

        # Validate issuer (iss) matches configured issuer
        iss = claims.get("iss")
        if iss and core.oidc_issuer and iss.rstrip("/") != core.oidc_issuer.rstrip("/"):
            core.logger.error(f"Invalid issuer: {iss}")
            abort(401, "Invalid issuer")

        # Validate the expiration time (exp) claim to ensure the token is still valid
        # Expiration and not-before with small clock skew allowance
        leeway = 60  # seconds
        now_utc = datetime.now(timezone.utc)
        exp = claims.get("exp")
        if exp:
            expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            if expiration_time + timedelta(seconds=leeway) < now_utc:
                core.logger.error("ID token has expired")
                abort(401, "Token has expired")
        nbf = claims.get("nbf")
        if nbf:
            not_before = datetime.fromtimestamp(nbf, tz=timezone.utc)
            if not_before - timedelta(seconds=leeway) > now_utc:
                core.logger.error("ID token not yet valid")
                abort(401, "Token not yet valid")

        # Reset the session to prevent session fixation attacks
        session.clear()

        # Extract user information from the claims
        user = claims.get("email") or claims.get("preferred_username") or claims.get("name") or "oidc-user"
        groups = claims.get("groups") or claims.get("roles") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]

        # Validate groups if they are defined in the configuration
        if core.oidc_admin_group or core.oidc_user_group:
            if not groups:
                core.logger.error("No groups found in ID token")
                abort(403, "Access denied: No groups found")

            # Check if the user is in the admin group
            is_admin = core.oidc_admin_group in groups if core.oidc_admin_group else False

            # Check if the user is in the allowed user group
            is_user_allowed = core.oidc_user_group in groups if core.oidc_user_group else True

            if not is_user_allowed:
                core.logger.error(f"User {user} is not in the allowed group")
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
            session["admin_login_time"] = core.get_current_time().isoformat()
            session["admin_user"] = user
            session["admin_csrf_token"] = secrets.token_hex(32)

        # All users are redirected to the home page after login.
        return redirect(url_for("door.index"))
    except Exception as e:
        core.logger.error(f"OIDC callback error: {e}")
        return abort(401)


@auth_bp.route("/auth/status")
def auth_status():
    """Return current authentication status and OIDC capability flags for UI."""
    enabled = bool(core.oauth)
    authenticated = enabled and bool(session.get("oidc_authenticated"))
    return jsonify(
        {
            "oidc_enabled": enabled,
            "oidc_authenticated": authenticated,
            "user": session.get("oidc_user") if authenticated else None,
            "groups": session.get("oidc_groups", []) if authenticated else [],
            "require_pin_for_oidc": core.require_pin_for_oidc,
        }
    )


@auth_bp.route("/oidc/logout")
def oidc_logout():
    """Logout from OIDC and clear session"""
    if core.oauth:
        try:
            # Clear the local session
            session.clear()

            # Fetch the .well-known configuration
            well_known_url = f"{core.oidc_issuer}/.well-known/openid-configuration"
            response = requests.get(well_known_url, timeout=10)
            if response.status_code == 200:
                config = response.json()
                logout_url = config.get("end_session_endpoint")
                if logout_url:
                    # Redirect to the OIDC provider's logout endpoint
                    return redirect(f"{logout_url}?redirect_uri={url_for('door.index', _external=True)}")
                else:
                    core.logger.error("Logout URL not found in .well-known configuration")
                    return (
                        jsonify({"status": "error", "message": "Logout URL not found"}),
                        500,
                    )
            else:
                core.logger.error(f"Failed to fetch .well-known configuration: {response.status_code}")
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
            core.logger.error(f"Error during OIDC logout: {e}")
            return jsonify({"status": "error", "message": "Failed to logout"}), 500
    else:
        # If OIDC is not enabled, just clear the session
        session.clear()
        return redirect(url_for("door.index"))
