"""Security helpers: rate limiting, headers, request validation."""

import hashlib
import logging
import secrets
import time
from datetime import timedelta

from flask import request, session

from config import (
    BLOCK_TIME,
    MAX_ATTEMPTS,
    MAX_GLOBAL_ATTEMPTS_PER_HOUR,
    SESSION_MAX_ATTEMPTS,
    get_current_time,
)

logger = logging.getLogger("dooropener")


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    """In-memory multi-layer rate limiter.

    Tracks per-IP, per-session, and global failed attempt counts with
    automatic blocking after configurable thresholds.
    """

    __slots__ = (
        "ip_failed", "ip_blocked_until", "session_failed",
        "session_blocked_until", "global_failed", "global_last_reset",
        "_last_prune",
    )

    def __init__(self):
        self.ip_failed: dict[str, int] = {}
        self.ip_blocked_until: dict[str, object] = {}
        self.session_failed: dict[str, int] = {}
        self.session_blocked_until: dict[str, object] = {}
        self.global_failed = 0
        self.global_last_reset = get_current_time()
        self._last_prune = get_current_time()

    # --- Query methods ---

    def check_global_rate_limit(self) -> bool:
        now = get_current_time()
        if now - self.global_last_reset > timedelta(hours=1):
            self.global_failed = 0
            self.global_last_reset = now
            self._prune_expired(now)
        return self.global_failed < MAX_GLOBAL_ATTEMPTS_PER_HOUR

    def _prune_expired(self, now) -> None:
        """Remove expired block/failure entries to prevent unbounded memory growth."""
        for key in [k for k, v in self.ip_blocked_until.items() if v and now >= v]:
            del self.ip_blocked_until[key]
            self.ip_failed.pop(key, None)
        for key in [k for k, v in self.session_blocked_until.items() if v and now >= v]:
            del self.session_blocked_until[key]
            self.session_failed.pop(key, None)

    def is_blocked(self, identifier: str, session_id: str) -> tuple[bool, float]:
        """Return (blocked, remaining_seconds) checking all layers."""
        # Persistent session cookie first
        sess_block_ts = session.get("blocked_until_ts")
        if sess_block_ts and time.time() < float(sess_block_ts):
            return True, float(sess_block_ts) - time.time()

        now = get_current_time()
        remaining = 0.0

        sb = self.session_blocked_until.get(session_id)
        if sb and now < sb:
            remaining = max(remaining, (sb - now).total_seconds())

        ib = self.ip_blocked_until.get(identifier)
        if ib and now < ib:
            remaining = max(remaining, (ib - now).total_seconds())

        return remaining > 0, remaining

    def blocked_until_ts(self, identifier: str, session_id: str) -> float | None:
        """Return epoch timestamp for the latest active block, or None."""
        now = get_current_time()
        ts = None

        sb = self.session_blocked_until.get(session_id)
        if sb and now < sb:
            ts = sb.timestamp()

        ib = self.ip_blocked_until.get(identifier)
        if ib and now < ib:
            ip_ts = ib.timestamp()
            ts = max(ts or ip_ts, ip_ts)

        return ts

    # --- Mutation methods ---

    def record_failure(
        self, identifier: str, session_id: str
    ) -> tuple[str, int]:
        """Record a failed attempt.

        Returns (reason_key, remaining_attempts).
        reason_key: ``"session_blocked"`` | ``"ip_blocked"`` | ``"failed"``
        """
        now = get_current_time()
        self.ip_failed[identifier] = self.ip_failed.get(identifier, 0) + 1
        self.session_failed[session_id] = self.session_failed.get(session_id, 0) + 1
        self.global_failed += 1

        if self.session_failed[session_id] >= SESSION_MAX_ATTEMPTS:
            self.session_blocked_until[session_id] = now + BLOCK_TIME
            session["blocked_until_ts"] = (now + BLOCK_TIME).timestamp()
            return "session_blocked", 0

        if self.ip_failed[identifier] >= MAX_ATTEMPTS:
            self.ip_blocked_until[identifier] = now + BLOCK_TIME
            return "ip_blocked", 0

        remaining = min(
            SESSION_MAX_ATTEMPTS - self.session_failed.get(session_id, 0),
            MAX_ATTEMPTS - self.ip_failed.get(identifier, 0),
        )
        return "failed", remaining

    def record_success(self, identifier: str, session_id: str) -> None:
        """Clear all rate-limiting state for a successful authentication."""
        self.ip_failed.pop(identifier, None)
        self.session_failed.pop(session_id, None)
        if identifier in self.ip_blocked_until:
            del self.ip_blocked_until[identifier]
        if session_id in self.session_blocked_until:
            del self.session_blocked_until[session_id]
        session.pop("blocked_until_ts", None)


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------
def get_client_identifier() -> tuple[str, str, str]:
    """Return ``(primary_ip, session_id, composite_identifier)``."""
    primary_ip = request.remote_addr
    session_id = session.get("_session_id")
    if not session_id:
        session_id = secrets.token_hex(16)
        session["_session_id"] = session_id

    ua = request.headers.get("User-Agent", "")[:100]
    lang = request.headers.get("Accept-Language", "")[:50]
    fp = hashlib.sha256((ua + lang).encode()).hexdigest()[:8]
    identifier = f"{primary_ip}:{fp}"
    return primary_ip, session_id, identifier


def add_security_headers(response):
    """Attach hardening headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
        "magnetometer=(), gyroscope=(), fullscreen=(self)"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    return response


def is_request_suspicious() -> bool:
    """Detect obviously automated / bot traffic.

    Does NOT flag common tools (curl, wget, python-requests) since those
    are used by health-checks and legitimate API clients.
    """
    ua = request.headers.get("User-Agent", "")
    if not ua or len(ua) < 10:
        return True
    bot_patterns = ["bot", "crawler", "spider", "scraper"]
    return any(p in ua.lower() for p in bot_patterns)


def validate_pin_input(pin) -> tuple[bool, str | None]:
    """Validate PIN format. Returns ``(valid, cleaned_pin)``."""
    try:
        if not isinstance(pin, str):
            return False, None
        if not pin.isdigit() or not (4 <= len(pin) <= 8):
            return False, None
        return True, pin
    except Exception:
        return False, None


def get_delay_seconds(attempt_count: int) -> int:
    """Calculate progressive delay: 1s, 2s, 4s, 8s, 16s (informational only)."""
    return min(2 ** (attempt_count - 1), 16) if attempt_count > 0 else 0
