"""Read, classify and summarise the audit log (log.txt).

Every audit entry has a ``status`` such as ``SUCCESS`` or ``ADMIN_USER_CREATE``. This module turns
those raw codes into something an admin can read: which *category* an entry belongs to (door,
security, admin, system), a human label, and a severity. It also computes the statistics shown on
the admin dashboard. It is pure (no Flask, no globals) so it can be tested directly.
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

CATEGORIES = ("door", "security", "admin", "system")

# status -> (category, label, severity). Severity: ok | info | warn | bad
STATUS_INFO: Dict[str, tuple] = {
    # --- door: someone used the keypad / SSO -------------------------------------------------
    "SUCCESS": ("door", "Door opened", "ok"),
    "AUTH_FAILURE": ("door", "Wrong PIN", "warn"),
    "DISABLED_USER": ("door", "Disabled account", "warn"),
    "INVALID_FORMAT": ("door", "Malformed request", "warn"),
    # --- security: the rate limiter stepped in -----------------------------------------------
    "SESSION_BLOCKED": ("security", "Session blocked", "warn"),
    "IP_BLOCKED": ("security", "IP blocked", "warn"),
    "BLOCK_ENFORCED": ("security", "Block enforced", "warn"),
    "GLOBAL_THRESHOLD": ("security", "Global limit hit", "bad"),
    # --- system: the door did not open although it should have -------------------------------
    "FAILURE": ("system", "Open failed (Home Assistant)", "bad"),
    "API_FAILURE": ("system", "Open failed (internal error)", "bad"),
    "EXCEPTION": ("system", "Server error", "bad"),
    # --- admin: the dashboard itself ---------------------------------------------------------
    "ADMIN_SUCCESS": ("admin", "Admin login", "info"),
    "ADMIN_FAILURE": ("admin", "Admin login failed", "warn"),
    "ADMIN_SESSION_BLOCKED": ("admin", "Admin login blocked", "warn"),
    "ADMIN_IP_BLOCKED": ("admin", "Admin login blocked", "warn"),
    "ADMIN_USER_CREATE": ("admin", "User created", "info"),
    "ADMIN_USER_UPDATE": ("admin", "User updated", "info"),
    "ADMIN_USER_DELETE": ("admin", "User deleted", "info"),
    "ADMIN_USER_MIGRATE": ("admin", "User migrated", "info"),
    "ADMIN_LOGS_CLEAR": ("admin", "Logs cleared", "info"),
    "ADMIN_SETTING": ("admin", "Setting changed", "info"),
}

DENIED = {"AUTH_FAILURE", "DISABLED_USER", "INVALID_FORMAT"}
FAULTS = {"FAILURE", "API_FAILURE", "EXCEPTION"}
BLOCKS = {"SESSION_BLOCKED", "IP_BLOCKED", "BLOCK_ENFORCED", "GLOBAL_THRESHOLD"}
ADMIN_CHANGES = {s for s, v in STATUS_INFO.items() if v[0] == "admin"} - {
    "ADMIN_SUCCESS",
    "ADMIN_FAILURE",
    "ADMIN_SESSION_BLOCKED",
    "ADMIN_IP_BLOCKED",
}

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def classify(status: Optional[str]) -> Dict[str, str]:
    """Category, label and severity for a raw status code (unknown codes are shown as-is)."""
    info = STATUS_INFO.get(status or "")
    if info:
        return {"category": info[0], "label": info[1], "severity": info[2]}
    if status and status.startswith("ADMIN_"):
        return {"category": "admin", "label": status[6:].replace("_", " ").capitalize(), "severity": "info"}
    return {"category": "system", "label": (status or "Unknown").replace("_", " ").capitalize(), "severity": "info"}


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    """One log line -> raw fields, or None if it isn't an audit entry. Handles the current JSON
    format (optionally behind a logging-module prefix) and the old ``ts - ip - user - status`` one."""
    line = line.strip()
    if not line:
        return None
    start = line.find("{")
    try:
        data = json.loads(line[start:] if start != -1 else line)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    if not line.startswith("{") and " - " in line:
        parts = line.split(" - ", 4)
        if len(parts) >= 4:
            return {
                "timestamp": parts[0],
                "ip": parts[1],
                "user": parts[2],
                "status": parts[3],
                "details": parts[4] if len(parts) > 4 else None,
            }
    return None


def entry_from_raw(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a raw log record and add its classification."""
    user = raw.get("user")
    status = raw.get("status")
    details = raw.get("details")
    entry = {
        "timestamp": raw.get("timestamp"),
        "ip": raw.get("ip"),
        "user": user if user and user != "UNKNOWN" else None,
        "status": status,
        "details": details,
        # Door attempts made while test mode was on never touched the door.
        "test": "TEST MODE" in str(details or ""),
    }
    entry.update(classify(status))
    return entry


def read_entries(lines: Iterable[str]) -> List[Dict[str, Any]]:
    entries = []
    for line in lines:
        raw = _parse_line(line)
        if raw is not None:
            entries.append(entry_from_raw(raw))
    return entries


def _parse_ts(value: Any, tz) -> Optional[datetime]:
    """Aware datetime in ``tz`` (naive timestamps, e.g. from the old format, are taken as ``tz``)."""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace(",", "."))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)
    return dt.astimezone(tz)


def _ref(entry: Dict[str, Any], dt: datetime) -> Dict[str, Any]:
    return {"timestamp": dt.isoformat(), "user": entry["user"], "ip": entry["ip"], "label": entry["label"]}


def compute_stats(entries: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    """Dashboard statistics. ``now`` carries the configured timezone; every bucket (day, hour,
    weekday) is in that timezone, not the server's or the browser's."""
    tz = now.tzinfo
    today = now.date()
    day_30 = now - timedelta(days=30)
    day_7 = now - timedelta(days=7)
    day_1 = now - timedelta(days=1)

    categories: Counter = Counter()
    test_entries = 0
    opens = denied = faults = 0
    opens_today = opens_7d = opens_30d = 0
    users_opened: Counter = Counter()
    users_last: Dict[str, datetime] = {}
    via_sso = 0
    daily_opens: Counter = Counter()
    daily_denied: Counter = Counter()
    hourly_opens = [0] * 24
    hourly_denied = [0] * 24
    heat = [[0] * 24 for _ in range(7)]
    weekday_opens = [0] * 7
    first_door: Optional[datetime] = None
    last_door: Optional[datetime] = None
    last_open = None

    sec_blocks = 0
    sec_blocks_24h = 0
    sec_by_type: Counter = Counter()
    ip_trouble: Dict[str, Counter] = defaultdict(Counter)

    admin_logins = admin_failed = admin_changes = 0
    last_admin_login = None
    recent_admin: List[Dict[str, Any]] = []

    sys_errors = sys_errors_7d = 0
    last_error = None

    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None

    for e in entries:
        dt = _parse_ts(e["timestamp"], tz)
        if dt is not None:
            first_ts = dt if first_ts is None or dt < first_ts else first_ts
            last_ts = dt if last_ts is None or dt > last_ts else last_ts
        cat, status = e["category"], e["status"]
        categories[cat] += 1

        if e["test"] and cat in ("door", "system"):
            test_entries += 1  # counted separately, never mixed into real door statistics
            continue

        if cat == "door":
            if status == "SUCCESS":
                opens += 1
                if e["user"]:
                    users_opened[e["user"]] += 1
                if "via OIDC" in str(e["details"] or ""):
                    via_sso += 1
                if dt is not None:
                    users_last[e["user"] or ""] = max(users_last.get(e["user"] or "", dt), dt)
                    daily_opens[dt.date()] += 1
                    hourly_opens[dt.hour] += 1
                    heat[dt.weekday()][dt.hour] += 1
                    weekday_opens[dt.weekday()] += 1
                    opens_today += dt.date() == today
                    opens_7d += dt >= day_7
                    opens_30d += dt >= day_30
                    first_door = dt if first_door is None or dt < first_door else first_door
                    last_door = dt if last_door is None or dt > last_door else last_door
                    if last_open is None or dt > _parse_ts(last_open["timestamp"], tz):
                        last_open = _ref(e, dt)
            else:
                denied += 1
                if dt is not None:
                    daily_denied[dt.date()] += 1
                    hourly_denied[dt.hour] += 1
                    first_door = dt if first_door is None or dt < first_door else first_door
                    last_door = dt if last_door is None or dt > last_door else last_door
                if e["ip"]:
                    ip_trouble[e["ip"]]["denied"] += 1
        elif cat == "security":
            sec_blocks += 1
            sec_by_type[status] += 1
            if dt is not None and dt >= day_1:
                sec_blocks_24h += 1
            if e["ip"]:
                ip_trouble[e["ip"]]["blocked"] += 1
        elif cat == "admin":
            if status == "ADMIN_SUCCESS":
                admin_logins += 1
                if dt is not None and (last_admin_login is None or dt > _parse_ts(last_admin_login["timestamp"], tz)):
                    last_admin_login = _ref(e, dt)
            elif status in ("ADMIN_FAILURE", "ADMIN_SESSION_BLOCKED", "ADMIN_IP_BLOCKED"):
                admin_failed += 1
                if e["ip"]:
                    ip_trouble[e["ip"]]["admin_failed"] += 1
            else:
                admin_changes += 1
            if dt is not None and status != "ADMIN_SUCCESS":
                recent_admin.append({**_ref(e, dt), "details": e["details"], "severity": e["severity"]})
        else:  # system
            if status in FAULTS:
                faults += 1
            sys_errors += 1
            if dt is not None:
                if dt >= day_7:
                    sys_errors_7d += 1
                if last_error is None or dt > _parse_ts(last_error["timestamp"], tz):
                    last_error = {**_ref(e, dt), "details": e["details"]}

    attempts = opens + denied + faults
    span_days = 1
    if first_door is not None and last_door is not None:
        span_days = max(1, (last_door.date() - first_door.date()).days + 1)

    def peak(counts: List[int]) -> Optional[int]:
        return max(range(len(counts)), key=counts.__getitem__) if any(counts) else None

    hour_peak, day_peak = peak(hourly_opens), peak(weekday_opens)
    daily = []
    for back in range(13, -1, -1):
        d = today - timedelta(days=back)
        daily.append({"date": d.isoformat(), "opens": daily_opens.get(d, 0), "denied": daily_denied.get(d, 0)})

    top_users = [
        {"user": u, "opens": n, "last_used": users_last[u].isoformat() if u in users_last else None}
        for u, n in users_opened.most_common(8)
    ]
    top_ips = sorted(
        (
            {
                "ip": ip,
                "denied": c["denied"],
                "blocked": c["blocked"],
                "admin_failed": c["admin_failed"],
                "total": sum(c.values()),
            }
            for ip, c in ip_trouble.items()
        ),
        key=lambda r: (-r["total"], r["ip"]),
    )[:5]
    recent_admin.sort(key=lambda r: r["timestamp"], reverse=True)

    return {
        "generated_at": now.isoformat(),
        "entries": len(entries),
        "first": first_ts.isoformat() if first_ts else None,
        "last": last_ts.isoformat() if last_ts else None,
        "categories": {c: categories.get(c, 0) for c in CATEGORIES},
        "test_mode_entries": test_entries,
        "door": {
            "opens": opens,
            "denied": denied,
            "faults": faults,
            "attempts": attempts,
            "success_rate": round(opens / attempts * 100, 1) if attempts else None,
            "opens_today": opens_today,
            "opens_7d": opens_7d,
            "opens_30d": opens_30d,
            "avg_per_day": round(opens / span_days, 1) if opens else 0,
            "unique_users": len(users_opened),
            "via_sso": via_sso,
            "last_open": last_open,
            "busiest_hour": {"hour": hour_peak, "count": hourly_opens[hour_peak]} if hour_peak is not None else None,
            "busiest_weekday": (
                {"weekday": WEEKDAYS[day_peak], "count": weekday_opens[day_peak]} if day_peak is not None else None
            ),
            "daily": daily,
            "hourly": [{"hour": h, "opens": hourly_opens[h], "denied": hourly_denied[h]} for h in range(24)],
            "heatmap": heat,
            "top_users": top_users,
        },
        "security": {
            "blocks": sec_blocks,
            "blocks_24h": sec_blocks_24h,
            "by_type": dict(sec_by_type),
            "top_ips": top_ips,
        },
        "admin": {
            "logins": admin_logins,
            "failed_logins": admin_failed,
            "changes": admin_changes,
            "last_login": last_admin_login,
            "recent": recent_admin[:6],
        },
        "system": {"errors": sys_errors, "errors_7d": sys_errors_7d, "last_error": last_error},
    }
