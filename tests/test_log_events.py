"""Classification and statistics of the audit log."""

import json
from datetime import datetime, timedelta, timezone

import pytest

import log_events
from log_events import classify, compute_stats, entry_from_raw, read_entries

TZ = timezone(timedelta(hours=2))
NOW = datetime(2026, 11, 18, 15, 0, tzinfo=TZ)  # a Wednesday


def line(status, ts=NOW, user="UNKNOWN", ip="10.0.0.1", details=""):
    return json.dumps(
        {"timestamp": ts.isoformat(), "ip": ip, "session": "abc", "user": user, "status": status, "details": details}
    )


def stats(lines):
    return compute_stats(read_entries(lines), NOW)


# --- classification ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status, category",
    [
        ("SUCCESS", "door"),
        ("AUTH_FAILURE", "door"),
        ("DISABLED_USER", "door"),
        ("INVALID_FORMAT", "door"),
        ("SESSION_BLOCKED", "security"),
        ("IP_BLOCKED", "security"),
        ("BLOCK_ENFORCED", "security"),
        ("GLOBAL_THRESHOLD", "security"),
        ("FAILURE", "system"),
        ("API_FAILURE", "system"),
        ("EXCEPTION", "system"),
        ("ADMIN_SUCCESS", "admin"),
        ("ADMIN_FAILURE", "admin"),
        ("ADMIN_USER_CREATE", "admin"),
        ("ADMIN_LOGS_CLEAR", "admin"),
    ],
)
def test_every_known_status_lands_in_the_right_category(status, category):
    assert classify(status)["category"] == category


def test_a_valid_pin_that_did_not_open_the_door_is_not_a_wrong_pin():
    """FAILURE means Home Assistant failed after a valid PIN; AUTH_FAILURE is the wrong PIN."""
    assert classify("FAILURE")["label"].startswith("Open failed")
    assert classify("AUTH_FAILURE")["label"] == "Wrong PIN"
    assert classify("FAILURE")["severity"] == "bad" and classify("AUTH_FAILURE")["severity"] == "warn"


def test_unknown_statuses_are_still_shown_not_dropped():
    assert classify("ADMIN_SOMETHING_NEW") == {"category": "admin", "label": "Something new", "severity": "info"}
    assert classify("WHATEVER_ELSE")["category"] == "system"
    assert classify(None)["label"] == "Unknown"


def test_every_status_the_app_writes_is_classified():
    """Guard: a status added to app.py without an entry here would silently show as a generic row."""
    import re

    src = open("app.py", encoding="utf-8").read()
    written = set(re.findall(r'log_attempt\(\s*"([A-Z_]+)"', src)) | set(
        re.findall(r'"status": "([A-Z_]+)",\s*"details"', src)
    )
    assert written, "no statuses found: the pattern is out of date"
    assert written <= set(log_events.STATUS_INFO), written - set(log_events.STATUS_INFO)


def test_entry_normalises_unknown_user_and_flags_test_mode():
    e = entry_from_raw(
        {
            "timestamp": "t",
            "ip": "1.1.1.1",
            "user": "UNKNOWN",
            "status": "SUCCESS",
            "details": "Door opened (TEST MODE)",
        }
    )
    assert e["user"] is None and e["test"] is True and e["category"] == "door"


# --- parsing -------------------------------------------------------------------------------


def test_parses_json_lines_with_and_without_a_logging_prefix_and_the_old_format():
    lines = [
        line("SUCCESS", user="alice"),
        "2026-11-18 15:00:00,123 - " + line("AUTH_FAILURE"),
        "2026-11-18 15:00:00 - 1.2.3.4 - bob - SUCCESS - Door opened",
        "not a log line at all",
        "",
    ]
    entries = read_entries(lines)
    assert [e["status"] for e in entries] == ["SUCCESS", "AUTH_FAILURE", "SUCCESS"]
    assert entries[2]["user"] == "bob" and entries[2]["ip"] == "1.2.3.4"


# --- statistics ----------------------------------------------------------------------------


def test_empty_log_gives_zeros_and_no_division_errors():
    s = stats([])
    assert s["entries"] == 0 and s["first"] is None
    assert s["door"]["attempts"] == 0 and s["door"]["success_rate"] is None
    assert s["door"]["busiest_hour"] is None and s["door"]["last_open"] is None
    assert len(s["door"]["daily"]) == 14 and len(s["door"]["hourly"]) == 24
    assert all(sum(row) == 0 for row in s["door"]["heatmap"])


def test_admin_actions_are_not_counted_as_door_attempts():
    """The old dashboard counted every line as an attempt, so an admin login was a 'failed attempt'."""
    s = stats([line("ADMIN_SUCCESS", user="ADMIN"), line("ADMIN_USER_CREATE", user="ADMIN"), line("SUCCESS", user="a")])
    assert s["door"]["attempts"] == 1 and s["door"]["opens"] == 1 and s["door"]["success_rate"] == 100.0
    assert s["categories"] == {"door": 1, "security": 0, "admin": 2, "system": 0}


def test_door_counts_and_success_rate():
    s = stats(
        [
            line("SUCCESS", user="a"),
            line("SUCCESS", user="a"),
            line("SUCCESS", user="b"),
            line("AUTH_FAILURE"),
            line("DISABLED_USER", user="c"),
            line("FAILURE", user="a"),
        ]
    )
    d = s["door"]
    assert (d["opens"], d["denied"], d["faults"], d["attempts"]) == (3, 2, 1, 6)
    assert d["success_rate"] == 50.0 and d["unique_users"] == 2
    assert [u["user"] for u in d["top_users"]] == ["a", "b"] and d["top_users"][0]["opens"] == 2


def test_blocks_are_security_events_not_failed_attempts():
    s = stats([line("SUCCESS", user="a"), line("IP_BLOCKED"), line("SESSION_BLOCKED"), line("GLOBAL_THRESHOLD")])
    assert s["door"]["attempts"] == 1
    assert s["security"]["blocks"] == 3 and s["security"]["by_type"]["IP_BLOCKED"] == 1


def test_test_mode_entries_are_kept_out_of_real_statistics():
    s = stats([line("SUCCESS", user="a", details="Door opened (TEST MODE)"), line("SUCCESS", user="a")])
    assert s["door"]["opens"] == 1 and s["test_mode_entries"] == 1


def test_time_windows_use_the_configured_timezone():
    # 23:30 on the 17th in UTC+2 is 21:30 UTC; both are still "yesterday" relative to NOW (15:00 on the 18th)
    late = datetime(2026, 11, 17, 23, 30, tzinfo=TZ)
    utc_stamp = late.astimezone(timezone.utc)  # same instant, written in UTC
    s = stats([line("SUCCESS", ts=utc_stamp, user="a"), line("SUCCESS", ts=NOW, user="a")])
    assert s["door"]["opens_today"] == 1 and s["door"]["opens_7d"] == 2
    by_date = {d["date"]: d["opens"] for d in s["door"]["daily"]}
    assert by_date["2026-11-17"] == 1 and by_date["2026-11-18"] == 1


def test_windows_exclude_old_entries():
    old = NOW - timedelta(days=45)
    s = stats([line("SUCCESS", ts=old, user="a"), line("SUCCESS", ts=NOW - timedelta(days=10), user="a")])
    assert s["door"]["opens"] == 2 and s["door"]["opens_30d"] == 1 and s["door"]["opens_7d"] == 0


def test_hour_weekday_and_heatmap():
    wed_9 = NOW.replace(hour=9)
    fri_9 = (NOW + timedelta(days=2)).replace(hour=9)
    s = stats(
        [line("SUCCESS", ts=wed_9, user="a"), line("SUCCESS", ts=wed_9, user="b"), line("SUCCESS", ts=fri_9, user="a")]
    )
    d = s["door"]
    assert d["busiest_hour"] == {"hour": 9, "count": 3}
    assert d["busiest_weekday"] == {"weekday": "Wednesday", "count": 2}
    assert d["heatmap"][2][9] == 2 and d["heatmap"][4][9] == 1  # Mon=0 -> Wed=2, Fri=4


def test_last_open_is_the_most_recent_not_the_last_line():
    s = stats([line("SUCCESS", ts=NOW, user="late"), line("SUCCESS", ts=NOW - timedelta(hours=5), user="early")])
    assert s["door"]["last_open"]["user"] == "late"


def test_sso_opens_are_counted():
    s = stats([line("SUCCESS", user="a", details="Door opened via OIDC"), line("SUCCESS", user="a")])
    assert s["door"]["via_sso"] == 1


def test_average_per_day_spans_the_active_period():
    s = stats([line("SUCCESS", ts=NOW - timedelta(days=3), user="a")] + [line("SUCCESS", ts=NOW, user="a")] * 7)
    assert s["door"]["avg_per_day"] == 2.0  # 8 opens over 4 days


def test_top_ips_combine_denials_blocks_and_failed_admin_logins():
    s = stats(
        [line("AUTH_FAILURE", ip="6.6.6.6")] * 3
        + [line("IP_BLOCKED", ip="6.6.6.6"), line("ADMIN_FAILURE", ip="6.6.6.6"), line("AUTH_FAILURE", ip="7.7.7.7")]
    )
    top = s["security"]["top_ips"]
    assert top[0] == {"ip": "6.6.6.6", "denied": 3, "blocked": 1, "admin_failed": 1, "total": 5}
    assert top[1]["ip"] == "7.7.7.7"


def test_blocks_in_the_last_24_hours():
    s = stats([line("IP_BLOCKED", ts=NOW - timedelta(hours=2)), line("IP_BLOCKED", ts=NOW - timedelta(days=3))])
    assert s["security"]["blocks"] == 2 and s["security"]["blocks_24h"] == 1


def test_admin_summary_and_recent_activity():
    s = stats(
        [
            line("ADMIN_SUCCESS", ts=NOW - timedelta(hours=1), user="ADMIN"),
            line("ADMIN_FAILURE", ts=NOW - timedelta(hours=3), user="ADMIN"),
            line("ADMIN_USER_CREATE", ts=NOW - timedelta(minutes=5), user="ADMIN", details="username=carol"),
        ]
    )
    a = s["admin"]
    assert (a["logins"], a["failed_logins"], a["changes"]) == (1, 1, 1)
    assert a["last_login"]["timestamp"].startswith("2026-11-18T14:00")
    assert [r["label"] for r in a["recent"]] == [
        "User created",
        "Admin login failed",
    ]  # newest first; successful logins omitted


def test_system_errors_and_last_error():
    s = stats(
        [
            line(
                "FAILURE", ts=NOW - timedelta(days=2), user="a", details="Home Assistant unreachable (ConnectTimeout)"
            ),
            line("EXCEPTION", ts=NOW - timedelta(days=20)),
        ]
    )
    sy = s["system"]
    assert sy["errors"] == 2 and sy["errors_7d"] == 1
    assert "unreachable" in sy["last_error"]["details"]
    assert s["door"]["faults"] == 2


def test_entries_with_unparseable_timestamps_still_count_but_do_not_break_buckets():
    s = stats([line("SUCCESS", user="a").replace(NOW.isoformat(), "garbage")])
    assert s["door"]["opens"] == 1 and s["door"]["opens_today"] == 0 and s["first"] is None
