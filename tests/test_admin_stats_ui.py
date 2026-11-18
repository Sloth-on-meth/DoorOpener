"""Admin statistics UI: rendering helpers, the log category chips, and the CSP rule for styles."""

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _read(*parts):
    return open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def _node(script, payload=None):
    res = subprocess.run(
        ["node", "-e", script], input=json.dumps(payload or {}), capture_output=True, text=True, timeout=30
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


HELPERS = r"""
const api = require(process.cwd() + '/static/admin-stats.js');
const { run } = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {};
for (const [k, [fn, ...args]] of Object.entries(run)) out[k] = api[fn](...args);
console.log(JSON.stringify(out));
"""


@needs_node
def test_pure_helpers():
    now_dt = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
    now = int(now_dt.timestamp() * 1000)

    def iso(seconds_ago):
        return (now_dt - timedelta(seconds=seconds_ago)).isoformat()

    out = _node(
        HELPERS,
        {
            "run": {
                "hour": ["fmtHour", 7],
                "just": ["ago", iso(10), now],
                "min": ["ago", iso(5 * 60), now],
                "hours": ["ago", iso(3 * 3600), now],
                "days": ["ago", iso(2 * 86400), now],
                "bad": ["ago", "not a date", now],
                "one": ["plural", 1, "denial", "denials"],
                "many": ["plural", 3, "denial", "denials"],
                "zero": ["plural", 0, "denial", "denials"],
                "esc": ["esc", '<img src=x onerror="a">&\''],
                "empty_heat": ["heatAlpha", 0, 10],
                "full_heat": ["heatAlpha", 10, 10],
                "mid_heat": ["heatAlpha", 5, 10],
                "no_max": ["heatAlpha", 3, 0],
                "day": ["dayLabel", "2026-11-18"],
            }
        },
    )
    assert out["hour"] == "07:00"
    assert (out["just"], out["min"], out["hours"], out["days"], out["bad"]) == (
        "just now",
        "5 min ago",
        "3 h ago",
        "2 d ago",
        "",
    )
    assert (out["one"], out["many"], out["zero"]) == ("1 denial", "3 denials", "0 denials")
    assert "<" not in out["esc"] and "&lt;img" in out["esc"] and "&quot;" in out["esc"] and "&#39;" in out["esc"]
    assert out["empty_heat"] == 0.06 and out["full_heat"] == 1 and out["mid_heat"] == 0.6 and out["no_max"] == 0.06
    assert out["day"] == {"weekday": "Wed", "day": 18}


KPI = r"""
const api = require(process.cwd() + '/static/admin-stats.js');
const { stats } = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const els = {};
global.document = { getElementById: (id) => (els[id] = els[id] || { textContent: '' }) };
api.renderKpis(stats);
console.log(JSON.stringify(Object.fromEntries(Object.entries(els).map(([k, v]) => [k, v.textContent]))));
"""


def _stats(**door):
    base = {
        "opens": 0, "denied": 0, "faults": 0, "attempts": 0, "success_rate": None, "opens_today": 0,
        "opens_7d": 0, "opens_30d": 0, "busiest_hour": None, "busiest_weekday": None,
    }  # fmt: skip
    base.update(door)
    return {"door": base, "security": {"blocks": 0, "blocks_24h": 0}}


@needs_node
def test_kpis_for_an_empty_log_show_dashes_not_nan():
    out = _node(KPI, {"stats": _stats()})
    assert out["statRate"] == "—" and out["statBusy"] == "—"
    assert out["statRateSub"] == "no attempts yet" and out["statBusySub"] == "not enough data"
    assert "NaN" not in json.dumps(out) and "undefined" not in json.dumps(out)


@needs_node
def test_kpis_with_data():
    out = _node(
        KPI,
        {
            "stats": {
                **_stats(
                    opens=7,
                    denied=1,
                    faults=1,
                    attempts=9,
                    success_rate=77.78,
                    opens_today=2,
                    opens_7d=5,
                    opens_30d=7,
                    busiest_hour={"hour": 8, "count": 4},
                    busiest_weekday={"weekday": "Friday", "count": 3},
                ),  # fmt: skip
                "security": {"blocks": 5, "blocks_24h": 2},
            }
        },
    )
    assert out["statOpensToday"] == 2 and out["statOpensTodaySub"] == "7 days: 5 · 30 days: 7"
    assert out["statRate"] == "78%" and out["statRateSub"] == "1 denial · 1 fault"
    assert out["statBusy"] == "08:00" and out["statBusySub"] == "Fridays are busiest"
    assert out["statBlocked"] == 2 and out["statBlockedSub"] == "5 in total"


# --- the CSP forbids inline style attributes; they are dropped silently ----------------------


def _strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", src)


@pytest.mark.parametrize("name", ["admin.js", "admin-stats.js", "index.js"])
def test_scripts_never_emit_inline_style_attributes(name):
    """A style="..." in an HTML string is blocked by the Content-Security-Policy, so the element
    silently loses its colour/width. Set styles through el.style (CSSOM) instead."""
    code = _strip_comments(_read("static", name))
    assert not re.search(r"""style\s*=\s*["'\\]""", code), f"inline style attribute in {name}"


def test_templates_have_no_inline_style_attributes():
    for name in ("admin.html", "index.html"):
        html = re.sub(r"<style\b.*?</style>", "", _read("templates", name), flags=re.S)
        assert not re.search(r"""\sstyle\s*=""", html), name


# --- log categories --------------------------------------------------------------------------


def test_log_view_filters_by_category_and_labels_events():
    js = _read("static", "admin.js")
    assert "l.category === logCategory" in js
    assert "filterStatus" not in js and "filterStatus" not in _read("templates", "admin.html")
    html = _read("templates", "admin.html")
    for cat in ("", "door", "security", "admin", "system"):
        assert f'data-cat="{cat}"' in html
    assert 'class="chip active" data-cat="door" aria-pressed="true"' in html  # opens on the door events
    # severity drives the badge colour; the old binary success/failure badge is gone
    assert "badge-warn" in js and "badge-info" in js
    assert "'<span class=\"badge badge-failure\">Failure</span>'" not in js


def test_every_category_has_a_hint():
    js = _read("static", "admin.js")
    for cat in ("door", "security", "admin", "system"):
        assert re.search(rf"\b{cat}: '", js[js.index("CATEGORY_HINTS") :]), cat
