"""Offline / server-error handling on the keypad page (real functions from static/index.js under Node)."""

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

HARNESS = r"""
const { src, scenario } = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const banner = { textContent: '', hidden: true };
const toasts = [];
const document = { getElementById: (id) => (id === 'offline-banner' ? banner : null) };
const navigator = { onLine: scenario.onLine };
const showStatus = (m, t) => toasts.push([m, t]);
const lib = new Function('document', 'navigator', 'showStatus',
  src + '; return { readDoorResponse, reportRequestError };')(document, navigator, showStatus);
(async () => {
  let out = {};
  if (scenario.kind === 'read') {
    const res = { status: scenario.status, json: scenario.json
      ? async () => scenario.json : async () => { throw new SyntaxError('not json'); } };
    try { out.parsed = await lib.readDoorResponse(res); }
    catch (e) { out.error = { kind: e.kind, status: e.status }; }
  } else {
    out.keep = lib.reportRequestError(scenario.error);
  }
  console.log(JSON.stringify({ ...out, banner, toasts }));
})();
"""


def _fn(js, name):
    start = js.index(f"function {name}(")
    i = js.index("{", start)
    depth = 0
    for j in range(i, len(js)):
        depth += {"{": 1, "}": -1}.get(js[j], 0)
        if depth == 0:
            return js[start : j + 1]
    raise AssertionError(name)


def run(**scenario):
    js = open(os.path.join(ROOT, "static", "index.js"), encoding="utf-8").read()
    src = "\n".join(_fn(js, n) for n in ("setOfflineBanner", "readDoorResponse", "reportRequestError"))
    src = 'const OFFLINE_MESSAGE = "You\'re offline.";\n' + src
    scenario.setdefault("onLine", True)
    res = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps({"src": src, "scenario": scenario}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


@needs_node
def test_a_json_answer_is_passed_through_even_when_it_is_a_denial():
    out = run(kind="read", status=401, json={"status": "error", "message": "Wrong PIN"})
    assert out["parsed"]["status"] == 401 and out["parsed"]["data"]["message"] == "Wrong PIN"


@needs_node
def test_a_non_json_proxy_error_is_a_server_problem_not_a_denial():
    out = run(kind="read", status=502)
    assert out["error"] == {"kind": "server", "status": 502}


@needs_node
def test_server_problem_shows_a_toast_with_the_status_and_keeps_the_pin():
    out = run(kind="report", error={"kind": "server", "status": 502})
    assert out["keep"] is True
    assert out["toasts"] and "502" in out["toasts"][0][0]
    assert out["banner"]["hidden"] is True


@needs_node
def test_no_connection_shows_the_banner_and_keeps_the_pin():
    out = run(kind="report", error={"message": "Failed to fetch"})
    assert out["keep"] is True and out["banner"]["hidden"] is False
    assert "reach the server" in out["banner"]["textContent"]


@needs_node
def test_browser_reporting_offline_gets_the_offline_wording():
    out = run(kind="report", error={"message": "Failed to fetch"}, onLine=False)
    assert out["banner"]["hidden"] is False and "offline" in out["banner"]["textContent"].lower()


def test_banner_markup_is_a_polite_live_region():
    html = open(os.path.join(ROOT, "templates", "index.html"), encoding="utf-8").read()
    assert 'id="offline-banner"' in html and 'aria-live="polite"' in html and 'role="status"' in html
