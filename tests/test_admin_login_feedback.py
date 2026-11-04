"""Issue #39: the admin page accepted the password and then silently showed the login form again.

That happens when the browser refuses to keep the session cookie (a Secure cookie on a plain-HTTP
page). The login page now confirms the session stuck and explains what to do if it did not, and
the server logs a warning on the first such login.
"""

import json
import logging
import os
import shutil
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# --- server side ------------------------------------------------------------------------------


@pytest.fixture
def app_module(monkeypatch):
    import app as app_module

    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    monkeypatch.setattr(app_module, "_warned_secure_cookie_over_http", False)
    return app_module


def _login(app_module, base_url="http://door.example"):
    client = app_module.app.test_client()
    return client.post("/admin/auth", json={"password": "testpass"}, base_url=base_url)


def _warnings(caplog):
    return [r for r in caplog.records if "plain HTTP" in r.getMessage()]


def test_warns_on_http_login_when_the_cookie_is_secure(app_module, caplog, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "SESSION_COOKIE_SECURE", True)
    with caplog.at_level(logging.WARNING, logger="dooropener"):
        assert _login(app_module).status_code == 200  # the login itself still works
    (record,) = _warnings(caplog)
    assert "SESSION_COOKIE_SECURE" in record.getMessage() and "X-Forwarded-Proto" in record.getMessage()


def test_warns_only_once_per_process(app_module, caplog, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "SESSION_COOKIE_SECURE", True)
    with caplog.at_level(logging.WARNING, logger="dooropener"):
        _login(app_module)
        _login(app_module)
    assert len(_warnings(caplog)) == 1


def test_no_warning_over_https(app_module, caplog, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "SESSION_COOKIE_SECURE", True)
    with caplog.at_level(logging.WARNING, logger="dooropener"):
        _login(app_module, base_url="https://door.example")
    assert _warnings(caplog) == []


def test_no_warning_when_the_cookie_is_not_secure(app_module, caplog, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "SESSION_COOKIE_SECURE", False)
    with caplog.at_level(logging.WARNING, logger="dooropener"):
        _login(app_module)
    assert _warnings(caplog) == []


def test_a_failed_login_does_not_warn(app_module, caplog, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "SESSION_COOKIE_SECURE", True)
    with caplog.at_level(logging.WARNING, logger="dooropener"):
        app_module.app.test_client().post("/admin/auth", json={"password": "wrong"}, base_url="http://door.example")
    assert _warnings(caplog) == []


# --- browser side: run the real login() from admin.html under Node ----------------------------

HARNESS = r"""
const fs = require('fs');
const { src, scenario } = JSON.parse(fs.readFileSync(0, 'utf8'));
const els = {
  adminPassword: { value: 'pw' },
  rememberMe: { checked: false },
  loginError: { style: { display: 'none' }, textContent: '' },
};
const document = { getElementById: (id) => els[id] };
let reloads = 0;
const window = {
  location: { protocol: scenario.protocol, hostname: scenario.hostname, reload: () => { reloads += 1; } },
};
const calls = [];
const fetch = async (url) => {
  calls.push(url);
  if (url === '/admin/auth') return { json: async () => scenario.auth };
  if (scenario.check === 'throw') throw new Error('network');
  return { json: async () => ({ authenticated: scenario.check }) };
};
const login = new Function('document', 'window', 'fetch', src + '; return login;')(document, window, fetch);
login().then(() => {
  const error = els.loginError.textContent;
  console.log(JSON.stringify({ reloads, error, shown: els.loginError.style.display, calls }));
});
"""


def _login_source():
    html = open(os.path.join(ROOT, "templates", "admin.html"), encoding="utf-8").read()
    start = html.index("async function login()")
    depth, i = 0, html.index("{", start)
    for j in range(i, len(html)):
        depth += {"{": 1, "}": -1}.get(html[j], 0)
        if depth == 0:
            return html[start : j + 1]
    raise AssertionError("login() not terminated")


def run_login(*, auth=None, check=True, protocol="http:", hostname="192.168.1.10"):
    scenario = {
        "auth": auth or {"status": "success"},
        "check": check,
        "protocol": protocol,
        "hostname": hostname,
    }
    res = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps({"src": _login_source(), "scenario": scenario}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@needs_node
def test_login_reloads_when_the_session_was_kept():
    out = run_login(check=True)
    assert out["reloads"] == 1 and out["error"] == ""
    assert out["calls"] == ["/admin/auth", "/admin/check-auth"]


@needs_node
def test_plain_http_non_localhost_gets_the_specific_explanation_and_no_reload():
    out = run_login(check=False, protocol="http:", hostname="192.168.1.10")
    assert out["reloads"] == 0 and out["shown"] == "block"
    for needle in ("Password accepted", "plain HTTP", "Secure", "SESSION_COOKIE_SECURE=false", "HTTPS"):
        assert needle in out["error"], needle


@needs_node
@pytest.mark.parametrize(
    "protocol, hostname", [("https:", "door.example"), ("http:", "localhost"), ("http:", "127.0.0.1")]
)
def test_other_origins_get_the_generic_cookie_hint(protocol, hostname):
    out = run_login(check=False, protocol=protocol, hostname=hostname)
    assert out["reloads"] == 0 and "did not keep the login session" in out["error"]
    assert "plain HTTP" not in out["error"] and "X-Forwarded-Proto" in out["error"]


@needs_node
def test_wrong_password_is_unchanged_and_makes_no_session_check():
    out = run_login(auth={"status": "error"})
    assert out["reloads"] == 0 and out["error"] == "Invalid admin password"
    assert out["calls"] == ["/admin/auth"]


@needs_node
def test_if_the_session_check_itself_fails_fall_back_to_the_normal_reload():
    out = run_login(check="throw")
    assert out["reloads"] == 1 and out["error"] == ""
