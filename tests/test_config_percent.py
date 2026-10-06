"""A '%' in config values must not break reading or saving config.

conftest replaces configparser.ConfigParser with a mock for every test, so the real parser
behaviour is exercised in a subprocess against a throwaway copy of the app.
"""

import os
import shutil
import subprocess
import sys
import textwrap

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CONFIG = """[HomeAssistant]
url = http://localhost:8123
token = dummy_test_token
switch_entity = switch.test_door

[admin]
admin_password = p%ss-w0rd-with-percent

[server]
test_mode = true
"""

SCRIPT = textwrap.dedent(
    """
    import app
    assert app.admin_password == "p%ss-w0rd-with-percent", app.admin_password
    app.app.config["TESTING"] = True
    c = app.app.test_client()
    assert c.post("/admin/auth", json={"password": "p%ss-w0rd-with-percent"}).status_code == 200
    token = c.get("/admin/check-auth").get_json()["csrf_token"]
    r = c.post("/admin/notice", json={"notice": "50% off"}, headers={"X-CSRF-Token": token})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert "50% off" in open(app.config_path).read()
    print("OK")
    """
)


def test_percent_in_password_and_notice_with_real_configparser(tmp_path):
    work = tmp_path / "app"
    work.mkdir()
    for name in os.listdir(ROOT):
        if name.endswith(".py") and name != "conftest.py":
            shutil.copy(os.path.join(ROOT, name), work / name)
    for d in ("templates", "static"):
        shutil.copytree(os.path.join(ROOT, d), work / d)
    (work / "config.ini").write_text(CONFIG)
    env = {
        **os.environ,
        "DOOROPENER_LOG_DIR": str(tmp_path / "logs"),
        "USERS_STORE_PATH": str(tmp_path / "users.json"),
        "FLASK_SECRET_KEY": "x" * 32,
        "DOOROPENER_ALLOW_INSECURE_DEFAULTS": "true",
    }
    out = subprocess.run(
        [sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(work)!r}); {SCRIPT}"],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip().endswith("OK")
