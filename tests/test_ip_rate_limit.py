"""Rate limits must key on the client IP, not on headers the client controls."""

import pytest

HEADERS = {"User-Agent": "pytest-client/1.0 (+https://example.test)", "Content-Type": "application/json"}


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


@pytest.fixture
def client(app_module):
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def test_identifier_ignores_user_agent_and_language(app_module):
    seen = set()
    for i in range(5):
        with app_module.app.test_request_context(
            "/", headers={"User-Agent": f"agent-number-{i}", "Accept-Language": f"xx-{i}"}
        ):
            seen.add(app_module.get_client_identifier()[2])
    assert len(seen) == 1


def test_rotating_user_agent_still_gets_blocked(client, app_module):
    app_module.test_mode = True
    statuses = []
    for i in range(app_module.MAX_ATTEMPTS + 1):
        client.delete_cookie("session")  # also drop the cookie so only the IP can throttle
        h = {**HEADERS, "User-Agent": f"rotating-agent-{i}-padding", "Accept-Language": f"l{i}"}
        statuses.append(client.post("/open-door", json={"pin": "0000"}, headers=h).status_code)
    assert statuses[-1] == 429


def test_env_override_wins_even_if_ini_value_is_invalid(tmp_path):
    """DOOROPENER_TRUSTED_PROXIES must be selected before the INI value is parsed.

    conftest mocks ConfigParser, so run the real thing in a subprocess against a throwaway copy.
    """
    import os
    import shutil
    import subprocess
    import sys

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    work = tmp_path / "app"
    work.mkdir()
    for name in os.listdir(root):
        if name.endswith(".py"):
            shutil.copy(os.path.join(root, name), work / name)
    for d in ("templates", "static"):
        shutil.copytree(os.path.join(root, d), work / d)
    (work / "config.ini").write_text(
        "[HomeAssistant]\nurl = http://x\ntoken = t\nswitch_entity = switch.d\n"
        "[admin]\nadmin_password = a-real-password\n[server]\ntrusted_proxies = not-a-number\n"
    )
    env = {**os.environ, "DOOROPENER_LOG_DIR": str(tmp_path / "logs"), "USERS_STORE_PATH": str(tmp_path / "u.json")}
    code = f"import sys; sys.path.insert(0, {str(work)!r}); import app; print(app.TRUSTED_PROXIES)"

    ok = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=work,
        env={**env, "DOOROPENER_TRUSTED_PROXIES": "0"},
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0, ok.stderr[-1500:]
    assert ok.stdout.strip().endswith("0")
