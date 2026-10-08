"""The app must not run with placeholder signing keys or well-known admin passwords."""

import pytest


@pytest.fixture
def app_module():
    import app as app_module

    return app_module


def test_weak_secret_rejected(app_module):
    for bad in ("your-secret-key-here", "change-me-to-something-long-and-random", "short"):
        with pytest.raises(RuntimeError):
            app_module._reject_weak_secret(bad, "FLASK_SECRET_KEY")
    app_module._reject_weak_secret("a" * 32, "FLASK_SECRET_KEY")


def test_insecure_override_allows_weak_secret(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "_ALLOW_INSECURE", True)
    app_module._reject_weak_secret("short", "FLASK_SECRET_KEY")


def test_example_files_ship_only_rejected_placeholders(app_module):
    import configparser
    import os

    root = os.path.join(os.path.dirname(__file__), "..")
    cfg = configparser.RawConfigParser()
    cfg.read(os.path.join(root, "config.ini.example"))
    assert cfg.get("admin", "admin_password").lower() in app_module._PLACEHOLDER_ADMIN_PASSWORDS
    env = {k: v for k, _, v in (ln.partition("=") for ln in open(os.path.join(root, ".env.example")) if "=" in ln)}
    assert env["FLASK_SECRET_KEY"].strip() == ""


def test_admin_password_hash_supported(app_module, monkeypatch):
    from werkzeug.security import generate_password_hash

    monkeypatch.setattr(app_module, "admin_password", generate_password_hash("s3cret-é"))
    assert app_module.verify_admin_password("s3cret-é")
    assert not app_module.verify_admin_password("nope")


def test_plaintext_admin_password_with_non_ascii(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "admin_password", "pässwörd-1")
    assert app_module.verify_admin_password("pässwörd-1")
    assert not app_module.verify_admin_password("passwoerd-1")


def test_hash_of_a_default_admin_password_is_detected(app_module, monkeypatch):
    from werkzeug.security import generate_password_hash

    monkeypatch.setattr(app_module, "admin_password", generate_password_hash("admin123"))
    assert app_module._admin_password_is_default()
    monkeypatch.setattr(app_module, "admin_password", generate_password_hash("a-genuinely-strong-one"))
    assert not app_module._admin_password_is_default()


def test_readme_admin_example_is_a_rejected_placeholder(app_module):
    """The README line is copy-pasted; ConfigParser would keep any inline '# ...' as part of the value."""
    import os
    import re

    text = open(os.path.join(os.path.dirname(__file__), "..", "README.md")).read()
    values = re.findall(r"^admin_password = (.*)$", text, flags=re.M)
    assert values
    assert all(v.strip().lower() in app_module._PLACEHOLDER_ADMIN_PASSWORDS for v in values)


def test_startup_rejects_the_shipped_example_config(tmp_path):
    """End to end: copy config.ini.example verbatim and boot the app, as a careless operator would.

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
    shutil.copy(os.path.join(root, "config.ini.example"), work / "config.ini")

    # Drop pytest-cov's env vars so this throwaway copy isn't measured (see test_config_percent).
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV_CORE", "COVERAGE", "DOOROPENER_ALLOW"))}
    env.update(
        DOOROPENER_LOG_DIR=str(tmp_path / "logs"),
        USERS_STORE_PATH=str(tmp_path / "u.json"),
        FLASK_SECRET_KEY="x" * 32,
    )
    code = f"import sys; sys.path.insert(0, {str(work)!r}); import app"

    rejected = subprocess.run([sys.executable, "-I", "-c", code], cwd=work, env=env, capture_output=True, text=True)
    assert rejected.returncode != 0
    assert "well-known default" in rejected.stderr

    allowed = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=work,
        env={**env, "DOOROPENER_ALLOW_INSECURE_DEFAULTS": "true"},
        capture_output=True,
        text=True,
    )
    assert allowed.returncode == 0, allowed.stderr[-1500:]
