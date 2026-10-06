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
