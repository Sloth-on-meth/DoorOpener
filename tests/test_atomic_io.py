"""config.ini must never be left truncated or half-written."""

import os
from configparser import RawConfigParser
from unittest.mock import patch

import pytest

from atomic_io import atomic_write_text


def test_writes_content_and_leaves_no_temp_files(tmp_path):
    target = tmp_path / "config.ini"
    target.write_text("old")
    atomic_write_text(str(target), "new")
    assert target.read_text() == "new"
    assert [p.name for p in tmp_path.iterdir()] == ["config.ini"]


def test_creates_missing_file(tmp_path):
    target = tmp_path / "sub" / "config.ini"
    atomic_write_text(str(target), "x")
    assert target.read_text() == "x"


def test_bind_mount_fallback_overwrites_in_place(tmp_path):
    """os.replace() fails with EBUSY on a single-file Docker bind mount; fall back to in-place."""
    target = tmp_path / "config.ini"
    target.write_text("old")
    with patch("atomic_io.os.replace", side_effect=OSError("busy")):
        atomic_write_text(str(target), "new")
    assert target.read_text() == "new"
    assert [p.name for p in tmp_path.iterdir()] == ["config.ini"]


def test_failed_fallback_write_restores_original(tmp_path):
    target = tmp_path / "config.ini"
    target.write_text("precious")
    real_open = open

    def flaky_open(path, mode="r", *a, **kw):
        if str(path) == str(target) and mode == "w":
            f = real_open(path, mode, *a, **kw)  # truncates, like the real failure mode
            f.close()
            raise OSError("disk full")
        return real_open(path, mode, *a, **kw)

    with patch("atomic_io.os.replace", side_effect=OSError("busy")), patch("builtins.open", flaky_open):
        with pytest.raises(OSError):
            atomic_write_text(str(target), "new")
    assert target.read_text() == "precious"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.ini"]


def test_falls_back_to_system_tmp_when_target_dir_is_read_only(tmp_path):
    target = tmp_path / "config.ini"
    target.write_text("old")
    real_mkstemp = __import__("tempfile").mkstemp
    calls = []

    def mkstemp(dir=None, **kw):
        calls.append(dir)
        if dir == str(tmp_path):
            raise PermissionError("read-only dir")
        return real_mkstemp(dir=dir, **kw)

    with patch("atomic_io.tempfile.mkstemp", mkstemp):
        atomic_write_text(str(target), "new")  # os.replace across devices may fall back; either way content lands
    assert target.read_text() == "new"
    assert calls[0] == str(tmp_path) and len(calls) == 2


def test_save_config_uses_atomic_writer(tmp_path, monkeypatch):
    import app as app_module

    cfg = RawConfigParser()
    cfg.read_dict({"server": {"notice": "hello"}})
    path = tmp_path / "config.ini"
    path.write_text("old")
    monkeypatch.setattr(app_module, "config", cfg)
    monkeypatch.setattr(app_module, "config_path", str(path))
    app_module.save_config()
    assert "notice = hello" in path.read_text()
    assert os.listdir(tmp_path) == ["config.ini"]
