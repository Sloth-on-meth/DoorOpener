"""Regression for #41: users.json bind-mounted as a single file inside a read-only /app.

The temp file falls back to /tmp, os.replace() fails across devices, and the in-place
fallback used to create users.json.bak next to the target, which raised PermissionError
and aborted every create/update/delete.
"""

import errno
import tempfile
from unittest.mock import patch

import pytest

from users_store import UsersStore


def _readonly_dir_env(target_dir, scratch):
    """Patches that emulate a root-owned dir holding only a writable, bind-mounted users.json.

    (The suite runs as root, so chmod can't really deny writes; deny them explicitly instead.)
    """
    real_mkstemp = tempfile.mkstemp
    real_copy2 = __import__("shutil").copy2
    created_in_target = []

    def mkstemp(dir=None, **kw):
        if dir == str(target_dir):
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_mkstemp(dir=str(scratch), **kw)

    def copy2(src, dst, **kw):
        if str(dst).startswith(str(target_dir)) and str(dst) != str(target_dir / "users.json"):
            created_in_target.append(str(dst))
            raise PermissionError(errno.EACCES, "Permission denied", str(dst))
        return real_copy2(src, dst, **kw)

    return created_in_target, [
        patch("users_store.tempfile.mkstemp", mkstemp),
        patch("users_store.os.replace", side_effect=OSError(errno.EXDEV, "cross-device link")),
        patch("users_store.shutil.copy2", copy2),
    ]


def test_edits_succeed_when_target_directory_cannot_take_new_files(tmp_path):
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    store = UsersStore(str(target_dir / "users.json"))
    store.create_user("alice", "1234")  # file exists before we simulate the read-only dir

    created, patches = _readonly_dir_env(target_dir, scratch)
    for p in patches:
        p.start()
    try:
        store.create_user("bob", "5678")
        store.update_user("alice", active=False)
        store.delete_user("bob")
        store.touch_user("alice")
    finally:
        for p in patches:
            p.stop()

    assert created == []  # nothing was created beside the target
    reread = UsersStore(str(target_dir / "users.json")).list_users()["users"]
    assert [(u["username"], u["active"]) for u in reread] == [("alice", False)]
    assert [p.name for p in target_dir.iterdir()] == ["users.json"]  # no stray .bak
    assert list(scratch.iterdir()) == []  # temp file and backup cleaned up


def test_failed_overwrite_restores_the_original_file(tmp_path):
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    store = UsersStore(str(target_dir / "users.json"))
    store.create_user("alice", "1234")
    before = (target_dir / "users.json").read_text()

    created, patches = _readonly_dir_env(target_dir, scratch)
    real_open = open

    def flaky_open(path, mode="r", *a, **kw):
        if str(path) == str(target_dir / "users.json") and mode == "w":
            real_open(path, mode, *a, **kw).close()  # truncates, like a disk filling up
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, mode, *a, **kw)

    for p in patches:
        p.start()
    try:
        with patch("builtins.open", flaky_open):
            with pytest.raises(OSError):
                store.update_user("alice", active=False)
    finally:
        for p in patches:
            p.stop()
    assert (target_dir / "users.json").read_text() == before


def test_backup_is_kept_when_restoring_it_also_fails(tmp_path):
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    store = UsersStore(str(target_dir / "users.json"))
    store.create_user("alice", "1234")
    before = (target_dir / "users.json").read_text()
    target = str(target_dir / "users.json")

    _, patches = _readonly_dir_env(target_dir, scratch)
    real_open = open
    real_copy2 = __import__("shutil").copy2

    def flaky_open(path, mode="r", *a, **kw):
        if str(path) == target and mode == "w":
            real_open(path, mode, *a, **kw).close()  # truncates, like a disk filling up
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, mode, *a, **kw)

    def copy2(src, dst, **kw):
        if str(dst) == target:  # the restore
            raise OSError(errno.EIO, "I/O error")
        return real_copy2(src, dst, **kw)

    # Start the env patches first, then layer ours on top so ours wins for copy2.
    for p in patches:
        p.start()
    try:
        with patch("builtins.open", flaky_open), patch("users_store.shutil.copy2", copy2):
            with pytest.raises(OSError):
                store.update_user("alice", active=False)
    finally:
        for p in patches:
            p.stop()

    backups = [p for p in scratch.iterdir() if p.suffix == ".bak"]
    assert len(backups) == 1 and backups[0].read_text() == before
