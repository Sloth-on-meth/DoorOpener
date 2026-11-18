"""A full disk must fail a save cleanly, never empty users.json or lose its backup."""

import errno
import os
import subprocess
from unittest.mock import patch

import pytest

import atomic_io
from atomic_io import atomic_write_text, backup_files
from users_store import UsersStore, UsersStoreError


def _force_fallback():
    return patch("atomic_io.os.replace", side_effect=OSError(errno.EBUSY, "busy"))


def _fake_statvfs(free_bytes):
    class St:
        f_frsize = 1
        f_bavail = free_bytes

    return patch("atomic_io.os.statvfs", return_value=St())


def test_full_disk_leaves_existing_file_untouched(tmp_path):
    target = tmp_path / "users.json"
    target.write_text("ORIGINAL")
    with _force_fallback(), _fake_statvfs(10), pytest.raises(OSError) as exc:
        atomic_write_text(str(target), "x" * 5000)
    assert exc.value.errno == errno.ENOSPC
    assert target.read_text() == "ORIGINAL"
    assert list(tmp_path.glob("*.bak")) == []
    assert list(tmp_path.glob("*.tmp")) == []


def test_backup_is_kept_in_backup_dir(tmp_path):
    target = tmp_path / "users.json"
    target.write_text("ORIGINAL")
    keep = tmp_path / "logs"
    real_open = open

    def failing_open(p, mode="r", *a, **k):
        if str(p) == str(target) and "w" in mode:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(p, mode, *a, **k)

    real_copy = atomic_io.shutil.copyfile

    def copy_fail_on_restore(src, dst):
        if str(dst) == str(target):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_copy(src, dst)

    with _force_fallback(), patch("builtins.open", failing_open), patch(
        "atomic_io.shutil.copyfile", copy_fail_on_restore
    ), pytest.raises(OSError, match="preserved in"):
        atomic_write_text(str(target), "NEW", backup_dir=str(keep))
    kept = backup_files(str(target), str(keep))
    assert len(kept) == 1 and open(kept[0]).read() == "ORIGINAL"


def test_backup_removed_after_successful_fallback_write(tmp_path):
    target = tmp_path / "users.json"
    target.write_text("ORIGINAL")
    keep = tmp_path / "logs"
    with _force_fallback():
        atomic_write_text(str(target), "NEW", backup_dir=str(keep))
    assert target.read_text() == "NEW"
    assert backup_files(str(target), str(keep)) == []


def test_empty_store_with_retained_backup_fails_closed(tmp_path):
    path = tmp_path / "users.json"
    path.write_text("")
    keep = tmp_path / "logs"
    keep.mkdir()
    (keep / "users.json.abc.bak").write_text('{"users": {}}')
    store = UsersStore(str(path), backup_dir=str(keep))
    with pytest.raises(UsersStoreError, match="backup"):
        store.list_users()
    assert path.read_text() == ""


def test_empty_store_without_backup_is_still_fresh(tmp_path):
    path = tmp_path / "users.json"
    path.write_text("")
    store = UsersStore(str(path), backup_dir=str(tmp_path / "logs"))
    assert store.list_users() == {"users": []}


def _mount_tiny_tmpfs(path):
    os.makedirs(path, exist_ok=True)
    r = subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64k", "tmpfs", path], capture_output=True)
    return r.returncode == 0


def test_real_full_disk(tmp_path):
    mnt = str(tmp_path / "tiny")
    if not _mount_tiny_tmpfs(mnt):
        pytest.skip("cannot mount a tmpfs here")
    try:
        target = os.path.join(mnt, "users.json")
        with open(target, "w") as f:
            f.write("ORIGINAL")
        with open(os.path.join(mnt, "filler"), "wb") as f:
            try:
                f.write(b"0" * (1024 * 1024))
            except OSError:
                pass
        with _force_fallback(), pytest.raises(OSError):
            atomic_write_text(target, "y" * 20000)
        assert open(target).read() == "ORIGINAL"
    finally:
        subprocess.run(["umount", mnt], capture_output=True)
