"""Crash-safe file replacement shared by the users store and config writer."""

import errno
import os
import shutil
import tempfile

# Headroom kept free on top of the new content before an in-place overwrite is attempted.
_FREE_SPACE_MARGIN = 4096


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _check_free_space(path: str, needed: int) -> None:
    """Raise ENOSPC *before* the live file is truncated if low space is detected.

    Advisory only: it samples free space and reserves nothing, so a concurrent writer can still
    fill the disk afterwards (the backup/restore below covers that). It stats the target itself,
    not its parent, because for a single-file bind mount they can be on different filesystems.
    """
    try:
        st = os.statvfs(path)
    except OSError:
        return  # can't tell; let the write itself decide
    free = st.f_bavail * st.f_frsize
    if free < needed + _FREE_SPACE_MARGIN:
        raise OSError(
            errno.ENOSPC,
            f"Not enough free space to safely rewrite {path} "
            f"({free} bytes free, {needed} needed); the file was left untouched",
        )


def backup_files(path: str, backup_dir: str) -> list:
    """Backups retained for ``path`` in ``backup_dir`` after a failed in-place write, newest first.

    A missing directory means none were kept; any other error (e.g. permissions) is raised rather
    than reported as "no backups", since that would let a caller wrongly treat the store as fresh.
    """
    prefix = os.path.basename(path) + "."
    try:
        names = os.listdir(backup_dir)
    except FileNotFoundError:
        return []
    found = [os.path.join(backup_dir, n) for n in names if n.startswith(prefix) and n.endswith(".bak")]
    return sorted(found, key=lambda f: (os.path.getmtime(f), f), reverse=True)


def atomic_write_text(path: str, content: str, backup_dir: str = None) -> None:
    """Write ``content`` to ``path`` without ever leaving it truncated or half-written.

    Prefers a temp file next to the target (same filesystem, so ``os.replace`` is atomic).
    Falls back to /tmp when the target directory can't take a new file (e.g. /app is
    root-owned while the app runs unprivileged), and when the target is a single-file
    Docker bind mount (``os.replace`` fails with EBUSY/EXDEV) it backs up the existing
    file, overwrites in place, and restores the backup if that write fails partway.

    Before the in-place overwrite it checks (advisory, not a reservation) that the filesystem has
    room for the new content, so a detected low-space condition fails the save without touching the
    existing file. ``backup_dir`` (a persistent, writable directory) is where the backup is kept;
    if given and the backup can't be created there, the save is aborted before the live file is
    opened. It defaults to the temp file's directory, which in a container is often ephemeral.
    A backup that couldn't be restored is never deleted.

    Raises OSError if no temp file can be created or the final write fails.
    """
    dir_path = os.path.dirname(path) or "."
    os.makedirs(dir_path, exist_ok=True)

    tmp_path = None
    for tmp_dir in (dir_path, tempfile.gettempdir()):
        try:
            fd, tmp_path = tempfile.mkstemp(dir=tmp_dir, suffix=".tmp")
            break
        except OSError:
            continue
    else:
        raise OSError(f"Cannot create temp file in {dir_path} or {tempfile.gettempdir()}")

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.replace(tmp_path, path)
        except OSError:
            # Back up beside the temp file, not at path + ".bak": the temp file's directory is
            # known to be writable (it may be /tmp when the target's directory is read-only).
            backup_path = None
            if os.path.exists(path):
                _check_free_space(path, len(content.encode("utf-8")))
                bdir = backup_dir or os.path.dirname(tmp_path)
                try:
                    os.makedirs(bdir, exist_ok=True)
                    bfd, backup_path = tempfile.mkstemp(dir=bdir, prefix=os.path.basename(path) + ".", suffix=".bak")
                except OSError as e:
                    # Never overwrite in place without a backup the recovery check can find.
                    raise OSError(
                        e.errno, f"Cannot create a backup in {bdir} (needed before rewriting {path}): {e.strerror or e}"
                    ) from e
                os.close(bfd)
                try:
                    # copyfile, not copy2: copy2 also copies permission bits, which would turn the
                    # 0600 backup (made by mkstemp) into a copy of the target's mode, e.g. a
                    # world-readable copy of config.ini (HA token, admin password) in /tmp.
                    shutil.copyfile(path, backup_path)
                except Exception:
                    _remove_quietly(backup_path)
                    raise
            try:
                with open(path, "w", encoding="utf-8") as dst:
                    dst.write(content)
                    dst.flush()
                    os.fsync(dst.fileno())
            except Exception:
                if backup_path:
                    # If restoring fails too, the backup is deliberately kept (it is then the only
                    # intact copy) and the error says where it is. copyfile keeps the target's mode.
                    try:
                        shutil.copyfile(backup_path, path)
                    except Exception as restore_err:
                        raise OSError(
                            f"Could not write {path} and could not restore it; "
                            f"the previous contents are preserved in {backup_path}"
                        ) from restore_err
                    _remove_quietly(backup_path)
                raise
            if backup_path:
                _remove_quietly(backup_path)
            os.remove(tmp_path)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
