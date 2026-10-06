"""Crash-safe file replacement shared by the users store and config writer."""

import os
import shutil
import tempfile


def atomic_write_text(path: str, content: str) -> None:
    """Write ``content`` to ``path`` without ever leaving it truncated or half-written.

    Prefers a temp file next to the target (same filesystem, so ``os.replace`` is atomic).
    Falls back to /tmp when the target directory can't take a new file (e.g. /app is
    root-owned while the app runs unprivileged), and when the target is a single-file
    Docker bind mount (``os.replace`` fails with EBUSY/EXDEV) it backs up the existing
    file, overwrites in place, and restores the backup if that write fails partway.

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
            backup_path = path + ".bak"
            has_existing = os.path.exists(path)
            if has_existing:
                shutil.copy2(path, backup_path)
            try:
                with open(path, "w", encoding="utf-8") as dst:
                    dst.write(content)
                    dst.flush()
                    os.fsync(dst.fileno())
            except Exception:
                if has_existing:
                    shutil.copy2(backup_path, path)
                raise
            finally:
                if has_existing:
                    try:
                        os.remove(backup_path)
                    except OSError:
                        pass
            os.remove(tmp_path)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
