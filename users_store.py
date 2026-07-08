import hmac
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


class UsersStoreError(RuntimeError):
    """Raised when the on-disk users store cannot be safely read or written."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UsersStore:
    """JSON-backed user store with atomic writes and merge-over-config behavior.

    - JSON schema:
      {
        "users": {
          "alice": {"pin": "1234", "active": true, "created_at": "...", "updated_at": "...", "last_used_at": null}
        }
      }
    - Effective PINs: merge base_pins (from config.ini [pins]) with overrides/additions in JSON.
      If a username exists in JSON, it takes precedence (including active flag).
      Users only present in base_pins are considered active.
    """

    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Any] = {"users": {}}

    def _load_file(self) -> None:
        if not os.path.exists(self.path):
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self.data = {"users": {}}
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            raise UsersStoreError(f"Cannot read users store at {self.path}: {e}") from e
        if content.strip() == "":
            # A freshly-created/empty file (e.g. touch'd but never written) has no
            # data to lose, so it's safe to treat like a missing file.
            self.data = {"users": {}}
            return
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            # Do NOT fall back to {"users": {}} here. Every mutation loads then
            # immediately re-saves self.data, so treating a corrupt file as "no
            # users" would let the very next login or admin edit permanently
            # overwrite the real data with an empty store. Fail loudly instead
            # and leave the on-disk file untouched.
            raise UsersStoreError(f"Cannot parse users store at {self.path}: {e}") from e
        if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
            raise UsersStoreError(f"Users store at {self.path} has an unexpected format")
        self.data = data

    def _save_atomic(self) -> None:
        dir_path = os.path.dirname(self.path)
        os.makedirs(dir_path, exist_ok=True)
        # Prefer writing the temp file next to the target (same filesystem = atomic
        # rename). Fall back to /tmp when the app directory can't take a new file,
        # e.g. when users.json is a single-file Docker bind-mount, or the primary
        # filesystem is out of space/inodes.
        tmp_path = None
        for tmp_dir in (dir_path, tempfile.gettempdir()):
            try:
                fd, tmp_path = tempfile.mkstemp(dir=tmp_dir, suffix=".tmp")
                break
            except OSError:
                continue
        else:
            raise UsersStoreError(f"Cannot create temp file in {dir_path} or {tempfile.gettempdir()}")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            try:
                # Same filesystem: atomic rename, no window where the file is
                # missing or half-written.
                os.replace(tmp_path, self.path)
            except OSError:
                # Cross-device: os.replace() can't atomically rename here, so
                # back up the existing file before overwriting it. If the copy
                # below fails partway (disk fills up, process killed), restore
                # from the backup instead of leaving users.json truncated.
                backup_path = self.path + ".bak"
                has_existing = os.path.exists(self.path)
                if has_existing:
                    shutil.copy2(self.path, backup_path)
                try:
                    with open(tmp_path, "r", encoding="utf-8") as src:
                        content = src.read()
                    with open(self.path, "w", encoding="utf-8") as dst:
                        dst.write(content)
                        dst.flush()
                        os.fsync(dst.fileno())
                except Exception:
                    if has_existing:
                        shutil.copy2(backup_path, self.path)
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

    def effective_pins(self, base_pins: Dict[str, str]) -> Dict[str, str]:
        self._load_file()
        effective: Dict[str, str] = {}
        # Start with base pins (implicitly active)
        for user, pin in (base_pins or {}).items():
            effective[user] = pin
        # Apply JSON overrides/additions
        for user, meta in self.data.get("users", {}).items():
            active = bool(meta.get("active", True))
            if not active:
                # remove from effective if present
                if user in effective:
                    del effective[user]
                continue
            pin = meta.get("pin")
            if isinstance(pin, str) and 4 <= len(pin) <= 8 and pin.isdigit():
                effective[user] = pin
        return effective

    def list_users(self, include_pins: bool = False) -> Dict[str, Any]:
        self._load_file()
        items = []
        for user, meta in self.data.get("users", {}).items():
            item = {
                "username": user,
                "active": bool(meta.get("active", True)),
                "created_at": meta.get("created_at"),
                "updated_at": meta.get("updated_at"),
                "last_used_at": meta.get("last_used_at"),
                "times_used": meta.get("times_used", 0),
            }
            if include_pins:
                item["pin"] = meta.get("pin")
            items.append(item)
        return {"users": items}

    def _ensure_loaded(self):
        self._load_file()

    @staticmethod
    def _validate_username(username: str) -> bool:
        if not isinstance(username, str) or not (1 <= len(username) <= 32):
            return False
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
        return all(c in allowed for c in username)

    @staticmethod
    def _validate_pin(pin: str) -> bool:
        return isinstance(pin, str) and pin.isdigit() and 4 <= len(pin) <= 8

    def create_user(self, username: str, pin: str, active: bool = True) -> None:
        self._ensure_loaded()
        if not self._validate_username(username):
            raise ValueError("Invalid username")
        if not self._validate_pin(pin):
            raise ValueError("Invalid pin")
        if username in self.data["users"]:
            raise KeyError("User already exists")
        now = _now_iso()
        self.data["users"][username] = {
            "pin": pin,
            "active": bool(active),
            "created_at": now,
            "updated_at": now,
            "last_used_at": None,
            "times_used": 0,
        }
        self._save_atomic()

    def update_user(self, username: str, pin: Optional[str] = None, active: Optional[bool] = None) -> None:
        self._ensure_loaded()
        if username not in self.data["users"]:
            raise KeyError("User not found")
        if pin is not None and not self._validate_pin(pin):
            raise ValueError("Invalid pin")
        if active is not None:
            active = bool(active)
        meta = self.data["users"][username]
        if pin is not None:
            meta["pin"] = pin
        if active is not None:
            meta["active"] = active
        meta["updated_at"] = _now_iso()
        self._save_atomic()

    def delete_user(self, username: str) -> None:
        self._ensure_loaded()
        if username not in self.data["users"]:
            raise KeyError("User not found")
        del self.data["users"][username]
        self._save_atomic()

    def touch_user(self, username: str) -> None:
        self._ensure_loaded()
        if username in self.data["users"]:
            self.data["users"][username]["last_used_at"] = _now_iso()
            # Increment times_used counter, defaulting to 0 if not present (for existing users)
            self.data["users"][username]["times_used"] = self.data["users"][username].get("times_used", 0) + 1
            self._save_atomic()

    def user_exists(self, username: str) -> bool:
        self._ensure_loaded()
        return username in self.data["users"]

    def find_disabled_user_by_pin(self, pin: str) -> Optional[str]:
        """Return the username of an inactive user whose PIN matches, or None."""
        self._ensure_loaded()
        for username, meta in self.data["users"].items():
            if not bool(meta.get("active", True)):
                stored_pin = meta.get("pin", "")
                if isinstance(stored_pin, str) and hmac.compare_digest(pin, stored_pin):
                    return username
        return None
