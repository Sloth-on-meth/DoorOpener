import copy
import hmac
import json
import os
from datetime import datetime, timezone
from functools import wraps
from inspect import isfunction
from threading import RLock
from typing import Any, Dict, Optional

from atomic_io import atomic_write_text

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


class UsersStoreError(RuntimeError):
    """Raised when the on-disk users store cannot be safely read or written."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_valid_pin(pin: Any) -> bool:
    """4-8 ASCII digits. str.isdigit() alone also accepts Unicode digits (e.g. Arabic-Indic),
    which hmac.compare_digest cannot compare."""
    return isinstance(pin, str) and pin.isascii() and pin.isdigit() and 4 <= len(pin) <= 8


def pins_equal(a: str, b: str) -> bool:
    """Constant-time PIN comparison that tolerates non-ASCII input instead of raising TypeError."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


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
        # Copy of the store as of the last successful read or write (None = never succeeded).
        self._last_good: Optional[Dict[str, Any]] = None

    def _remember_good(self) -> None:
        self._last_good = copy.deepcopy(self.data)

    def _load_file(self) -> None:
        self._read_store()
        self._remember_good()

    def _read_store(self) -> None:
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
        self._write_store()
        self._remember_good()

    def _write_store(self) -> None:
        try:
            atomic_write_text(self.path, json.dumps(self.data, ensure_ascii=False, indent=2))
        except OSError as e:
            # atomic_write_text does the temp-file / cross-device / backup / restore handling
            # (shared with config.ini) and puts the location of any retained backup in the message.
            raise UsersStoreError(f"Cannot write users store at {self.path}: {e}") from e

    @staticmethod
    def _merge(data: Dict[str, Any], base_pins: Dict[str, str]) -> Dict[str, str]:
        effective: Dict[str, str] = {}
        # Start with base pins (implicitly active)
        for user, pin in (base_pins or {}).items():
            effective[user] = pin
        # Apply JSON overrides/additions
        for user, meta in data.get("users", {}).items():
            active = bool(meta.get("active", True))
            if not active:
                # remove from effective if present
                if user in effective:
                    del effective[user]
                continue
            pin = meta.get("pin")
            if is_valid_pin(pin):
                effective[user] = pin
        return effective

    def effective_pins(self, base_pins: Dict[str, str]) -> Dict[str, str]:
        self._load_file()
        return self._merge(self.data, base_pins)

    def degraded_pins(self, base_pins: Dict[str, str]) -> Dict[str, str]:
        """PINs to honour when the store file can't be read.

        Falling back to config.ini alone would silently re-enable users disabled in the store and
        resurrect config PINs that a store record replaced. Instead, re-derive the effective PINs
        from the last snapshot that was successfully read *or written* (so edits made since the
        last login are included). With no snapshot (unreadable since startup) fail closed rather
        than guess.
        """
        if self._last_good is None:
            return {}
        return self._merge(self._last_good, base_pins)

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
        return is_valid_pin(pin)

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
        """Return the username of an inactive user whose PIN matches, or None.

        Best-effort: an unreadable store yields None so a wrong PIN is still counted as an
        ordinary failure (rather than raising, which would skip the rate-limit counters).
        """
        try:
            self._ensure_loaded()
        except UsersStoreError:
            return None
        for username, meta in self.data["users"].items():
            if not bool(meta.get("active", True)):
                stored_pin = meta.get("pin", "")
                if isinstance(stored_pin, str) and pins_equal(pin, stored_pin):
                    return username
        return None

    def all_pins(self) -> set:
        """Every PIN held by a store user, active or not (a disabled user's PIN is still taken)."""
        self._ensure_loaded()
        return {m["pin"] for m in self.data["users"].values() if isinstance(m.get("pin"), str)}

    def pin_exists(self, pin: str, exclude_username: Optional[str] = None) -> bool:
        """Return True if the PIN is already assigned to any store user (excluding one username)."""
        self._ensure_loaded()
        for username, meta in self.data["users"].items():
            if exclude_username is not None and username == exclude_username:
                continue
            stored_pin = meta.get("pin", "")
            if isinstance(stored_pin, str) and stored_pin == pin:
                return True
        return False


def _locked(method):
    """Serialise a method on the store's re-entrant lock.

    Every operation is load -> mutate -> save on shared instance state, and gunicorn runs
    several threads. Without this, a touch_user() racing an admin edit can write back a stale
    snapshot and silently undo it (e.g. re-activate a user who was just disabled).
    """

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        # setdefault is atomic in CPython, so concurrent first calls end up sharing one lock.
        with self.__dict__.setdefault("_lock", RLock()):
            return method(self, *args, **kwargs)

    return wrapper


# Lock every public method. Done here rather than with a decorator on each def so that methods
# added later are protected by default and the method bodies above stay untouched.
for _name, _attr in list(vars(UsersStore).items()):
    if not _name.startswith("_") and isfunction(_attr):
        setattr(UsersStore, _name, _locked(_attr))
