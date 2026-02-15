import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional


ISO_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UsersStore:
    """JSON-backed user store with cached reverse PIN lookup.

    - JSON schema:
      {
        "users": {
          "alice": {"pin": "1234", "active": true, "created_at": "...", "updated_at": "...", "last_used_at": null}
        }
      }
    - Maintains a cached ``{pin: username}`` reverse map, invalidated on any CRUD operation.
    """

    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Any] = {"users": {}}
        self._loaded = False
        self._pin_cache: Dict[str, str] | None = None  # pin -> username

    def _load_file(self) -> None:
        if self._loaded:
            return
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                    if "users" not in self.data or not isinstance(
                        self.data["users"], dict
                    ):
                        self.data = {"users": {}}
            else:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                self.data = {"users": {}}
        except Exception:
            self.data = {"users": {}}
        finally:
            self._loaded = True
            self._pin_cache = None  # invalidate on load

    def _save_atomic(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        self._pin_cache = None  # invalidate on write

    def _invalidate_cache(self) -> None:
        self._pin_cache = None

    def get_pin_map(self) -> Dict[str, str]:
        """Return cached ``{pin: username}`` dict of active users."""
        self._ensure_loaded()
        if self._pin_cache is not None:
            return self._pin_cache
        result: Dict[str, str] = {}
        for user, meta in self.data.get("users", {}).items():
            if not bool(meta.get("active", True)):
                continue
            pin = meta.get("pin")
            if isinstance(pin, str) and 4 <= len(pin) <= 8 and pin.isdigit():
                result[pin] = user
        self._pin_cache = result
        return result

    def lookup_pin(self, pin: str) -> str | None:
        """Return username for *pin*, or ``None`` if no match."""
        return self.get_pin_map().get(pin)

    def list_users(self, include_pins: bool = False) -> Dict[str, Any]:
        self._ensure_loaded()
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

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load_file()

    @staticmethod
    def _validate_username(username: str) -> bool:
        if not isinstance(username, str) or not (1 <= len(username) <= 32):
            return False
        allowed = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
        )
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

    def update_user(
        self, username: str, pin: Optional[str] = None, active: Optional[bool] = None
    ) -> None:
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
            self.data["users"][username]["times_used"] = (
                self.data["users"][username].get("times_used", 0) + 1
            )
            self._save_atomic()

    def user_exists(self, username: str) -> bool:
        self._ensure_loaded()
        return username in self.data["users"]
