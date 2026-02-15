"""Home Assistant API client."""

import logging

import requests

import config

logger = logging.getLogger("dooropener")


class HAClient:
    """Thin wrapper around the HA REST API.

    Configuration values (``entity_id``, ``ha_url``, etc.) are read from
    the ``config`` module at call time so that tests can monkeypatch them.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = config.ha_ca_bundle if config.ha_ca_bundle else True
        self.session.headers.update(
            {
                "Authorization": f"Bearer {config.ha_token}",
                "Content-Type": "application/json",
            }
        )

    def trigger_entity(self) -> dict:
        """Call the correct HA service to open the door.

        Returns ``{"success": bool, "error": str|None, "status_code": int}``.
        """
        eid = config.entity_id
        if eid.startswith("lock."):
            service = "lock/unlock"
        elif eid.startswith("input_boolean."):
            service = "input_boolean/turn_on"
        else:
            service = "switch/turn_on"

        url = f"{config.ha_url}/api/services/{service}"
        try:
            resp = self.session.post(
                url, json={"entity_id": eid}, timeout=10
            )
            resp.raise_for_status()
            return {"success": True, "error": None, "status_code": resp.status_code}
        except requests.RequestException as exc:
            logger.error("HA API error: %s", exc)
            code = getattr(getattr(exc, "response", None), "status_code", 502)
            return {
                "success": False,
                "error": "Failed to contact Home Assistant",
                "status_code": code,
            }

    def get_battery_level(self) -> int | None:
        """Fetch battery percentage (0-100) or ``None``."""
        try:
            resp = self.session.get(
                f"{config.ha_url}/api/states/{config.battery_entity}",
                timeout=10,
            )
            if resp.status_code != 200:
                logger.error("Battery fetch HTTP %s", resp.status_code)
                return None
            state = resp.json().get("state")
            if state is not None:
                level = float(state)
                if 0 <= level <= 100:
                    return int(level)
        except Exception as exc:
            logger.warning("Battery fetch error: %s", exc)
        return None
