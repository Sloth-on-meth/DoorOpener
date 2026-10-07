"""PINs are ASCII digits only; non-ASCII input must fail cleanly, never raise."""

import pytest

from users_store import UsersStore, is_valid_pin, pins_equal

HEADERS = {"User-Agent": "pytest-client/1.0 (+https://example.test)", "Content-Type": "application/json"}


@pytest.mark.parametrize("pin", ["١٢٣٤", "²²²²", "１２３４", "123", "123456789", "12 4", None, 1234])
def test_is_valid_pin_rejects(pin):
    assert not is_valid_pin(pin)


def test_is_valid_pin_accepts_ascii_digits():
    assert is_valid_pin("1234") and is_valid_pin("12345678")


def test_pins_equal_handles_non_ascii():
    assert pins_equal("١٢٣٤", "١٢٣٤")
    assert not pins_equal("١٢٣٤", "1234")


def test_store_rejects_unicode_digit_pin(tmp_path):
    store = UsersStore(str(tmp_path / "users.json"))
    with pytest.raises(ValueError):
        store.create_user("u", "١٢٣٤")


def test_unicode_digit_pin_is_a_counted_400_not_a_500(client):
    import app as app_module

    r = client.post("/open-door", json={"pin": "٣٣٣٣"}, headers=HEADERS)
    assert r.status_code == 400
    assert sum(app_module.ip_failed_attempts.values()) == 1


def test_non_ascii_config_pin_does_not_break_other_logins(client):
    import app as app_module

    app_module.user_pins.update({"weird": "١٢٣٤", "ok": "4321"})
    assert client.post("/open-door", json={"pin": "4321"}, headers=HEADERS).status_code == 200
