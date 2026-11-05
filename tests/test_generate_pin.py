"""The add-user form's random PIN generator: unique, unguessable, admin-only."""

import json
import os
import shutil
import subprocess
from types import SimpleNamespace

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def env(tmp_path, monkeypatch):
    import app as app_module
    from users_store import UsersStore

    store = UsersStore(str(tmp_path / "users.json"))
    monkeypatch.setattr(app_module, "users_store", store)
    monkeypatch.setattr(app_module, "user_pins", {"cfg": "246810"})
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    client = app_module.app.test_client()
    assert client.post("/admin/auth", json={"password": "testpass"}).status_code == 200
    token = client.get("/admin/check-auth").get_json()["csrf_token"]
    return SimpleNamespace(app=app_module, client=client, store=store, csrf={"X-CSRF-Token": token}, mp=monkeypatch)


def _generate(env, **params):
    return env.client.get("/admin/generate-pin", query_string=params)


# --- the generator ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pin, trivial",
    [
        ("1111", True),
        ("000000", True),
        ("1234", True),
        ("123456", True),
        ("0123", True),
        ("4321", True),
        ("98765432", True),
        ("1357", False),
        ("1212", False),
        ("120345", False),
        ("246810", False),
    ],
)
def test_trivial_pin_detection(env, pin, trivial):
    assert env.app._is_trivial_pin(pin) is trivial


def test_generated_pins_have_the_requested_length_and_are_digits(env):
    for length in range(4, 9):
        pin = env.app.generate_unused_pin(length, set())
        assert len(pin) == length and pin.isascii() and pin.isdigit()


def test_generator_never_returns_a_taken_or_trivial_pin(env):
    taken = {f"{n:04d}" for n in range(0, 10000, 2)}  # half the 4-digit space is taken
    for _ in range(300):
        pin = env.app.generate_unused_pin(4, taken)
        assert pin not in taken and not env.app._is_trivial_pin(pin)


def test_generator_is_random_and_uses_the_secrets_module(env):
    calls = []
    real = env.app.secrets.randbelow
    env.mp.setattr(env.app.secrets, "randbelow", lambda n: calls.append(n) or real(n))
    pins = {env.app.generate_unused_pin(6, set()) for _ in range(40)}
    assert calls and len(pins) > 30


@pytest.mark.parametrize("upper, taken", [(20, [0, 3, 4, 19]), (10, [0]), (10, [9]), (10, [3, 4, 5]), (6, [])])
def test_nth_free_number_matches_a_brute_force_listing(env, upper, taken):
    free = [n for n in range(upper) if n not in taken]
    assert [env.app._nth_free_number(taken, k) for k in range(len(free))] == free
    assert list(env.app._free_numbers(taken, upper)) == free


@pytest.mark.parametrize("length", [5, 6, 7, 8])
def test_the_one_free_pin_is_found_at_every_length(env, length):
    """A near-full space at lengths 6-8 used to return None after 1000 random misses."""
    free = "7391" + "0" * (length - 4)
    space_taken = {f"{n:0{length}d}" for n in range(10**length)} if length <= 5 else None
    if space_taken is not None:
        assert env.app.generate_unused_pin(length, space_taken - {free}) == free
        return
    # 10**6..10**8 entries would be too big to build: take every PIN in the first and last thousands
    # of the space plus a spread in between, and check the answer is free and uniformly reachable.
    taken = {f"{n:0{length}d}" for n in range(1000)} | {f"{n:0{length}d}" for n in range(10**length - 1000, 10**length)}
    seen = {env.app.generate_unused_pin(length, taken) for _ in range(200)}
    assert not (seen & taken) and len(seen) > 150


def test_every_free_pin_is_reachable_and_roughly_equally_likely(env):
    taken = {f"{n:04d}" for n in range(10000)} - {"2580", "7391", "4826"}
    counts = {}
    for _ in range(900):
        pin = env.app.generate_unused_pin(4, taken)
        counts[pin] = counts.get(pin, 0) + 1
    assert set(counts) == {"2580", "7391", "4826"}
    assert all(200 < c < 400 for c in counts.values()), counts  # ~300 each


def test_none_only_when_every_free_pin_is_trivial(env):
    nearly_full = {f"{n:04d}" for n in range(10000)}
    assert env.app.generate_unused_pin(4, nearly_full - {"1111", "1234"}) is None  # only trivial ones left
    assert env.app.generate_unused_pin(4, nearly_full - {"1111", "1234", "5073"}) == "5073"


def test_a_nearly_full_pin_space_still_yields_the_one_free_pin(env):
    every = {f"{n:04d}" for n in range(10000)}
    free = "7391"
    assert env.app.generate_unused_pin(4, every - {free}) == free


def test_no_pin_when_the_short_space_is_full(env):
    assert env.app.generate_unused_pin(4, {f"{n:04d}" for n in range(10000)}) is None


def test_invalid_length_is_rejected_by_the_generator(env):
    for bad in (3, 9, 0, -1):
        with pytest.raises(ValueError):
            env.app.generate_unused_pin(bad, set())


# --- the endpoint -----------------------------------------------------------------------------


def test_endpoint_requires_an_admin_session():
    import app as app_module

    anon = app_module.app.test_client()
    assert anon.get("/admin/generate-pin").status_code == 401


def test_default_is_six_digits_and_length_is_selectable(env):
    assert len(_generate(env).get_json()["pin"]) == 6
    for length in range(4, 9):
        body = _generate(env, length=length).get_json()
        assert len(body["pin"]) == length and body["length"] == length


@pytest.mark.parametrize("length", ["3", "9", "abc", "", "-4", "5.5"])
def test_bad_length_is_a_400(env, length):
    assert _generate(env, length=length).status_code == 400


def test_a_config_pin_is_excluded_even_when_it_is_the_only_one_that_looks_free(env):
    """Squeeze the 4-digit space until only three PINs are left; one of them is a config.ini PIN."""
    env.mp.setattr(env.app, "user_pins", {"cfg": "2468"})
    free = {"2468", "5937", "1593"}
    env.mp.setattr(env.app.users_store, "all_pins", lambda: {f"{n:04d}" for n in range(10000)} - free)
    seen = {_generate(env, length=4).get_json()["pin"] for _ in range(60)}
    assert seen == {"5937", "1593"}  # never 2468: it belongs to config user "cfg"


def test_real_store_and_config_pins_are_excluded(env):
    env.store.create_user("alice", "135792")
    env.store.create_user("gone", "975318", active=False)
    env.mp.setattr(env.app, "user_pins", {"cfg": "246810"})
    taken = env.app.users_store.all_pins() | set(env.app.user_pins.values())
    assert {"135792", "975318", "246810"} <= taken
    for _ in range(50):
        assert _generate(env).get_json()["pin"] not in taken


def test_a_generated_pin_can_create_a_user_and_is_then_taken(env):
    pin = _generate(env).get_json()["pin"]
    r = env.client.post("/admin/users", json={"username": "newbie", "pin": pin}, headers=env.csrf)
    assert r.status_code == 201
    assert pin in env.store.all_pins()
    again = {_generate(env).get_json()["pin"] for _ in range(30)}
    assert pin not in again


def test_exhausted_pin_space_is_a_409(env):
    env.mp.setattr(env.app.users_store, "all_pins", lambda: {f"{n:04d}" for n in range(10000)})
    r = _generate(env, length=4)
    assert r.status_code == 409 and "No unused PIN" in r.get_json()["error"]


def test_unreadable_store_refuses_rather_than_guessing(env):
    from users_store import UsersStoreError

    def boom():
        raise UsersStoreError("corrupt")

    env.mp.setattr(env.app.users_store, "all_pins", boom)
    r = _generate(env)
    assert r.status_code == 500 and "pin" not in r.get_json()


def test_the_response_is_not_cacheable(env):
    assert "no-store" in _generate(env).headers["Cache-Control"]


# --- the button (real fillGeneratedPin() from admin.html, run under Node) ----------------------

HARNESS = r"""
const fs = require('fs');
const { src, scenario } = JSON.parse(fs.readFileSync(0, 'utf8'));
const els = {
  '#um_pin': { value: '', type: 'password' },
  '#um_pin_hint': { textContent: '' },
  '#um_pinlen': { value: scenario.length },
  '#modalOk': { disabled: false },
};
const card = { querySelector: (sel) => els[sel] };
const calls = [];
const fetch = async (url) => {
  calls.push(url);
  if (scenario.network === 'throw') throw new Error('offline');
  return { ok: scenario.ok, json: async () => scenario.body };
};
const fill = new Function('fetch', src + '; return fillGeneratedPin;')(fetch);
fill(card).then(() => console.log(JSON.stringify({
  value: els['#um_pin'].value, type: els['#um_pin'].type, hint: els['#um_pin_hint'].textContent, calls,
  confirmDisabled: els['#modalOk'].disabled,
})));
"""


def _fill_source():
    html = open(os.path.join(ROOT, "templates", "admin.html"), encoding="utf-8").read()
    start = html.index("async function fillGeneratedPin(card)")
    depth, i = 0, html.index("{", start)
    for j in range(i, len(html)):
        depth += {"{": 1, "}": -1}.get(html[j], 0)
        if depth == 0:
            return html[start : j + 1]
    raise AssertionError("fillGeneratedPin() not terminated")


def run_fill(**scenario):
    scenario.setdefault("length", "6")
    scenario.setdefault("ok", True)
    scenario.setdefault("body", {})
    res = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps({"src": _fill_source(), "scenario": scenario}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@needs_node
def test_button_fills_and_reveals_the_generated_pin():
    out = run_fill(length="8", body={"pin": "48261937", "length": 8})
    assert out["value"] == "48261937"
    assert out["type"] == "text"  # a password field would hide the one thing the admin must read
    assert "8-digit" in out["hint"] and "no one else" in out["hint"]
    assert out["calls"] == ["/admin/generate-pin?length=8"]


@needs_node
def test_button_shows_the_server_error_and_leaves_the_field_alone():
    out = run_fill(ok=False, body={"error": "No unused PIN of that length is left"})
    assert out["value"] == "" and out["type"] == "password"
    assert out["hint"] == "No unused PIN of that length is left"


@needs_node
def test_button_survives_a_network_failure():
    out = run_fill(network="throw")
    assert out["value"] == "" and out["hint"] == "Could not generate a PIN"


OVERLAP_HARNESS = r"""
const fs = require('fs');
const { src, order, waitAll } = JSON.parse(fs.readFileSync(0, 'utf8'));
const els = {
  '#um_pin': { value: '', type: 'password' },
  '#um_pin_hint': { textContent: '' },
  '#um_pinlen': { value: '6' },
  '#modalOk': { disabled: false },
};
const card = { querySelector: (sel) => els[sel] };
const pending = [];
const fetch = () => new Promise((resolve) => pending.push(resolve));
const fill = new Function('fetch', src + '; return fillGeneratedPin;')(fetch);
const respond = (i, body, ok = true) => pending[i]({ ok, json: async () => body });
const tick = () => new Promise((r) => setTimeout(r, 5));
(async () => {
  const trace = {};
  const first = fill(card);   // click 1
  const second = fill(card);  // click 2 while 1 is still pending
  trace.confirmDisabledWhilePending = els['#modalOk'].disabled;
  for (const [i, body, ok] of order) { respond(i, body, ok); await tick(); }
  if (waitAll) await Promise.all([first, second]);
  console.log(JSON.stringify({ ...trace, value: els['#um_pin'].value, hint: els['#um_pin_hint'].textContent,
    confirmDisabledAfter: els['#modalOk'].disabled }));
})();
"""


def run_overlap(order, wait_all=True):
    res = subprocess.run(
        ["node", "-e", OVERLAP_HARNESS],
        input=json.dumps({"src": _fill_source(), "order": order, "waitAll": wait_all}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


@needs_node
def test_save_is_blocked_while_a_pin_is_being_generated_and_freed_afterwards():
    out = run_fill(body={"pin": "482619"})
    assert out["confirmDisabled"] is False  # re-enabled once the response is in
    out = run_fill(ok=False, body={"error": "nope"})
    assert out["confirmDisabled"] is False  # ...and after a failure too
    out = run_fill(network="throw")
    assert out["confirmDisabled"] is False


@needs_node
def test_an_older_slower_response_cannot_overwrite_the_latest_one():
    # click 1 then click 2; click 2's answer arrives first, click 1's (stale) arrives last
    out = run_overlap([[1, {"pin": "222222"}, True], [0, {"pin": "111111"}, True]])
    assert out["value"] == "222222"
    assert out["confirmDisabledWhilePending"] is True and out["confirmDisabledAfter"] is False


@needs_node
def test_a_stale_error_cannot_replace_the_latest_hint_either():
    out = run_overlap([[1, {"pin": "333333"}, True], [0, {"error": "old failure"}, False]])
    assert out["value"] == "333333" and "old failure" not in out["hint"]


@needs_node
def test_the_confirm_button_stays_blocked_until_the_latest_request_finishes():
    # click 1's (stale) answer arrives while click 2 is still pending: nothing changes, Save stays blocked
    out = run_overlap([[0, {"pin": "111111"}, True]], wait_all=False)
    assert out["value"] == "" and out["confirmDisabledAfter"] is True


def _function_source(name):
    html = open(os.path.join(ROOT, "templates", "admin.html"), encoding="utf-8").read()
    start = html.index(f"function {name}(")
    depth, i = 0, html.index("{", start)
    for j in range(i, len(html)):
        depth += {"{": 1, "}": -1}.get(html[j], 0)
        if depth == 0:
            return html[start : j + 1]
    raise AssertionError(f"{name}() not terminated")


def test_the_generate_button_is_wired_up_in_the_add_user_dialog():
    """Cheap guard for the glue the Node tests don't reach (no DOM library in this repo): the dialog
    has the button, keeps the card showModal returns, and its click handler calls fillGeneratedPin."""
    src = _function_source("openAddUser")
    assert 'id="um_generate"' in src and 'id="um_pinlen"' in src and 'id="um_pin_hint"' in src
    assert "const card = showModal(" in src
    assert "card.querySelector('#um_generate').addEventListener('click', () => fillGeneratedPin(card))" in src
    assert "return card;" in _function_source("showModal")


def test_generate_is_disabled_while_a_save_is_in_flight():
    src = _function_source("openAddUser")
    assert "generateBtn.disabled = true" in src and "finally { generateBtn.disabled = false; }" in src
