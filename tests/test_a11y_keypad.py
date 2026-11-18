"""Accessibility of the keypad page: labels, live regions, focus, and keyboard handling."""

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _read(*parts):
    return open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def test_icon_only_buttons_have_accessible_names():
    html = _read("templates", "index.html")
    assert 'id="clearBtn" aria-label="Delete last digit"' in html
    assert 'id="submitBtn" class="keypad-btn submit-btn" aria-label="Open door"' in html
    assert 'class="github-btn" title="View on GitHub" aria-label="View on GitHub"' in html


def test_results_are_announced():
    html = _read("templates", "index.html")
    assert 'id="accessDeniedPopup" class="access-popup denied" role="alert"' in html
    assert 'id="accessGrantedPopup" class="access-popup granted" role="status"' in html
    assert 'id="toast-container" role="status" aria-live="polite"' in html
    assert 'id="pinAnnounce" class="sr-only" role="status" aria-live="polite"' in html


def test_keyboard_focus_is_visible_and_motion_can_be_reduced():
    css = _read("static", "index.css")
    assert ".keypad-btn:focus-visible" in css and "outline: 3px solid" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert ".sr-only" in css


def test_enter_on_a_keyboard_focused_button_is_left_to_the_button():
    js = _read("static", "index.js")
    assert "focusedByKeyboard" in js
    # a pointer interaction must reset it, or mouse users lose "Enter opens the door"
    assert "addEventListener('pointerdown', () => { focusedByKeyboard = false; }" in js


HARNESS = r"""
const { src, pin } = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const display = { innerHTML: '' }, announce = { textContent: '' };
const document = { getElementById: (id) => (id === 'pinAnnounce' ? announce : display) };
new Function('document', 'currentPin', 'pinVisible', src + '; updatePinDisplay();')(document, pin, false);
console.log(JSON.stringify(announce.textContent));
"""


def _announce(pin):
    js = _read("static", "index.js")
    start = js.index("function updatePinDisplay(")
    i = js.index("{", start)
    depth = 0
    for j in range(i, len(js)):
        depth += {"{": 1, "}": -1}.get(js[j], 0)
        if depth == 0:
            src = js[start : j + 1]
            break
    res = subprocess.run(
        ["node", "-e", HARNESS], input=json.dumps({"src": src, "pin": pin}), capture_output=True, text=True, timeout=30
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


@needs_node
def test_screen_reader_hears_the_count_never_the_digits():
    assert _announce("") == ""
    assert _announce("4") == "1 digit entered"
    out = _announce("4291")
    assert out == "4 digits entered" and "4291" not in out
