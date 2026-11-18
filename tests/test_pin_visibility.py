"""PIN display: dots by default, digits only after the user asks, hidden again on every page load."""

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

HARNESS = r"""
const { src, pin, visible } = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const display = { innerHTML: '' };
const document = { getElementById: () => display };
const run = new Function('document', 'currentPin', 'pinVisible', src + '; updatePinDisplay(); return null;');
run(document, pin, visible);
console.log(JSON.stringify(display.innerHTML));
"""


def _source(name):
    js = open(os.path.join(ROOT, "static", "index.js"), encoding="utf-8").read()
    start = js.index(f"function {name}(")
    i = js.index("{", start)
    depth = 0
    for j in range(i, len(js)):
        depth += {"{": 1, "}": -1}.get(js[j], 0)
        if depth == 0:
            return js[start : j + 1]
    raise AssertionError(name)


def _render(pin, visible):
    res = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps({"src": _source("updatePinDisplay"), "pin": pin, "visible": visible}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


@needs_node
def test_hidden_by_default_shows_only_dots():
    html = _render("4291", False)
    assert html.count("●") == 4 and "4291" not in html and "429" not in html


@needs_node
def test_visible_shows_each_digit():
    html = _render("4291", True)
    assert "●" not in html
    for d in "4291":
        assert f">{d}</span>" in html


@needs_node
def test_empty_pin_shows_placeholder_either_way():
    assert "Enter PIN" in _render("", False) and "Enter PIN" in _render("", True)


def test_toggle_is_accessible_and_starts_hidden():
    html = open(os.path.join(ROOT, "templates", "index.html"), encoding="utf-8").read()
    assert 'id="pinToggle"' in html and 'aria-pressed="false"' in html and 'aria-label="Show PIN"' in html
    js = open(os.path.join(ROOT, "static", "index.js"), encoding="utf-8").read()
    assert "let pinVisible = false" in js  # never persisted (no localStorage for it)
    assert "localStorage" not in js[js.index("pinVisible") : js.index("pinVisible") + 400]
