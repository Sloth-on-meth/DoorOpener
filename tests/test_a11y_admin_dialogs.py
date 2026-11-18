"""Admin dialogs are real dialogs: roles, labelled, Esc to close, focus kept inside, focus restored."""

import os

ROOT = os.path.dirname(os.path.dirname(__file__))


def _show_modal():
    js = open(os.path.join(ROOT, "static", "admin.js"), encoding="utf-8").read()
    start = js.index("function showModal(")
    i = js.index("{", start)
    depth = 0
    for j in range(i, len(js)):
        depth += {"{": 1, "}": -1}.get(js[j], 0)
        if depth == 0:
            return js[start : j + 1]
    raise AssertionError("showModal not terminated")


def test_dialog_is_announced_as_a_labelled_modal():
    src = _show_modal()
    assert "card.setAttribute('role', 'dialog')" in src
    assert "card.setAttribute('aria-modal', 'true')" in src
    assert "card.setAttribute('aria-labelledby', titleId)" in src
    assert 'id="${titleId}"' in src
    assert 'aria-label="Close"' in src


def test_escape_closes_and_tab_is_trapped():
    src = _show_modal()
    assert "e.key === 'Escape'" in src and "e.key === 'Tab'" in src
    assert "addEventListener('keydown', onKeydown, true)" in src
    # the listener is removed on close, or it would leak one per dialog opened
    assert "removeEventListener('keydown', onKeydown, true)" in src


def test_focus_starts_in_the_dialog_and_returns_afterwards():
    src = _show_modal()
    assert "previouslyFocused.focus()" in src
    # confirmations have no field: start on the safe choice, never on the destructive one
    assert "querySelector('#modalCancel')).focus()" in src
