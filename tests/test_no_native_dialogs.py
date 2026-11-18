"""The UI must not use the browser's blocking alert()/confirm()/prompt() dialogs.

They look out of place in the installed PWA and are suppressed in some embedded browsers.
Use the in-page modal helpers (modalError / confirmDialog) instead.
"""

import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(__file__))
NATIVE = re.compile(r"(?<![\w.])(alert|confirm|prompt)\s*\(")


def _code_only(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def test_no_native_dialogs_in_static_scripts_or_templates():
    files = glob.glob(os.path.join(ROOT, "static", "*.js")) + glob.glob(os.path.join(ROOT, "templates", "*.html"))
    offenders = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            for m in NATIVE.finditer(_code_only(f.read())):
                offenders.append(f"{os.path.basename(path)}: {m.group(0)}")
    assert not offenders, offenders
