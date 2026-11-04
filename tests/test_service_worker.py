"""The service worker must only cache the app shell and static assets, never API/admin responses."""

import os
import shutil
import subprocess

import pytest

SW = os.path.join(os.path.dirname(__file__), "..", "static", "service-worker.js")

HARNESS = r"""
const fs = require('fs');
const handlers = {};
const cacheWrites = [];
global.self = {
  location: { origin: 'https://door.test' },
  addEventListener: (type, fn) => { handlers[type] = fn; },
  skipWaiting: () => {}, clients: { claim: () => {} },
};
global.caches = {
  open: async () => ({ addAll: async () => {}, put: async (req) => { cacheWrites.push(req.url); } }),
  match: async () => undefined,
  keys: async () => [],
};
global.fetch = async () => ({ clone: () => ({}), ok: true });
eval(fs.readFileSync(process.argv[1], 'utf8'));
const out = {};
for (const path of ['/', '/static/gear.png', '/admin/users', '/admin/logs', '/auth/status', '/battery']) {
  let responded = false;
  const request = { method: 'GET', url: 'https://door.test' + path };
  handlers.fetch({ request, respondWith: () => { responded = true; } });
  out[path] = responded;
}
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_only_shell_and_static_are_intercepted():
    res = subprocess.run(["node", "-e", HARNESS, SW], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    import json

    handled = json.loads(res.stdout.strip().splitlines()[-1])
    assert handled["/"] and handled["/static/gear.png"]
    assert not any(handled[p] for p in ("/admin/users", "/admin/logs", "/auth/status", "/battery"))


def test_cache_version_bumped_to_purge_old_entries():
    # activate deletes every cache whose name != the current one, so a bump purges stale entries:
    # v3 purged cached admin data, v4 purges the cache-first copy of the old background image
    import re

    version = int(re.search(r"CACHE_VERSION = 'v(\d+)'", open(SW).read()).group(1))
    assert version >= 4


BACKGROUND_HARNESS = r"""
const fs = require('fs');
const handlers = {};
const puts = [];
let cached = { body: 'OLD-CACHED' };
global.self = { location: { origin: 'https://door.test' }, addEventListener: (t, fn) => { handlers[t] = fn; },
  skipWaiting: () => {}, clients: { claim: () => {} } };
global.caches = {
  open: async () => ({ addAll: async () => {}, put: async (key, res) => { puts.push(String(key)); } }),
  match: async () => cached,
  keys: async () => [],
};
const mode = process.argv[2];
global.fetch = async () => {
  if (mode === 'offline') throw new Error('offline');
  return { ok: true, body: 'FRESH', clone() { return this; } };
};
eval(fs.readFileSync(process.argv[1], 'utf8'));
(async () => {
  let result;
  const url = 'https://door.test/static/background.jpg?t=12345';
  handlers.fetch({ request: { method: 'GET', url }, respondWith: (p) => { result = p; } });
  const res = await result;
  await new Promise((r) => setTimeout(r, 10));
  console.log(JSON.stringify({ body: res.body, puts }));
})();
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize(
    "mode, body",
    [("online", "FRESH"), ("offline", "OLD-CACHED")],
)
def test_background_is_network_first_with_a_cache_fallback(mode, body):
    """A replaced background must show immediately; the cached copy is only for when offline."""
    import json

    res = subprocess.run(["node", "-e", BACKGROUND_HARNESS, SW, mode], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout.strip().splitlines()[-1])
    assert out["body"] == body
    if mode == "online":
        # stored under a fixed key, not the ?t=... URL, so the admin preview can't grow the cache
        assert out["puts"] == ["/static/background.jpg"]
