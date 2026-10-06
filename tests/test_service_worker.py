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
    # activate deletes every cache whose name != the current one, so a bump purges cached admin data
    assert "CACHE_VERSION = 'v3'" in open(SW).read()
