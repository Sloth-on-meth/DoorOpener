#!/usr/bin/with-contenv bash
# s6-overlay service script for DoorOpener.
# HA Supervisor writes user config to /data/options.json automatically.

export DOOROPENER_OPTIONS_PATH="/data/options.json"
export DOOROPENER_LOG_DIR="/data/logs"
export USERS_STORE_PATH="/data/users.json"

mkdir -p "${DOOROPENER_LOG_DIR}"

# Read port from options.json (default 6532)
DOOROPENER_PORT="$(python3 -c "import json; print(json.load(open('/data/options.json')).get('port', 6532))")"
export DOOROPENER_PORT

# If the user left ha_token empty, inject the Supervisor API token
HA_TOKEN="$(python3 -c "import json; print(json.load(open('/data/options.json')).get('ha_token', ''))")"
if [ -z "${HA_TOKEN}" ] && [ -n "${SUPERVISOR_TOKEN:-}" ]; then
  echo "[dooropener] No ha_token configured — using Supervisor API token"
  python3 -c "
import json, os
with open('/data/options.json') as f:
    opts = json.load(f)
opts['ha_token'] = os.environ.get('SUPERVISOR_TOKEN', '')
if not opts.get('ha_url') or opts['ha_url'] == 'http://supervisor/core':
    opts['ha_url'] = 'http://supervisor/core/api'
with open('/data/options.json', 'w') as f:
    json.dump(opts, f)
"
fi

echo "[dooropener] Starting DoorOpener on port ${DOOROPENER_PORT}..."
cd /app
exec gunicorn \
  --bind "0.0.0.0:${DOOROPENER_PORT}" \
  app:app \
  --workers 2 \
  --threads 2 \
  --timeout 60
