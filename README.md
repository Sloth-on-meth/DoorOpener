# DoorOpener

A secure web interface for controlling smart door openers via Home Assistant. Features a modern glass-morphism UI with visual keypad, per-user PINs, audio feedback, battery monitoring, and comprehensive brute-force protection.

[![CI](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/ci.yml)
[![Docker Build](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/docker-build.yml/badge.svg?branch=main)](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/docker-build.yml)
![Version](https://img.shields.io/badge/version-2.0.0-blue?style=flat-square)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue?style=flat-square)

---

<details>
  <summary><strong>Help Wanted: Home Assistant Add-on</strong></summary>

  ### Home Assistant Add-on Needed!
  If you know how to package this as a proper Home Assistant add-on, please open a PR!

  > **Important:** Any add-on solution must not break standalone usage. The project must remain fully usable both as a Home Assistant add-on _and_ as a standalone app (Docker).
</details>

---

<img width="2554" height="1187" alt="image" src="https://github.com/user-attachments/assets/e9e2fd6c-aa32-4ea1-933f-668fad3fbfc4" />

<img width="2554" height="1187" alt="image" src="https://github.com/user-attachments/assets/4d5259fa-ee7b-4d03-a02b-b77301cebf0c" />

## What It Does

DoorOpener provides a web-based keypad interface to remotely open doors connected to Home Assistant. Users enter their personal PIN on a visual keypad and the system securely communicates with Home Assistant to trigger the door opener.

**Key Features:**

- Visual 3×4 keypad interface with auto-submit
- Individual PINs for each user with JSON-based user management
- Audio feedback (success chimes, failure sounds)
- Real-time battery monitoring for Zigbee devices
- Multi-layer security with rate limiting and IP blocking
- Admin UI with user management and log viewer
- Test mode for safe development
- Supports Home Assistant `switch`, `lock`, and `input_boolean` entities

## Quick Start

### Home Assistant Add-on (Recommended)

1. In Home Assistant go to **Settings → Add-ons → Add-on Store → ⋮ → Repositories**
2. Paste the repository URL:
   ```
   https://github.com/Sloth-on-meth/DoorOpener
   ```
3. Find **DoorOpener** in the store and click **Install**
4. Configure `entity_id` and `admin_password` in the add-on options
5. Click **Start** — the panel appears in the sidebar with a door icon

> When running as an add-on you can leave `ha_url` and `ha_token` empty — the
> Supervisor API token is used automatically.

### Docker (Standalone)

```yaml
services:
  dooropener:
    image: ghcr.io/sloth-on-meth/dooropener:latest
    container_name: dooropener
    environment:
      - DOOROPENER_PORT=${DOOROPENER_PORT:-6532}
      - TZ=${TZ:-UTC}
      - PUID=${PUID:-1000}
      - PGID=${PGID:-1000}
      - UMASK=${UMASK:-002}
      - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
      - SESSION_COOKIE_SECURE=${SESSION_COOKIE_SECURE:-true}
    ports:
      - "${DOOROPENER_PORT:-6532}:${DOOROPENER_PORT:-6532}"
    volumes:
      - ./options.json:/app/options.json:ro
      - ./users.json:/app/users.json:rw
      - ./logs:/app/logs
    restart: unless-stopped
```

Steps:

1. `git clone https://github.com/Sloth-on-meth/DoorOpener.git && cd DoorOpener`
2. `cp options.json.example options.json` and edit it (see [Configuration](#configuration)).
3. `cp .env.example .env` and adjust values (`TZ`, `PUID`/`PGID`, `FLASK_SECRET_KEY`).
4. `docker compose up -d`

#### Building Locally

```bash
docker build -t dooropener:latest .
docker run -d --env-file .env \
  -v $(pwd)/options.json:/app/options.json:ro \
  -v $(pwd)/users.json:/app/users.json:rw \
  -v $(pwd)/logs:/app/logs \
  -p 6532:6532 dooropener:latest
```

## Configuration

### `options.json` (primary config)

All application settings live in a single `options.json` file. Copy the example and edit:

```bash
cp options.json.example options.json
```

```json
{
  "ha_url": "http://homeassistant.local:8123",
  "ha_token": "your_long_lived_access_token_here",
  "entity_id": "switch.dooropener_zigbee",
  "battery_entity": "sensor.dooropener_zigbee_battery",
  "port": 6532,
  "test_mode": false,
  "admin_password": "change_me_please",
  "max_attempts": 5,
  "block_time_minutes": 5,
  "max_global_attempts_per_hour": 50,
  "session_max_attempts": 3,
  "secret_key": "",
  "session_cookie_secure": false,
  "ca_bundle": ""
}
```

| Key | Description | Default |
|-----|-------------|---------|
| `ha_url` | Home Assistant base URL | _(required)_ |
| `ha_token` | Long-lived access token (HA → Profile → Security) | _(required)_ |
| `entity_id` | Entity to trigger (`switch.*`, `lock.*`, or `input_boolean.*`) | _(required)_ |
| `battery_entity` | Battery sensor entity for monitoring | auto-derived |
| `port` | Web server port (overridden by `DOOROPENER_PORT` env var) | `6532` |
| `test_mode` | When `true`, simulates door actions without calling HA | `false` |
| `admin_password` | Password for the admin dashboard | _(required)_ |
| `max_attempts` | Failed PIN attempts per IP before blocking | `5` |
| `block_time_minutes` | Block duration in minutes | `5` |
| `max_global_attempts_per_hour` | Global rate limit across all clients | `50` |
| `session_max_attempts` | Failed attempts per browser session before blocking | `3` |
| `secret_key` | Flask secret key (leave empty + set `FLASK_SECRET_KEY` env var instead) | `""` |
| `session_cookie_secure` | Set `true` when running behind HTTPS | `false` |
| `ca_bundle` | Path to a custom CA bundle (PEM) for self-signed HA certificates | `""` |

### Environment Variables (`.env` file)

```bash
# Port (optional, overrides options.json)
DOOROPENER_PORT=6532

# Timezone
TZ=Europe/Amsterdam

# Container user/group mapping (linuxserver-style)
PUID=1000
PGID=1000
UMASK=002

# Flask session secret (recommended for production)
FLASK_SECRET_KEY=please-change-me

# Set true when behind HTTPS reverse proxy
SESSION_COOKIE_SECURE=true
```

**Configuration priority:** Environment variables > `options.json` defaults.

### PUID/PGID and Permissions

The image supports `PUID`, `PGID`, and `UMASK` to avoid host-side `chown`. On startup the entrypoint aligns the runtime user/group to those IDs, ensures `/app/logs` is writable, then drops privileges via `gosu`.

### Logs

| Log | Location |
|-----|----------|
| Door access / audit log | `/app/logs/log.txt` (bind-mount `./logs:/app/logs`) |
| Gunicorn / access log | Container stdout/stderr (`docker logs dooropener`) |

## Self-Signed Certificates (Home Assistant)

If your Home Assistant uses a self-signed certificate, provide a custom CA bundle:

### Option 1 — `options.json` (recommended)

Set `"ca_bundle": "/etc/dooropener/ha-ca.pem"` in `options.json` and mount the file:

```yaml
services:
  dooropener:
    volumes:
      - ./options.json:/app/options.json:ro
      - ./certs/ha-ca.pem:/etc/dooropener/ha-ca.pem:ro
```

### Option 2 — Environment variable

```yaml
services:
  dooropener:
    environment:
      - REQUESTS_CA_BUNDLE=/etc/dooropener/ha-ca.pem
    volumes:
      - ./certs/ha-ca.pem:/etc/dooropener/ha-ca.pem:ro
```

> **Note:** The hostname in `ha_url` must match a Subject Alternative Name in the certificate.

## Usage

1. **Access interface** — visit `http://localhost:6532`
2. **Enter PIN** — use the visual keypad (4–8 digit PIN)
3. **Auto-submit** — the door opens automatically when a valid-length PIN is entered
4. **Admin access** — click the gear icon for the admin dashboard

## Security

### Protection Layers

| Layer | Description |
|-------|-------------|
| **IP rate limiting** | Blocks an IP after `max_attempts` failures for `block_time_minutes` |
| **Session rate limiting** | Blocks a browser session after `session_max_attempts` failures |
| **Global rate limiting** | Caps total failed attempts system-wide to `max_global_attempts_per_hour` |
| **Progressive delay info** | Exponential back-off metadata (1 s → 16 s) returned to the client |
| **Persistent cookie block** | Block state survives page reloads via a session cookie |
| **Audit logging** | Every attempt logged with timestamp, IP, session, user, and result |
| **Input validation** | PIN format and request body validated before processing |
| **Security headers** | CSP, X-Frame-Options DENY, HSTS referral, no-sniff, etc. |
| **Bot detection** | Obvious bot/crawler/spider user-agents are rejected |

### Security Headers

Every response includes:

- `Content-Security-Policy` — strict self-only policy
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` — geolocation, camera, microphone disabled
- `Cache-Control: no-store`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Main keypad interface |
| `POST` | `/open-door` | Validate PIN and trigger door entity |
| `GET` | `/battery` | Battery level JSON (`{"level": 85}`) |
| `GET` | `/admin` | Admin dashboard |
| `POST` | `/admin/auth` | Admin login |
| `GET` | `/admin/check-auth` | Check admin session |
| `POST` | `/admin/logout` | Admin logout |
| `GET` | `/admin/logs` | Retrieve audit logs (admin auth required) |
| `POST` | `/admin/logs/clear` | Clear logs (admin auth required) |
| `GET` | `/admin/users` | List users (admin auth required) |
| `POST` | `/admin/users` | Create user (admin auth required) |
| `PUT` | `/admin/users/<name>` | Update user (admin auth required) |
| `DELETE` | `/admin/users/<name>` | Delete user (admin auth required) |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   app.py                        │
│         Flask routes & request handling         │
├────────────┬──────────────┬─────────────────────┤
│ config.py  │ security.py  │   ha_client.py      │
│ options.json│ RateLimiter  │   HAClient          │
│ loader     │ headers      │   (requests.Session) │
│ timezone   │ validation   │   trigger / battery  │
├────────────┴──────────────┴─────────────────────┤
│               users_store.py                    │
│           JSON-based user management            │
└─────────────────────────────────────────────────┘
```

| Module | Responsibility |
|--------|---------------|
| `config.py` | Loads `options.json`, exposes all settings as module attributes, timezone handling via `zoneinfo` |
| `security.py` | `RateLimiter` class (IP / session / global), security headers, bot detection, PIN validation |
| `ha_client.py` | `HAClient` class wrapping `requests.Session` — dispatches `switch`/`lock`/`input_boolean` services |
| `users_store.py` | Atomic JSON-based user CRUD with usage tracking |
| `app.py` | Flask app, route handlers, audit logging |

## Development

### Prerequisites

- Python 3.12+
- An `options.json` file (copy from `options.json.example`)

### Local Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp options.json.example options.json   # edit as needed
python app.py
```

### Running Tests

```bash
pytest --tb=short -q
```

With coverage:

```bash
pytest --cov=./ --cov-report=term-missing --cov-fail-under=75
```

### Linting & Security

```bash
ruff check .          # lint
bandit -r . -x tests  # security scan
```

### Test Mode

Set `"test_mode": true` in `options.json` to test the interface without actually triggering the door in Home Assistant.

## CI / CD

### GitHub Actions

The CI pipeline (`.github/workflows/ci.yml`) runs on every push and PR:

| Job | Tool | Purpose |
|-----|------|---------|
| **Tests** | pytest + pytest-cov | Unit/integration tests, 75 % coverage gate |
| **Lint** | ruff | Code style and import checks |
| **Security** | bandit | Static security analysis |
| **Docker** | docker build | Smoke-test the container image |

### Dependabot

Weekly pull requests for dependency updates are configured via `.github/dependabot.yml`:

- **pip** dependencies — every Monday
- **GitHub Actions** versions — every Monday

## License

Open source — see repository for details.
