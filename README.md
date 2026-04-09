[![CI](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/ci.yml)
[![Docker Build](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/docker-build.yml/badge.svg?branch=main)](https://github.com/Sloth-on-meth/DoorOpener/actions/workflows/docker-build.yml)
![Version 1.12](https://img.shields.io/badge/version-1.12.2-blue?style=flat-square)
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Q5Q81T7CVO)

<details>
  <summary><strong>🚨 Help Wanted (expand)</strong></summary>

**Home Assistant Add-on:** I couldn't figure out how to package this as a proper HA add-on. If you know how, please open a PR. Any solution must keep standalone Docker usage working.

</details>

---

# 🚪 DoorOpener

A web-based keypad for controlling smart door locks via Home Assistant. PIN-protected with per-user codes, SSO login, rate limiting, and a dark glassmorphism UI.

<img width="1920" height="923" alt="keypad" src="https://github.com/user-attachments/assets/51f2e836-578d-4782-9156-3ba6e6752b59" />
<img width="1197" height="462" alt="admin" src="https://github.com/user-attachments/assets/edb8a1ab-0767-43fa-9238-0ccd41e1b4fd" />
<img width="1198" height="759" alt="image" src="https://github.com/user-attachments/assets/d84d9835-3a79-4be8-aebc-51fbe7f157ae" />

## Features

- Visual 3×4 keypad with auto-submit on valid PIN length
- Per-user PINs (4–8 digits), stored in a JSON user store
- Admin dashboard — user management, audit logs, leaderboard, 24-hour activity chart
- Public notice — admin can post a message displayed above the keypad
- Custom background image — upload, preview, and reset from the admin panel
- OIDC/SSO login (Authentik) with PKCE and optional pinless door open
- Pushbullet notifications — users can report problems directly from the keypad
- Terminal-style "ACCESS GRANTED" animation on successful open
- Audio feedback (success chimes, failure sounds) and haptic on mobile
- Real-time battery monitoring for Zigbee devices (polls every 60 s)
- Multi-layer rate limiting: per-IP, per-session, and global; applies to both PIN and admin auth endpoints
- Brute-force lockout with visual countdown on the keypad
- Security headers: CSP with per-request nonces, CSRF protection on all admin mutations, clickjacking prevention
- Dashboard HTML is only rendered server-side when the admin session is authenticated
- PWA — installable, works offline via service worker
- Optional page title (e.g. building name) displayed above the keypad
- Supports `switch`, `lock`, and `input_boolean` HA entities
- User migration tool — move users from legacy `config.ini [pins]` to the JSON store via the admin UI
- Test mode for safe development without triggering the actual door

---

## Quick Start

### Docker Compose (recommended)

```yaml
services:
  dooropener:
    image: ghcr.io/sloth-on-meth/dooropener:latest
    container_name: dooropener
    env_file: .env
    ports:
      - "${DOOROPENER_PORT:-6532}:${DOOROPENER_PORT:-6532}"
    volumes:
      - ./config.ini:/app/config.ini:ro
      - ./users.json:/app/users.json
      - ./logs:/app/logs
    restart: unless-stopped
```

```bash
git clone https://github.com/Sloth-on-meth/DoorOpener.git && cd DoorOpener
cp config.ini.example config.ini   # edit with your HA URL, token, entity
cp .env.example .env               # set FLASK_SECRET_KEY at minimum
docker compose up -d
```

Then open `http://your-server:6532`.

### Build locally

```bash
docker build -t dooropener:latest .
docker run -d --env-file .env \
  -v $(pwd)/config.ini:/app/config.ini:ro \
  -v $(pwd)/users.json:/app/users.json \
  -v $(pwd)/logs:/app/logs \
  -p 6532:6532 dooropener:latest
```

### Without Docker

```bash
pip install -r requirements.txt
python app.py
```

---

## Configuration

### .env

```bash
FLASK_SECRET_KEY=change-me-to-something-long-and-random   # required
DOOROPENER_PORT=6532          # default 6532
TZ=Europe/Amsterdam           # default UTC
PUID=1000                     # aligns container user to your host user
PGID=1000
UMASK=002
SESSION_COOKIE_SECURE=true    # set false only for local HTTP dev
```

> The image follows the linuxserver.io `PUID`/`PGID` convention. On startup, the entrypoint drops privileges to the specified user so logs are written with your host uid — no manual `chown` needed.

### config.ini

```ini
[HomeAssistant]
url = http://homeassistant.local:8123
token = your_long_lived_access_token
switch_entity = switch.your_door_opener
# battery_entity = sensor.your_door_battery   # defaults to sensor.<device>_battery
# ca_bundle = /etc/dooropener/ha-ca.pem       # custom CA for self-signed HA certs

[admin]
admin_password = change-me

[server]
port = 6532
test_mode = false              # WARNING: if true, door will NOT open — dev only
# page_title = Sunset Apartments   # displayed above keypad; omit to hide
# secret_key = ...             # alternative to FLASK_SECRET_KEY env var
67mode = false                 # enable 6-7 easter egg

[security]
max_attempts = 5               # failed attempts per IP before block
block_time_minutes = 5
max_global_attempts_per_hour = 50
session_max_attempts = 3       # failed attempts per session before block

[pushbullet]
# api_token = your_pushbullet_token   # enables problem-report button on keypad
```

> **`test_mode`**: A startup warning is logged and a banner is shown in the admin panel when this is `true`. Never leave it enabled in production — the door will silently succeed without opening.

### Self-signed Home Assistant certificate

Mount your CA bundle and point `ca_bundle` at it:

```yaml
volumes:
  - ./certs/ha-ca.pem:/etc/dooropener/ha-ca.pem:ro
```

```ini
[HomeAssistant]
ca_bundle = /etc/dooropener/ha-ca.pem
```

Alternatively, set `REQUESTS_CA_BUNDLE=/etc/dooropener/ha-ca.pem` as an environment variable.

---

## User Management

DoorOpener stores users in `users.json`. Manage them through the admin dashboard — no restarts needed.

**Admin UI features:**
- Create, edit, delete users
- Activate / deactivate without deletion
- View creation date, last used, and open count
- Migrate legacy users from `config.ini [pins]` to the JSON store (individually or all at once)
- Clear logs (test data or all)
- 24-hour activity bar chart and leaderboard

### Migrating from config.ini pins

If you previously defined users under `[pins]` in `config.ini`, the admin dashboard shows a **Migrate** button next to each legacy user. Migrating moves the user into `users.json` with full metadata tracking and removes them from `config.ini`. Use **Migrate All** to do this in bulk.

---

## Public Notice

The admin panel includes a **Public Notice** field. Whatever you write there is displayed in a banner above the keypad — useful for "Door out of service" messages or access hours. Clear the field to hide the banner.

---

## Background Image

Upload a custom background image (JPEG, PNG, GIF, or WebP, max 10 MB) from the admin panel. The original default background is preserved and can be restored at any time with the **Reset** button.

---

## Pushbullet Notifications

Set `[pushbullet] api_token` in `config.ini` to enable the problem-report button on the keypad. Users can send short messages (max 500 chars) to your Pushbullet account, rate-limited to 3 reports per IP per hour.

---

## OIDC / SSO (Authentik)

```ini
[oidc]
enabled = false
issuer = https://auth.example.com/application/o/dooropener
client_id = your_client_id
client_secret = your_client_secret
redirect_uri = https://your.domain/oidc/callback

# Group required to access admin dashboard (optional)
admin_group = dooropener-admins

# Group allowed to open the door via OIDC (leave empty = all authenticated users)
user_group = dooropener-users

# If true, OIDC users must still enter a PIN (no pinless open)
require_pin_for_oidc = false
```

When OIDC is enabled, a **Login with SSO** button appears on the keypad. Authenticated users in `user_group` can open the door without a PIN (unless `require_pin_for_oidc = true`). The OIDC flow uses PKCE (`S256`) and validates state and nonce parameters.

> If running behind a reverse proxy over HTTP for local dev, set `SESSION_COOKIE_SECURE=false` so the browser sends the session cookie.

---

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | — | Keypad UI |
| `POST` | `/open-door` | — | Open the door (`{"pin": "1234"}`) |
| `GET` | `/battery` | — | Battery level for configured Zigbee device |
| `GET` | `/auth/status` | — | Current OIDC auth state |
| `POST` | `/report-problem` | — | Send a problem report via Pushbullet |
| `GET` | `/health` | — | Health check — returns `{"status": "ok"}` |
| `GET` | `/login` | — | Initiate OIDC login flow |
| `GET` | `/oidc/callback` | — | OIDC redirect callback |
| `GET` | `/oidc/logout` | — | OIDC logout and session clear |
| `GET` | `/admin` | — | Admin UI (dashboard HTML only rendered when authenticated) |
| `POST` | `/admin/auth` | — | Admin password login |
| `GET` | `/admin/check-auth` | — | Check admin session state |
| `POST` | `/admin/logout` | Admin | End admin session |
| `GET` | `/admin/notice` | — | Get current public notice |
| `POST` | `/admin/notice` | Admin | Set or clear public notice |
| `GET` | `/admin/background` | Admin | Check if custom background is set |
| `POST` | `/admin/background` | Admin | Upload background image |
| `DELETE` | `/admin/background` | Admin | Reset background to default |
| `GET` | `/admin/logs` | Admin | Audit log entries (JSON) |
| `POST` | `/admin/logs/clear` | Admin | Clear logs |
| `GET` | `/admin/users` | Admin | User list (JSON) |
| `POST` | `/admin/users` | Admin | Create user |
| `PUT` | `/admin/users/<name>` | Admin | Update user |
| `DELETE` | `/admin/users/<name>` | Admin | Delete user |
| `POST` | `/admin/users/<name>/migrate` | Admin | Migrate user from config.ini to JSON store |
| `POST` | `/admin/users/migrate-all` | Admin | Migrate all config-only users |

---

## Easter Egg

Type `6767` on the keypad to trigger a full-screen 6-7 animation with confetti, an 8-bit fanfare, and haptic feedback.

Enable in `config.ini`:

```ini
[server]
67mode = true
```

Disabled by default — no client-side code is shipped when off.

---

## License

MIT — see [LICENSE](LICENSE).
