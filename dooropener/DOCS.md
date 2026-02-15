# DoorOpener — Home Assistant Add-on

A secure web interface for controlling smart door openers via Home Assistant.

## Installation

1. Add this repository to your Home Assistant add-on store:
   **Settings → Add-ons → Add-on Store → ⋮ → Repositories** → paste:
   ```
   https://github.com/Sloth-on-meth/DoorOpener
   ```
2. Find **DoorOpener** in the store and click **Install**.
3. Configure the add-on (see below) and click **Start**.

## Configuration

| Option | Description | Required |
|--------|-------------|----------|
| `ha_url` | Home Assistant URL (default uses Supervisor API) | No |
| `ha_token` | Long-lived access token (leave empty to use Supervisor token) | No |
| `entity_id` | Entity to trigger (`switch.*`, `lock.*`, or `input_boolean.*`) | **Yes** |
| `battery_entity` | Battery sensor entity for monitoring | No |
| `admin_password` | Password for the admin dashboard | **Yes** |
| `test_mode` | Simulate door actions without calling HA | No |
| `max_attempts` | Failed PIN attempts per IP before blocking | No |
| `block_time_minutes` | Block duration in minutes | No |
| `session_max_attempts` | Failed attempts per session before blocking | No |
| `secret_key` | Flask secret key (auto-generated if empty) | No |

## Usage

Once started, open the add-on via the sidebar (the door icon) or navigate to
the ingress URL. Enter your PIN on the visual keypad to open the door.

### Managing Users

Open the admin panel (gear icon), log in with your `admin_password`, and use
the **Users** tab to create, edit, or deactivate users. Each user gets a
unique 4–8 digit PIN.

## Data Storage

All add-on data is stored in `/data/` (persisted across restarts):

- `options.json` — configuration (managed by HA)
- `users.json` — user database
- `logs/log.txt` — audit log
