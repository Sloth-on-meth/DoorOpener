## v[1.7.0] - 2025-09-08

### 🔒 Security Enhancements (OIDC & App)
- OIDC now fully gated: all OIDC functionality is disabled unless the OAuth client is initialized and `enabled=true` in `[oidc]`.
- Added CSRF protection via `state` and replay protection via `nonce` in the OIDC flow.
- Enabled PKCE (`S256`).
- Strict token validation: issuer (`iss`) check, audience (`aud`) supports list or string, expiration (`exp`) and not‑before (`nbf`) with 60s leeway.
- Session fixation protection: session is cleared after successful token validation before setting auth data.
- Pinless open only when: OIDC enabled, session valid (non‑expired), user in allowed group (if configured), and `require_pin_for_oidc=false`.
- Hardened security headers: strong CSP, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`, `Permissions-Policy`, strict referrer policy, and no‑cache on dynamic endpoints.
- Admin login protected with progressive delays and temporary session blocking; all attempts are now audit‑logged.

### 🧪 Tests & CI
- Expanded OIDC tests: state/nonce, expired session behavior, pinless success, invalid state rejection, login redirect behavior, and OIDC gating.
- CI pushes Docker image to GHCR on every push using `docker/login-action` with PAT or `GITHUB_TOKEN` fallback.

### 🐳 Docker & Runtime
- Adopted linuxserver.io‑style `PUID`/`PGID`/`UMASK` pattern for painless host permissions.
- New `entrypoint.sh` aligns runtime user/group to host IDs, ensures `/app/logs` is writable, applies umask, then drops privileges via `gosu`.
- Fixed Debian package availability in `python:3.9-slim` (trixie) by installing `passwd` (provides `useradd`/`groupadd`) instead of `shadow`.
- `docker-compose.yml` updated to include `PUID`, `PGID`, `UMASK` envs; `config.ini` stays read‑only; `logs/` is writeable.

### 📝 Logging & Observability
- Switched to `RotatingFileHandler` for both access and audit logs to prevent unbounded growth.
- All logs centralized under `/app/logs/` (mount `./logs:/app/logs`).

### 🎨 UI/UX
- Frontend SSO button visibility now strictly follows backend `oidc_enabled` flag.
- Added missing `openDoorWithSSO()` function to make SSO button functional.

### 📚 Documentation
- README refreshed with compose example, `PUID/PGID/UMASK`, `SESSION_COOKIE_SECURE`, and logging paths in linuxserver.io style.
- `.env.example` updated with new envs.
- `config.ini.example` gains optional `[oidc] public_key` for local token signature validation.

### 🙏 Acknowledgements
- Thanks to @hanneshier for the idea and contributions around the OIDC flow.
- Thanks to @remijn for fixing my docker build flow

---

## v[1.6.0] - 2025-09-04

### 🚀 Features & Improvements
- **Configurable Security Parameters**: All rate limiting and blocking thresholds are now settable in `[security]` section of `config.ini`.
- **Dynamic Security Settings**: Security values (max attempts, block time, etc) are now loaded from config, not hardcoded.
- **Improved Error Messaging**: On door open failure, users are prompted with 'Please contact the administrator.'
- **Documentation**: README and config.ini.example updated for new security features.
- **UI/JS Polish**: Minor bugfixes and cleanup for keypad and error handling.
- **Version bump to 1.6.0**

---

## v[1.5.0] - 2025-09-04

### 🛠️ Maintenance & Release Preparation
- Removed deprecated `repository.json` file.
- Moved `favicon-192.png` into the `static/` directory for better asset organization.
- Updated documentation and project structure to clarify Home Assistant add-on compatibility and standalone usage requirements.
- General code review and preparation for v1.5 release.

---

## v[1.4.0] - 2025-09-03

### 🆙 Dependency Updates
- Updated all core dependencies to latest stable versions (Flask 3.1.2, requests 2.32.5, Werkzeug 3.1.3, pytz 2025.2) for improved security and compatibility.

### ♻️ Maintenance
- General codebase maintenance and preparation for future features.

---

# Changelog

## v[1.3.0] - 2025-09-03

### 🚀 Features & Improvements
- Now you do not have to build anymore - ghcr setup!
### 🐛 Bug Fixes
- api error

---

## v[1.2.0] - 2025-09-02

### 🔒 Enhanced Security Features

#### ✨ New Security Improvements
- **Multi-Layer Rate Limiting** - Session-based (3 attempts), IP-based (5 attempts), and global (50/hour) protection
- **Enhanced IP Detection** - Uses `request.remote_addr` instead of spoofable client headers
- **Session Tracking** - Unique session identifiers prevent easy bypass of rate limits
- **Suspicious Request Detection** - Blocks requests with missing/bot User-Agent headers
- **Composite Identifiers** - IP + User-Agent/language fingerprinting for better tracking

#### 🎨 Visual Interface Improvements
- **Visual Keypad Interface** - Replaced text input with responsive 3x4 grid keypad (0-9, backspace, enter)
- **Auto-Submit PIN Entry** - Door opens automatically when valid PIN length (4-8 digits) is entered
- **Perfect Alignment** - PIN display and keypad visually centered and width-matched
- **Keyboard Support** - Physical keyboard input (0-9, Backspace, Enter) works alongside touch

#### 🔊 Audio & Feedback Features
- **Success Sound** - Ascending chime sequence using Web Audio API
- **Failure Sound** - "Womp womp" descending trombone effect for invalid attempts
- **Visual Feedback** - Button animations, haptic vibration, toast notifications
- **Responsive Design** - Optimized for both desktop and mobile devices

#### 🧪 Testing & Development
- **Test Mode** - Safe testing without physical door operation (`test_mode = true` in config.ini)
- **Simulated Success** - Shows success messages and logs without Home Assistant API calls
- **Full Feature Testing** - All keypad, audio, and security features work in test mode

#### 🌍 Timezone Support
- **Environment Variable** - Set `TZ` environment variable for local timezone (default: UTC)
- **Consistent Logging** - All timestamps in logs use the configured timezone
- **Docker Integration** - Timezone configuration through docker-compose environment

#### 🛠️ Technical Improvements
- **Enhanced Logging** - Session IDs, composite identifiers, and detailed status tracking
- **Progressive Security** - Multiple blocking mechanisms with different thresholds
- **Dependency Updates** - Added pytz for robust timezone handling

#### 🐛 Bug Fixes
- Fixed variable reference errors in logging statements
- Resolved import conflicts with configparser
- Improved error handling in security functions

---

## [1.1.0] - 2025-09-02

### 🔧 Configuration Improvements

#### ✨ New Features
- **Environment Variable Port Configuration** - Port can now be configured via `DOOROPENER_PORT` environment variable
- **Flexible Configuration Priority** - Environment variables take precedence over config.ini settings
- **Docker Environment Integration** - Seamless port configuration through .env files and docker-compose

#### 🛠️ Technical Improvements
- **Simplified Docker Setup** - Removed complex startup scripts in favor of environment variable approach
- **Better Configuration Management** - Clear priority order: ENV var → config.ini → default fallback
- **Enhanced Documentation** - Updated README with environment variable best practices

#### 📝 Configuration Priority Order
1. `DOOROPENER_PORT` environment variable (highest priority)
2. `config.ini` `[server]` `port` setting
3. Default fallback: 6532

#### 🐛 Bug Fixes
- Fixed Docker container not respecting config.ini port settings
- Improved port configuration consistency between host and container

---

## [1.0.0] - 2025-09-02

### 🎉 Initial Release

#### ✨ Features
- **Modern Glass Morphism UI** - Premium frosted glass interface with backdrop blur effects
- **Per-User PIN Authentication** - Individual PINs for each resident/user
- **Zigbee Device Integration** - Automatic device detection and real-time battery monitoring
- **Admin Dashboard** - Password-protected admin panel with audit logging
- **Rate Limiting & Security** - Per-IP progressive delays and brute-force protection
- **Docker Containerization** - Complete Docker setup with health checks and resource limits
- **Responsive Design** - Optimized for desktop, tablet, and mobile devices

#### 🔐 Security Features
- Per-IP rate limiting with progressive delays (1s, 2s, 4s, 8s, 16s)
- 5-minute IP lockout after 5 failed attempts
- Secure session management with HTTPOnly cookies
- Input validation and sanitization
- Comprehensive audit logging

#### 🔧 Technical Features
- Home Assistant API integration
- MQTT battery level monitoring
- Real-time status updates
- Custom background image support
- Haptic feedback on mobile devices
- Toast notifications for user feedback

#### 📱 User Interface
- Glass morphism design with backdrop filters
- Color-coded battery indicators
- Interactive button states with animations
- Mobile-optimized touch interface
- Admin access via floating gear icon

#### 🐳 Docker Support
- Multi-stage Docker build
- Health checks and restart policies
- Resource limits (0.5 CPU cores, 256MB RAM)
- Log rotation and volume mounts
- Environment-based configuration

### 🐛 Known Issues
- Admin login persistence: Sessions don't persist across page refreshes
- SESSION_COOKIE_SECURE set to False for local HTTP development

### 🔧 Configuration
- Supports any Home Assistant switch entity
- Configurable user PINs via config.ini
- Customizable admin password
- Environment variable support for secrets
