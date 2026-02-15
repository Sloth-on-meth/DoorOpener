#!/bin/sh
set -e

# Default UID/GID pattern inspired by linuxserver.io containers
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"
UMASK="${UMASK:-002}"
APP_USER="appuser"
APP_GROUP="appgroup"
LOG_DIR="/app/logs"

apply_umask() {
  # shellcheck disable=SC2039
  umask "$UMASK" 2>/dev/null || true
}

if [ "$(id -u)" = "0" ]; then
  # Create/adjust group
  if getent group "${APP_GROUP}" >/dev/null 2>&1; then
    groupmod -o -g "${PGID}" "${APP_GROUP}" 2>/dev/null || true
  else
    groupadd -o -g "${PGID}" "${APP_GROUP}" 2>/dev/null || groupadd "${APP_GROUP}" || true
  fi

  # Create/adjust user
  if id "${APP_USER}" >/dev/null 2>&1; then
    usermod -o -u "${PUID}" -g "${APP_GROUP}" "${APP_USER}" 2>/dev/null || true
  else
    useradd -o -u "${PUID}" -g "${APP_GROUP}" -M -s /usr/sbin/nologin "${APP_USER}" 2>/dev/null || useradd -M -s /usr/sbin/nologin "${APP_USER}" || true
  fi

  # Ensure log dir exists and is owned by runtime user
  mkdir -p "${LOG_DIR}" || true
  chown -R "${PUID}:${PGID}" "${LOG_DIR}" 2>/dev/null || true
  chmod -R g+rwX "${LOG_DIR}" 2>/dev/null || true

  apply_umask

  # Drop privileges to app user for the main process
  exec gosu "${APP_USER}:${APP_GROUP}" "$@"
else
  # Already non-root; just run
  apply_umask
  exec "$@"
fi
