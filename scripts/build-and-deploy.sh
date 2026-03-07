#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-forward}"
REMOTE_BIN="${REMOTE_BIN:-/usr/local/bin/forward}"
LOCAL_BIN="${LOCAL_BIN:-forward}"

usage() {
    cat <<'EOF'
Usage:
  scripts/build-and-deploy.sh <user@host> [remote_bin_path] [service_name]

Examples:
  scripts/build-and-deploy.sh root@192.168.1.10
  scripts/build-and-deploy.sh root@192.168.1.10 /usr/local/bin/forward forward

Environment overrides:
  LOCAL_BIN     Local output binary name (default: forward)
  REMOTE_BIN    Remote binary path (default: /usr/local/bin/forward)
  SERVICE_NAME  systemd service name (default: forward)
EOF
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd" >&2
        exit 1
    fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    usage >&2
    exit 1
fi

if [[ -n "${2:-}" ]]; then
    REMOTE_BIN="$2"
fi

if [[ -n "${3:-}" ]]; then
    SERVICE_NAME="$3"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_REMOTE_BIN="${REMOTE_BIN}.tmp"

require_cmd go
require_cmd ssh
require_cmd scp

cd "$REPO_ROOT"

echo "Building ${LOCAL_BIN} for linux/amd64..."
GOOS=linux GOARCH=amd64 go build -o "$LOCAL_BIN" ./cmd/forward

echo "Stopping service ${SERVICE_NAME} on ${TARGET}..."
ssh "$TARGET" "systemctl stop '${SERVICE_NAME}'"

echo "Uploading ${LOCAL_BIN} to ${TARGET}:${TMP_REMOTE_BIN}..."
scp "$LOCAL_BIN" "${TARGET}:${TMP_REMOTE_BIN}"

echo "Installing binary to ${REMOTE_BIN}..."
ssh "$TARGET" "install -m 0755 '${TMP_REMOTE_BIN}' '${REMOTE_BIN}' && rm -f '${TMP_REMOTE_BIN}'"

echo "Starting service ${SERVICE_NAME} on ${TARGET}..."
ssh "$TARGET" "systemctl start '${SERVICE_NAME}'"

echo "Deployment finished."
