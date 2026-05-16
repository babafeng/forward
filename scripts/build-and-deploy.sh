#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-forward}"
REMOTE_BIN="${REMOTE_BIN:-/usr/local/bin/forward}"
LOCAL_BIN="${LOCAL_BIN:-forward}"

usage() {
    cat <<'EOF'
Usage:
  scripts/build-and-deploy.sh                 Local build and install to /usr/local/bin or ~/.local/bin
  scripts/build-and-deploy.sh <user@host> [remote_bin_path] [service_name]

Examples:
  scripts/build-and-deploy.sh
  scripts/build-and-deploy.sh root@192.168.1.1
  scripts/build-and-deploy.sh root@192.168.1.1 /usr/bin/forward forward

Environment overrides:
  LOCAL_BIN     Local output binary name (default: forward)
  REMOTE_BIN    Remote binary path (default: /usr/bin/forward for remote, auto-detect for local)
  SERVICE_NAME  System service name (default: forward)
EOF
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd" >&2
        exit 1
    fi
}

map_goarch() {
    local arch="$1"
    case "$arch" in
    x86_64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    mips) echo "mips" ;;
    mipsle) echo "mipsle" ;;
    *)
        echo "Unsupported CPU architecture: $arch" >&2
        exit 1
        ;;
    esac
}

detect_local_os() {
    uname -s | tr '[:upper:]' '[:lower:]'
}

detect_local_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
    x86_64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *) echo "$arch" ;;
    esac
}

default_local_install_dir() {
    if [[ -w "/usr/local/bin" ]]; then
        echo "/usr/local/bin"
    else
        echo "$HOME/.local/bin"
    fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# 获取编译参数
BUILD_LDFLAGS="-s -w"
BUILD_FLAGS="-trimpath"

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    # --- 本地安装模式 ---
    OS="$(detect_local_os)"
    ARCH="$(detect_local_arch)"
    INSTALL_DIR="$(default_local_install_dir)"

    BIN_NAME="$LOCAL_BIN"
    if [[ "$OS" == "msys"* || "$OS" == "mingw"* || "$OS" == "cygwin"* ]]; then
        BIN_NAME="${LOCAL_BIN}.exe"
    fi

    echo "Building ${BIN_NAME} for local ${OS}/${ARCH}..."
    CGO_ENABLED=0 go build $BUILD_FLAGS -ldflags="$BUILD_LDFLAGS" -o "$BIN_NAME" ./cmd/forward

    echo "Installing to ${INSTALL_DIR}/${BIN_NAME}..."
    mkdir -p "$INSTALL_DIR"

    SUDO_CMD=""
    if [[ ! -w "$INSTALL_DIR" ]] && command -v sudo >/dev/null 2>&1; then
        SUDO_CMD="sudo"
    fi

    if command -v install >/dev/null 2>&1; then
        $SUDO_CMD install -m 0755 "$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
    else
        $SUDO_CMD cp "$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
        [[ "$OS" != "windows" ]] && $SUDO_CMD chmod +x "$INSTALL_DIR/$BIN_NAME"
    fi

    echo "Local installation finished."
else
    # --- 远程部署模式 ---
    if [[ -n "${2:-}" ]]; then
        REMOTE_BIN="$2"
    fi
    if [[ -n "${3:-}" ]]; then
        SERVICE_NAME="$3"
    fi

    TMP_REMOTE_BIN="${REMOTE_BIN}.tmp"

    require_cmd go
    require_cmd ssh
    require_cmd scp

    # 检测如何忽略 ssh 的 Post-Quantum Key Exchange 警告
    SSH_OPT=""
    if ssh -o WarnWeakCrypto=no-pq-kex -V >/dev/null 2>&1; then
        SSH_OPT="-o WarnWeakCrypto=no-pq-kex"
    fi

    echo "Detecting remote CPU architecture on ${TARGET}..."
    REMOTE_UNAME_ARCH="$(ssh $SSH_OPT "$TARGET" "uname -m")"
    REMOTE_GOARCH="$(map_goarch "$REMOTE_UNAME_ARCH")"

    echo "Building ${LOCAL_BIN} for linux/${REMOTE_GOARCH}..."
    CGO_ENABLED=0 GOOS=linux GOARCH="$REMOTE_GOARCH" go build $BUILD_FLAGS -ldflags="$BUILD_LDFLAGS" -o "$LOCAL_BIN" ./cmd/forward

    echo "Uploading ${LOCAL_BIN} to ${TARGET}:${TMP_REMOTE_BIN}..."
    # 确保远程目录存在
    ssh $SSH_OPT "$TARGET" "mkdir -p '$(dirname "${REMOTE_BIN}")'"

    # 尝试检查 scp 是否支持 -O 选项
    SCP_CMD="scp"
    if scp -O 2>&1 | grep -q 'illegal option\|unknown option'; then
        # 不支持 -O（较旧的 scp，默认使用原生协议）
        SCP_CMD="scp"
    elif scp 2>&1 | grep -q '\[-O\]\|\[.*O.*\]'; then
        # 支持 -O（较新的 scp，默认可能是 sftp，需要 -O 强制使用原生协议）
        SCP_CMD="scp -O"
    else
        # 兼容处理
        SCP_CMD="scp -O"
    fi

    echo "Using command: $SCP_CMD $SSH_OPT"
    if ! $SCP_CMD $SSH_OPT "$LOCAL_BIN" "${TARGET}:${TMP_REMOTE_BIN}"; then
        echo "Upload failed."
        exit 1
    fi

    echo "Installing binary to ${REMOTE_BIN}..."
    # OpenWrt 的 install 命令可能在不同路径或不可用，使用 cp + chmod 作为兜底
    ssh $SSH_OPT "$TARGET" "cp '${TMP_REMOTE_BIN}' '${REMOTE_BIN}' && chmod 0755 '${REMOTE_BIN}' && rm -f '${TMP_REMOTE_BIN}'"

    echo "Deployment finished."
fi
