#!/usr/bin/env bash

set -euo pipefail

repo="babafeng/forward"
base_url="https://api.github.com/repos/$repo/releases"

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd"
        exit 1
    fi
}

detect_os() {
    local uname_s
    uname_s="$(uname -s)"
    case "$uname_s" in
    Linux*) echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW* | MSYS* | CYGWIN*) echo "windows" ;;
    *)
        echo "Unsupported operating system: $uname_s"
        exit 1
        ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
    x86_64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *)
        echo "Unsupported CPU architecture: $arch"
        exit 1
        ;;
    esac
}

default_install_dir() {
    local os="$1"
    if [[ -n "${INSTALL_DIR:-}" ]]; then
        echo "$INSTALL_DIR"
        return
    fi
    if [[ "$os" == "windows" ]]; then
        echo "$HOME/bin"
        return
    fi
    if [[ -w "/usr/local/bin" ]]; then
        echo "/usr/local/bin"
        return
    fi
    echo "$HOME/.local/bin"
}

install_forward() {
    local version="$1"
    local os cpu_arch archive_ext bin_name asset download_url
    local install_dir dest sudo_cmd

    require_cmd curl

    os="$(detect_os)"
    cpu_arch="$(detect_arch)"

    archive_ext="tar.gz"
    bin_name="forward"
    if [[ "$os" == "windows" ]]; then
        archive_ext="zip"
        bin_name="forward.exe"
    fi

    asset="forward_${version}_${os}_${cpu_arch}.${archive_ext}"

    download_url="$(curl -fsSL "$base_url/tags/$version" | \
        grep -Eo "\"browser_download_url\": \"[^\"]*${asset}\"" | \
        awk -F'\"' '{print $4}' | head -n 1)"

    if [[ -z "$download_url" ]]; then
        echo "Download not found for ${os}/${cpu_arch} (${asset})."
        exit 1
    fi

    _forward_tmpdir="$(mktemp -d)"
    trap 'if [[ -n "${_forward_tmpdir:-}" && -d "${_forward_tmpdir}" ]]; then rm -rf "${_forward_tmpdir}"; fi' EXIT

    echo "Downloading forward version $version..."
    curl -fsSL -o "$_forward_tmpdir/$asset" "$download_url"

    echo "Installing forward version $version..."
    if [[ "$archive_ext" == "tar.gz" ]]; then
        require_cmd tar
        tar -xzf "$_forward_tmpdir/$asset" -C "$_forward_tmpdir"
    else
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "$_forward_tmpdir/$asset" -d "$_forward_tmpdir"
        else
            require_cmd tar
            tar -xf "$_forward_tmpdir/$asset" -C "$_forward_tmpdir"
        fi
    fi

    local bin_path="$_forward_tmpdir/$bin_name"
    if [[ ! -f "$bin_path" ]]; then
        bin_path="$(find "$_forward_tmpdir" -maxdepth 2 -type f -name "$bin_name" | head -n 1)"
    fi
    if [[ -z "$bin_path" || ! -f "$bin_path" ]]; then
        echo "Failed to locate $bin_name in archive."
        exit 1
    fi

    install_dir="$(default_install_dir "$os")"
    mkdir -p "$install_dir"

    dest="$install_dir/forward"
    if [[ "$os" == "windows" ]]; then
        dest="$install_dir/forward.exe"
    fi

    sudo_cmd=""
    if [[ ! -w "$install_dir" ]]; then
        if command -v sudo >/dev/null 2>&1; then
            sudo_cmd="sudo"
        else
            echo "No permission to write to $install_dir. Set INSTALL_DIR or run as root."
            exit 1
        fi
    fi

    if [[ "$os" != "windows" ]]; then
        chmod +x "$bin_path"
    fi

    if command -v install >/dev/null 2>&1; then
        $sudo_cmd install -m 0755 "$bin_path" "$dest"
    else
        $sudo_cmd mv "$bin_path" "$dest"
        if [[ "$os" != "windows" ]]; then
            $sudo_cmd chmod +x "$dest"
        fi
    fi

    echo "forward installation completed: $dest version $version"
    if [[ ":$PATH:" != *":$install_dir:"* ]]; then
        echo "Make sure $install_dir is in your PATH."
    fi
}

require_cmd curl
versions=$(curl -fsSL "$base_url" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')

if [[ "${1:-}" == "--install" ]]; then
    latest_version=$(echo "$versions" | head -n 1)
    install_forward "$latest_version"
else
    echo "Available forward versions:"
    select version in $versions; do
        if [[ -n $version ]]; then
            install_forward "$version"
            break
        else
            echo "Invalid choice! Please select a valid option."
        fi
    done
fi
