#!/usr/bin/env bash

set -euo pipefail

NAME="forward"
LABEL=""
BIN=""
MODE=""
WORKDIR=""
NO_START=0
REMOVE=0
ARGS=()

usage() {
    cat <<'EOF'
Usage:
  scripts/register-service.sh [options] -- <forward args>

Options:
  --name <name>         Service name (default: forward)
  --label <label>       launchd label (macOS only, default: --name)
  --bin <path>          Path to forward binary (default: from PATH)
  --working-dir <dir>   Working directory for the service
  --system              Install as system service (root required)
  --user                Install as user service
  --remove              Unregister and remove the service
  --no-start            Write service files only, do not load/enable
  -h, --help            Show help

Examples:
  # Linux/macOS user service
  scripts/register-service.sh -- --L tcp://:8080/1.2.3.4:80

  # Linux system service (run as root or with sudo)
  scripts/register-service.sh --system -- --L tcp://:8080/1.2.3.4:80

  # macOS user service
  scripts/register-service.sh -- --L http://:1080
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

systemd_quote() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '"%s"' "$s"
}

xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&apos;}"
    printf '%s' "$s"
}

detect_os() {
    local uname_s
    uname_s="$(uname -s)"
    case "$uname_s" in
    Linux*) echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *) die "unsupported OS: $uname_s" ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
    --name)
        NAME="$2"
        shift 2
        ;;
    --label)
        LABEL="$2"
        shift 2
        ;;
    --bin)
        BIN="$2"
        shift 2
        ;;
    --working-dir)
        WORKDIR="$2"
        shift 2
        ;;
    --system)
        MODE="system"
        shift
        ;;
    --user)
        MODE="user"
        shift
        ;;
    --remove | --uninstall)
        REMOVE=1
        shift
        ;;
    --no-start)
        NO_START=1
        shift
        ;;
    --)
        shift
        ARGS=("$@")
        break
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        die "unknown option: $1"
        ;;
    esac
done

if [[ -z "$BIN" ]]; then
    BIN="$(command -v forward || true)"
fi
if [[ -z "$BIN" ]]; then
    die "forward binary not found; use --bin <path>"
fi

OS="$(detect_os)"
if [[ -z "$MODE" ]]; then
    if [[ "$OS" == "linux" ]]; then
        MODE="system"
    else
        MODE="user"
    fi
fi

if [[ -z "$LABEL" ]]; then
    LABEL="$NAME"
fi

install_linux() {
    command -v systemctl >/dev/null 2>&1 || die "systemctl not found"

    local unit_dir unit_path sudo_cmd
    local systemctl_cmd=()

    if [[ "$MODE" == "user" ]]; then
        unit_dir="$HOME/.config/systemd/user"
        systemctl_cmd=(systemctl --user)
    else
        unit_dir="/etc/systemd/system"
        if [[ "$(id -u)" -ne 0 ]]; then
            if command -v sudo >/dev/null 2>&1; then
                sudo_cmd="sudo"
            else
                die "system install requires root or sudo"
            fi
        fi
        if [[ -n "${sudo_cmd:-}" ]]; then
            systemctl_cmd=(sudo systemctl)
        else
            systemctl_cmd=(systemctl)
        fi
    fi

    unit_path="$unit_dir/${NAME}.service"

    if [[ "$REMOVE" -eq 1 ]]; then
        "${systemctl_cmd[@]}" disable --now "$NAME" >/dev/null 2>&1 || true
        if [[ -n "${sudo_cmd:-}" ]]; then
            sudo rm -f "$unit_path"
        else
            rm -f "$unit_path"
        fi
        "${systemctl_cmd[@]}" daemon-reload
        echo "Removed systemd unit: $unit_path"
        return
    fi

    local exec_line
    exec_line="$(systemd_quote "$BIN")"
    for arg in "${ARGS[@]}"; do
        exec_line+=" $(systemd_quote "$arg")"
    done

    if [[ -n "${sudo_cmd:-}" ]]; then
        sudo mkdir -p "$unit_dir"
        cat <<EOF | sudo tee "$unit_path" >/dev/null
[Unit]
Description=forward service ($NAME)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$exec_line
Restart=on-failure
RestartSec=5
EOF
    else
        mkdir -p "$unit_dir"
        cat <<EOF >"$unit_path"
[Unit]
Description=forward service ($NAME)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$exec_line
Restart=on-failure
RestartSec=5
EOF
    fi

    if [[ -n "$WORKDIR" ]]; then
        if [[ -n "${sudo_cmd:-}" ]]; then
            printf "WorkingDirectory=%s\n" "$WORKDIR" | sudo tee -a "$unit_path" >/dev/null
        else
            printf "WorkingDirectory=%s\n" "$WORKDIR" >>"$unit_path"
        fi
    fi

    if [[ "$MODE" == "user" ]]; then
        if [[ -n "${sudo_cmd:-}" ]]; then
            printf "\n[Install]\nWantedBy=default.target\n" | sudo tee -a "$unit_path" >/dev/null
        else
            printf "\n[Install]\nWantedBy=default.target\n" >>"$unit_path"
        fi
    else
        if [[ -n "${sudo_cmd:-}" ]]; then
            printf "\n[Install]\nWantedBy=multi-user.target\n" | sudo tee -a "$unit_path" >/dev/null
        else
            printf "\n[Install]\nWantedBy=multi-user.target\n" >>"$unit_path"
        fi
    fi

    "${systemctl_cmd[@]}" daemon-reload
    if [[ "$NO_START" -eq 1 ]]; then
        echo "Wrote systemd unit: $unit_path"
        return
    fi
    "${systemctl_cmd[@]}" enable --now "$NAME"
    echo "Installed systemd unit: $unit_path"
}

install_macos() {
    command -v launchctl >/dev/null 2>&1 || die "launchctl not found"

    local plist_dir plist_path sudo_cmd domain

    if [[ "$MODE" == "user" ]]; then
        plist_dir="$HOME/Library/LaunchAgents"
        domain="gui/$(id -u)"
    else
        plist_dir="/Library/LaunchDaemons"
        domain="system"
        if [[ "$(id -u)" -ne 0 ]]; then
            if command -v sudo >/dev/null 2>&1; then
                sudo_cmd="sudo"
            else
                die "system install requires root or sudo"
            fi
        fi
    fi

    plist_path="$plist_dir/${LABEL}.plist"

    local args_xml=""
    local arg
    for arg in "$BIN" "${ARGS[@]}"; do
        args_xml+="        <string>$(xml_escape "$arg")</string>"$'\n'
    done

    if [[ "$REMOVE" -eq 1 ]]; then
        if launchctl help bootstrap >/dev/null 2>&1; then
            if [[ -n "${sudo_cmd:-}" ]]; then
                sudo launchctl bootout "$domain" "$plist_path" >/dev/null 2>&1 || true
            else
                launchctl bootout "$domain" "$plist_path" >/dev/null 2>&1 || true
            fi
        else
            if [[ -n "${sudo_cmd:-}" ]]; then
                sudo launchctl unload -w "$plist_path" >/dev/null 2>&1 || true
            else
                launchctl unload -w "$plist_path" >/dev/null 2>&1 || true
            fi
        fi
        if [[ -n "${sudo_cmd:-}" ]]; then
            sudo rm -f "$plist_path"
        else
            rm -f "$plist_path"
        fi
        echo "Removed launchd plist: $plist_path"
        return
    fi

    if [[ -n "${sudo_cmd:-}" ]]; then
        sudo mkdir -p "$plist_dir"
        {
            cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
${args_xml}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
EOF
            if [[ -n "$WORKDIR" ]]; then
                printf '    <key>WorkingDirectory</key>\n    <string>%s</string>\n' "$(xml_escape "$WORKDIR")"
            fi
            cat <<EOF
</dict>
</plist>
EOF
        } | sudo tee "$plist_path" >/dev/null
    else
        mkdir -p "$plist_dir"
        {
            cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
${args_xml}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
EOF
            if [[ -n "$WORKDIR" ]]; then
                printf '    <key>WorkingDirectory</key>\n    <string>%s</string>\n' "$(xml_escape "$WORKDIR")"
            fi
            cat <<EOF
</dict>
</plist>
EOF
        } >"$plist_path"
    fi

    if [[ "$NO_START" -eq 1 ]]; then
        echo "Wrote launchd plist: $plist_path"
        return
    fi

    if launchctl help bootstrap >/dev/null 2>&1; then
        if [[ -n "${sudo_cmd:-}" ]]; then
            sudo launchctl bootout "$domain" "$plist_path" >/dev/null 2>&1 || true
            sudo launchctl bootstrap "$domain" "$plist_path"
            sudo launchctl enable "$domain/$LABEL" >/dev/null 2>&1 || true
            sudo launchctl kickstart -k "$domain/$LABEL"
        else
            launchctl bootout "$domain" "$plist_path" >/dev/null 2>&1 || true
            launchctl bootstrap "$domain" "$plist_path"
            launchctl enable "$domain/$LABEL" >/dev/null 2>&1 || true
            launchctl kickstart -k "$domain/$LABEL"
        fi
    else
        if [[ -n "${sudo_cmd:-}" ]]; then
            sudo launchctl unload -w "$plist_path" >/dev/null 2>&1 || true
            sudo launchctl load -w "$plist_path"
        else
            launchctl unload -w "$plist_path" >/dev/null 2>&1 || true
            launchctl load -w "$plist_path"
        fi
    fi

    echo "Installed launchd plist: $plist_path"
}

case "$OS" in
linux) install_linux ;;
darwin) install_macos ;;
esac
