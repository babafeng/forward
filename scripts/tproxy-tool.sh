#!/usr/bin/env bash

set -euo pipefail

MODE=""
TARGET_HOST=""
SSH_USER="${SSH_USER:-root}"
SSH_PORT="${SSH_PORT:-22}"
LAN_IFACE="br-lan"
TPROXY_PORT="12345"
RULE_PRIORITY="100"
LOOKUP_TABLE="100"
BYPASS_REMOTE=""
NO_CRON=0

BYPASS_CLIENTS=()
BYPASS_DESTS=()

usage() {
    cat <<'EOF'
Usage:
  scripts/tproxy-tool.sh --install <host> [options]
  scripts/tproxy-tool.sh --uninstall <host> [options]
  scripts/tproxy-tool.sh --list <host> [options]

Options:
  --ssh-user <user>          SSH user, default: root
  --ssh-port <port>          SSH port, default: 22
  --lan-iface <iface>        LAN interface to intercept, default: br-lan
  --tproxy-port <port>       Local TProxy port, default: 12345
  --rule-priority <prio>     Policy rule priority, default: 100
  --lookup-table <table>     Policy routing table, default: 100
  --bypass-client <ip>       Bypass a LAN client source IP, repeatable
  --bypass-dest <ip>         Extra destination IP to bypass, repeatable
  --bypass-remote <host>     Bypass a remote hostname by resolving it into xray_server4/xray_server6
  --no-cron                  Do not install the remote cron updater
  -h, --help                 Show help

Examples:
  scripts/tproxy-tool.sh --install 192.168.1.1
  scripts/tproxy-tool.sh --install 192.168.1.1 --bypass-client 192.168.1.100
  scripts/tproxy-tool.sh --install 192.168.1.1 --bypass-remote jp.babafeng.icu
  scripts/tproxy-tool.sh --uninstall 192.168.1.1
  scripts/tproxy-tool.sh --list 192.168.1.1
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
}

info() {
    printf '[INFO] %s\n' "$*"
}

warn() {
    printf '[WARN] %s\n' "$*" >&2
}

confirm_yes() {
    local answer
    read -r -p "$1 Type Yes to continue: " answer
    [[ "$answer" == "Yes" ]]
}

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6() {
    [[ "$1" == *:* ]]
}

join_by() {
    local sep="$1"
    shift || true
    local out=""
    local item
    for item in "$@"; do
        if [[ -n "$out" ]]; then
            out+="$sep"
        fi
        out+="$item"
    done
    printf '%s' "$out"
}

shell_quote() {
    printf "%q" "$1"
}

render_nft_file() {
    local bypass_clients4=()
    local bypass_clients6=()
    local bypass_dests4=()
    local bypass_dests6=()
    local item

    if ((${#BYPASS_CLIENTS[@]} > 0)); then
        for item in "${BYPASS_CLIENTS[@]}"; do
            if is_ipv4 "$item"; then
                bypass_clients4+=("$item")
            elif is_ipv6 "$item"; then
                bypass_clients6+=("$item")
            else
                die "invalid --bypass-client value: $item"
            fi
        done
    fi

    if ((${#BYPASS_DESTS[@]} > 0)); then
        for item in "${BYPASS_DESTS[@]}"; do
            if is_ipv4 "$item"; then
                bypass_dests4+=("$item")
            elif is_ipv6 "$item"; then
                bypass_dests6+=("$item")
            else
                die "invalid --bypass-dest value: $item"
            fi
        done
    fi

    cat <<EOF
# Included inside: table inet fw4 { ... }
# DO NOT define a new table here.

set xray_local4 {
  type ipv4_addr
  flags interval
  elements = {
    0.0.0.0/8,
    10.0.0.0/8,
    100.64.0.0/10,
    127.0.0.0/8,
    169.254.0.0/16,
    172.16.0.0/12,
    192.168.0.0/16,
    224.0.0.0/4,
    240.0.0.0/4
  }
}

set xray_local6 {
  type ipv6_addr
  flags interval
  elements = {
    ::1/128,
    fc00::/7,
    fe80::/10
  }
}

set xray_server4 { type ipv4_addr; flags interval; }
set xray_server6 { type ipv6_addr; flags interval; }

chain xray_prerouting {
  type filter hook prerouting priority mangle; policy accept;

  # 只抓 LAN 进来的流量。
  iifname != "$(shell_quote "$LAN_IFACE")" return
EOF

    if ((${#bypass_clients4[@]} > 0)); then
        printf '  ip saddr { %s } return\n' "$(join_by ', ' "${bypass_clients4[@]}")"
    fi
    if ((${#bypass_clients6[@]} > 0)); then
        printf '  ip6 saddr { %s } return\n' "$(join_by ', ' "${bypass_clients6[@]}")"
    fi
    if ((${#bypass_dests4[@]} > 0)); then
        printf '  ip daddr { %s } return\n' "$(join_by ', ' "${bypass_dests4[@]}")"
    fi
    if ((${#bypass_dests6[@]} > 0)); then
        printf '  ip6 daddr { %s } return\n' "$(join_by ', ' "${bypass_dests6[@]}")"
    fi

    cat <<EOF

  # ===== bypass 保留网段 / 远端服务 =====
  ip daddr @xray_local4 return
  ip daddr @xray_server4 return
  ip6 daddr @xray_local6 return
  ip6 daddr @xray_server6 return

  # DNS 不走透明代理。
  udp dport 53 return
  tcp dport 53 return

  # DHCP / DHCPv6 不走透明代理。
  udp dport { 67, 68 } return
  udp sport { 67, 68 } return
  udp dport { 546, 547 } return
  udp sport { 546, 547 } return

  # 其余 TCP / UDP 进入 TProxy。
  meta l4proto { tcp, udp } counter tproxy to :${TPROXY_PORT} meta mark set 0x1 accept
}
EOF
}

build_remote_install_script() {
    local nft_payload
    nft_payload="$(render_nft_file)"

    cat <<EOF
#!/bin/sh
set -eu

RULE_FILE="/etc/nftables.d/90-xray-tproxy.nft"
LOOKUP_TABLE=$(shell_quote "$LOOKUP_TABLE")
RULE_PRIORITY=$(shell_quote "$RULE_PRIORITY")
TPROXY_PORT=$(shell_quote "$TPROXY_PORT")
BYPASS_REMOTE=$(shell_quote "$BYPASS_REMOTE")
NO_CRON=$(shell_quote "$NO_CRON")

has_bypass_changes() {
  [ -n "$BYPASS_REMOTE" ] && return 0
  grep -qE '^[[:space:]]+ip saddr \{' "$RULE_FILE" 2>/dev/null && return 0
  grep -qE '^[[:space:]]+ip6 saddr \{' "$RULE_FILE" 2>/dev/null && return 0
  grep -qE '^[[:space:]]+ip daddr \{' "$RULE_FILE" 2>/dev/null && return 0
  grep -qE '^[[:space:]]+ip6 daddr \{' "$RULE_FILE" 2>/dev/null && return 0
  return 1
}

network_config_exists() {
  uci -q get network.forward_tproxy4 >/dev/null 2>&1 &&
  uci -q get network.forward_tproxy6 >/dev/null 2>&1 &&
  uci -q get network.forward_tproxy_route4 >/dev/null 2>&1 &&
  uci -q get network.forward_tproxy_route6 >/dev/null 2>&1
}

EXISTED_BEFORE=0
if network_config_exists; then
  EXISTED_BEFORE=1
fi

ensure_network_config() {
  uci -q delete network.forward_tproxy4 || true
  uci -q delete network.forward_tproxy6 || true
  uci -q delete network.forward_tproxy_route4 || true
  uci -q delete network.forward_tproxy_route6 || true

  uci set network.forward_tproxy4='rule'
  uci set network.forward_tproxy4.priority="\$RULE_PRIORITY"
  uci set network.forward_tproxy4.mark='0x1/0x1'
  uci set network.forward_tproxy4.lookup="\$LOOKUP_TABLE"
  uci set network.forward_tproxy4.family='ipv4'

  uci set network.forward_tproxy6='rule'
  uci set network.forward_tproxy6.priority="\$RULE_PRIORITY"
  uci set network.forward_tproxy6.mark='0x1/0x1'
  uci set network.forward_tproxy6.lookup="\$LOOKUP_TABLE"
  uci set network.forward_tproxy6.family='ipv6'

  uci set network.forward_tproxy_route4='route'
  uci set network.forward_tproxy_route4.interface='lo'
  uci set network.forward_tproxy_route4.target='0.0.0.0/0'
  uci set network.forward_tproxy_route4.table="\$LOOKUP_TABLE"
  uci set network.forward_tproxy_route4.type='local'

  uci set network.forward_tproxy_route6='route6'
  uci set network.forward_tproxy_route6.interface='lo'
  uci set network.forward_tproxy_route6.target='::/0'
  uci set network.forward_tproxy_route6.table="\$LOOKUP_TABLE"
  uci set network.forward_tproxy_route6.type='local'

  uci commit network
}

write_nft_file() {
  cat >"\$RULE_FILE" <<'NFT_EOF'
$nft_payload
NFT_EOF
}

install_remote_updater() {
  [ -n "\$BYPASS_REMOTE" ] || return 0

  cat >/usr/bin/update-xray-bypass.sh <<'SCRIPT_EOF'
#!/bin/sh
set -eu

HOST="$(shell_quote "$BYPASS_REMOTE")"
NFT="/usr/sbin/nft"
TABLE_FAMILY="inet"
TABLE_NAME="fw4"
SET4="xray_server4"
SET6="xray_server6"

resolve_ips() {
  nslookup "\$HOST" 2>/dev/null | awk '/^Address: /{print \$2}'
}

IPS="\$(resolve_ips || true)"
[ -n "\$IPS" ] || {
  echo "Failed to resolve \$HOST" >&2
  exit 1
}

\$NFT list set \$TABLE_FAMILY \$TABLE_NAME \$SET4 >/dev/null 2>&1 || \
  \$NFT add set \$TABLE_FAMILY \$TABLE_NAME \$SET4 "{ type ipv4_addr; flags interval; }"
\$NFT list set \$TABLE_FAMILY \$TABLE_NAME \$SET6 >/dev/null 2>&1 || \
  \$NFT add set \$TABLE_FAMILY \$TABLE_NAME \$SET6 "{ type ipv6_addr; flags interval; }"

\$NFT flush set \$TABLE_FAMILY \$TABLE_NAME \$SET4
\$NFT flush set \$TABLE_FAMILY \$TABLE_NAME \$SET6

for ip in \$IPS; do
  case "\$ip" in
    *:*) \$NFT add element \$TABLE_FAMILY \$TABLE_NAME \$SET6 "{ \$ip }" ;;
    *)   \$NFT add element \$TABLE_FAMILY \$TABLE_NAME \$SET4 "{ \$ip }" ;;
  esac
done
SCRIPT_EOF

  chmod +x /usr/bin/update-xray-bypass.sh
  /usr/bin/update-xray-bypass.sh

  if [ "\$NO_CRON" != "1" ]; then
    grep -Fqx '*/10 * * * * /usr/bin/update-xray-bypass.sh >/dev/null 2>&1' /etc/crontabs/root 2>/dev/null || \
      printf '%s\n' '*/10 * * * * /usr/bin/update-xray-bypass.sh >/dev/null 2>&1' >> /etc/crontabs/root
    /etc/init.d/cron restart
  fi
}

apply_runtime() {
  if [ "$EXISTED_BEFORE" = "1" ] && has_bypass_changes; then
    :
  else
    /etc/init.d/network restart
  fi
  fw4 reload
}

ensure_network_config
write_nft_file
install_remote_updater
apply_runtime

echo "Installed transparent proxy policy."
echo "Rule file: \$RULE_FILE"
echo "TProxy port: \$TPROXY_PORT"
echo "Check with: ip rule show; ip -6 rule show; ip route show table \$LOOKUP_TABLE; ip -6 route show table \$LOOKUP_TABLE; nft list chain inet fw4 xray_prerouting"
EOF
}

build_remote_uninstall_script() {
    cat <<EOF
#!/bin/sh
set -eu

RULE_FILE="/etc/nftables.d/90-xray-tproxy.nft"
LOOKUP_TABLE=$(shell_quote "$LOOKUP_TABLE")

delete_anonymous_network_rules() {
  local idx section mark lookup priority family
  idx=0
  while uci -q get "network.@rule[\$idx]" >/dev/null 2>&1; do
    section="network.@rule[\$idx]"
    mark="\$(uci -q get "\$section.mark" || true)"
    lookup="\$(uci -q get "\$section.lookup" || true)"
    priority="\$(uci -q get "\$section.priority" || true)"
    family="\$(uci -q get "\$section.family" || true)"
    if [ "\$lookup" = "\$LOOKUP_TABLE" ] && [ "\$priority" = '100' ]; then
      case "\$mark" in
        0x1|0x1/0x1)
          uci -q delete "\$section" || true
          continue
          ;;
      esac
      if [ "\$family" = 'ipv4' ] || [ "\$family" = 'ipv6' ] || [ -z "\$family" ]; then
        uci -q delete "\$section" || true
        continue
      fi
    fi
    idx=\$((idx + 1))
  done

  idx=0
  while uci -q get "network.@route[\$idx]" >/dev/null 2>&1; do
    section="network.@route[\$idx]"
    if [ "\$(uci -q get "\$section.interface" || true)" = 'lo' ] && \
       [ "\$(uci -q get "\$section.table" || true)" = "\$LOOKUP_TABLE" ] && \
       [ "\$(uci -q get "\$section.type" || true)" = 'local' ] && \
       [ "\$(uci -q get "\$section.target" || true)" = '0.0.0.0/0' ]; then
      uci -q delete "\$section" || true
      continue
    fi
    idx=\$((idx + 1))
  done

  idx=0
  while uci -q get "network.@route6[\$idx]" >/dev/null 2>&1; do
    section="network.@route6[\$idx]"
    if [ "\$(uci -q get "\$section.interface" || true)" = 'lo' ] && \
       [ "\$(uci -q get "\$section.table" || true)" = "\$LOOKUP_TABLE" ] && \
       [ "\$(uci -q get "\$section.type" || true)" = 'local' ] && \
       [ "\$(uci -q get "\$section.target" || true)" = '::/0' ]; then
      uci -q delete "\$section" || true
      continue
    fi
    idx=\$((idx + 1))
  done
}

cleanup_nft_runtime() {
  nft delete chain inet fw4 xray_prerouting >/dev/null 2>&1 || true
  nft delete set inet fw4 xray_server4 >/dev/null 2>&1 || true
  nft delete set inet fw4 xray_server6 >/dev/null 2>&1 || true
}

uci -q delete network.forward_tproxy4 || true
uci -q delete network.forward_tproxy6 || true
uci -q delete network.forward_tproxy_route4 || true
uci -q delete network.forward_tproxy_route6 || true
delete_anonymous_network_rules
uci commit network

rm -f "\$RULE_FILE"
rm -f /usr/bin/update-xray-bypass.sh

if [ -f /etc/crontabs/root ]; then
  tmp_file="\$(mktemp)"
  grep -Fv '*/10 * * * * /usr/bin/update-xray-bypass.sh >/dev/null 2>&1' /etc/crontabs/root >"\$tmp_file" || true
  cat "\$tmp_file" >/etc/crontabs/root
  rm -f "\$tmp_file"
  /etc/init.d/cron restart
fi

/etc/init.d/network restart
cleanup_nft_runtime
fw4 reload

echo "Uninstalled transparent proxy policy."
EOF
}

build_remote_list_script() {
    cat <<'EOF'
#!/bin/sh
set -eu

echo "=== ip rule (ipv4) ==="
ip rule show | grep -E '(^0:|lookup 100|lookup local|lookup main|lookup default)' || true
echo

echo "=== ip route table 100 (ipv4) ==="
ip route show table 100 || true
echo

echo "=== ip rule (ipv6) ==="
ip -6 rule show | grep -E '(^0:|lookup 100|lookup local|lookup main|lookup default)' || true
echo

echo "=== ip route table 100 (ipv6) ==="
ip -6 route show table 100 || true
echo

echo "=== network tproxy sections ==="
uci show network | grep -E 'forward_tproxy|@rule\[|@route\[|@route6\[' || true
echo

echo "=== firewall includes ==="
uci show firewall | grep -E "(include|path=|type='script')" || true
echo

echo "=== nft xray_prerouting ==="
nft list chain inet fw4 xray_prerouting 2>/dev/null || true
echo

echo "=== nft bypass sets ==="
nft list set inet fw4 xray_server4 2>/dev/null || true
nft list set inet fw4 xray_server6 2>/dev/null || true
echo

echo "=== rule file ==="
cat /etc/nftables.d/90-xray-tproxy.nft 2>/dev/null || true
echo

echo "=== listeners/processes ==="
netstat -lntup 2>/dev/null | grep -E '(:12345\b|:7895\b|:7892\b|:7893\b|:7890\b|:7891\b|:7874\b)' || true
ps w | grep -E '[x]ray|[s]ing-box|[c]lash|[m]ihomo' || true

EOF
}

run_remote_script() {
    local script_text="$1"
    ssh -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "${SSH_USER}@${TARGET_HOST}" 'sh -s' <<<"$script_text"
}

run_remote_script_detached() {
    local script_text="$1"
    local op_name="$2"
    local remote_script="/tmp/tproxy-tool-${op_name}-$$.sh"
    local remote_log="/tmp/tproxy-tool-${op_name}-$$.log"

    ssh -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "${SSH_USER}@${TARGET_HOST}" \
        "cat > $(shell_quote "$remote_script") && chmod +x $(shell_quote "$remote_script") && nohup $(shell_quote "$remote_script") >$(shell_quote "$remote_log") 2>&1 </dev/null & printf '%s\n' $(shell_quote "$remote_log")" \
        <<<"$script_text"
}

remote_network_config_exists() {
    ssh -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "${SSH_USER}@${TARGET_HOST}" \
        "uci -q get network.forward_tproxy4 >/dev/null 2>&1 && \
         uci -q get network.forward_tproxy6 >/dev/null 2>&1 && \
         uci -q get network.forward_tproxy_route4 >/dev/null 2>&1 && \
         uci -q get network.forward_tproxy_route6 >/dev/null 2>&1"
}

has_bypass_options() {
    ((${#BYPASS_CLIENTS[@]} > 0)) && return 0
    ((${#BYPASS_DESTS[@]} > 0)) && return 0
    [[ -n "$BYPASS_REMOTE" ]] && return 0
    return 1
}

install_requires_network_restart() {
    if ! has_bypass_options; then
        return 0
    fi
    if remote_network_config_exists; then
        return 1
    fi
    return 0
}

wait_for_reconnect() {
    info "OpenWrt will restart network. Wait about 30 seconds and reconnect Wi-Fi."
    sleep 30
    while true; do
        if ssh -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            -o ConnectTimeout=5 "${SSH_USER}@${TARGET_HOST}" 'true' >/dev/null 2>&1; then
            info "Wi-Fi reconnected. Listing current transparent proxy state."
            break
        fi
        info "Waiting for Wi-Fi reconnection to ${TARGET_HOST}..."
        sleep 5
    done
    run_remote_script "$(build_remote_list_script)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
    --install)
        MODE="install"
        TARGET_HOST="${2:-}"
        shift 2
        ;;
    --uninstall)
        MODE="uninstall"
        TARGET_HOST="${2:-}"
        shift 2
        ;;
    --list)
        MODE="list"
        TARGET_HOST="${2:-}"
        shift 2
        ;;
    --ssh-user)
        SSH_USER="${2:-}"
        shift 2
        ;;
    --ssh-port)
        SSH_PORT="${2:-}"
        shift 2
        ;;
    --lan-iface)
        LAN_IFACE="${2:-}"
        shift 2
        ;;
    --tproxy-port)
        TPROXY_PORT="${2:-}"
        shift 2
        ;;
    --rule-priority)
        RULE_PRIORITY="${2:-}"
        shift 2
        ;;
    --lookup-table)
        LOOKUP_TABLE="${2:-}"
        shift 2
        ;;
    --bypass-client)
        BYPASS_CLIENTS+=("${2:-}")
        shift 2
        ;;
    --bypass-dest)
        BYPASS_DESTS+=("${2:-}")
        shift 2
        ;;
    --bypass-remote)
        BYPASS_REMOTE="${2:-}"
        shift 2
        ;;
    --no-cron)
        NO_CRON=1
        shift
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

[[ -n "$MODE" ]] || {
    usage
    exit 1
}
[[ -n "$TARGET_HOST" ]] || die "missing target host"

require_cmd ssh

case "$MODE" in
install)
    if install_requires_network_restart; then
        warn "Installing transparent proxy will restart OpenWrt network and your Wi-Fi/network connection will disconnect temporarily."
        confirm_yes "Proceed with install?" || die "installation cancelled"
        info "Starting transparent proxy installation. Network will disconnect temporarily."
        run_remote_script_detached "$(build_remote_install_script)" "install" >/dev/null
        wait_for_reconnect
    else
        info "Updating transparent proxy bypass rules. This will reload firewall rules and may briefly affect existing connections."
        run_remote_script "$(build_remote_install_script)"
        info "Bypass update completed. Listing current transparent proxy state."
        run_remote_script "$(build_remote_list_script)"
    fi
    ;;
uninstall)
    warn "Uninstalling transparent proxy will restart OpenWrt network and your Wi-Fi/network connection will disconnect temporarily."
    confirm_yes "Proceed with uninstall?" || die "uninstall cancelled"
    info "Starting transparent proxy uninstall. Network will disconnect temporarily."
    run_remote_script_detached "$(build_remote_uninstall_script)" "uninstall" >/dev/null
    wait_for_reconnect
    ;;
list)
    info "Listing key transparent proxy route and firewall settings."
    run_remote_script "$(build_remote_list_script)"
    ;;
esac
