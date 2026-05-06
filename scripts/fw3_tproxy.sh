#!/bin/sh

# OpenWrt fw3 / iptables transparent proxy helper for forward -T.
# TCP and UDP are both handled with TPROXY. Do not use nat REDIRECT here:
# REDIRECT rewrites the TCP destination to the proxy port and breaks the
# original destination port used by transparent proxy sniffing.

PROXY_PORT="${PROXY_PORT:-12345}"
FWMARK="${FWMARK:-0x50}"
ROUTE_TABLE="${ROUTE_TABLE:-150}"
LAN_SUBNET="${LAN_SUBNET:-192.168.0.0/16}"
CHAIN="FORWARD_TPROXY"
LEGACY_NAT_CHAIN="PROXY_TCP"
LEGACY_MANGLE_CHAIN="PROXY_UDP"

TARGET_IPS=""
BYPASS_IPS=""
BYPASS_HOSTS=""

log_info() {
    printf '\033[32m[INFO]\033[0m %s\n' "$*"
}

log_warn() {
    printf '\033[33m[WARN]\033[0m %s\n' "$*" >&2
}

log_err() {
    printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2
}

usage() {
    cat <<EOF
用法:
  $0 start [选项] IP1 [IP2 IP3 ...]
  $0 stop
  $0 status

选项:
  -p, --port PORT           forward -T 监听端口，默认: ${PROXY_PORT}
  -m, --mark MARK           fwmark，默认: ${FWMARK}
  -t, --table TABLE         策略路由表，默认: ${ROUTE_TABLE}
  -l, --lan CIDR           局域网网段，默认: ${LAN_SUBNET}
  -r, --remote-host HOST    代理服务器域名，解析后自动绕过，可重复
  -b, --bypass-ip IP        额外绕过的目标 IP，可重复
  -h, --help                显示帮助

示例:
  $0 start 192.168.31.150
  $0 start -r eae90ac541.d26-01-11.am15boy.com 192.168.31.150
  $0 start -p 12345 -b 1.2.3.4 192.168.31.150 192.168.31.151
  $0 stop

启动 forward:
  ./forward -T ${PROXY_PORT} -F '你的节点 URL'
EOF
}

is_ipv4() {
    case "$1" in
        *[!0-9.]* | "" | *.*.*.*.*) return 1 ;;
        *.*.*.*) return 0 ;;
        *) return 1 ;;
    esac
}

append_unique() {
    var_name="$1"
    new_item="$2"
    eval "old_list=\${$var_name}"
    for old_item in $old_list; do
        [ "$old_item" = "$new_item" ] && return 0
    done
    if [ -z "$old_list" ]; then
        eval "$var_name=\$new_item"
    else
        eval "$var_name=\"\$old_list \$new_item\""
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        log_err "缺少命令: $1"
        exit 1
    }
}

resolve_host_ipv4() {
    host="$1"

    if command -v resolveip >/dev/null 2>&1; then
        resolveip -4 "$host" 2>/dev/null | awk '/^[0-9.]+$/ { print }'
        return 0
    fi

    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$host" 2>/dev/null | awk '
            /^Address[[:space:]]+[0-9]+:/ { print $3 }
            /^Address:/ { print $2 }
        ' | awk '/^[0-9.]+$/ { print }'
        return 0
    fi

    if command -v ping >/dev/null 2>&1; then
        ping -4 -c 1 -W 1 "$host" 2>/dev/null |
            sed -n 's/^PING[^(]*(\([0-9.]*\)).*/\1/p'
        return 0
    fi

    return 1
}

resolve_bypass_hosts() {
    for host in $BYPASS_HOSTS; do
        found=""
        for ip in $(resolve_host_ipv4 "$host"); do
            if is_ipv4 "$ip"; then
                append_unique BYPASS_IPS "$ip"
                found=1
            fi
        done
        if [ -z "$found" ]; then
            log_warn "无法解析远端域名，未添加绕过规则: $host"
        fi
    done
}

iptables_del_loop() {
    while iptables "$@" 2>/dev/null; do
        :
    done
}

delete_chain_refs() {
    table="$1"
    hook="$2"
    chain="$3"

    while :; do
        rules="$(iptables -t "$table" -S "$hook" 2>/dev/null |
            grep -- " -j ${chain}" |
            sed 's/^-A /-D /')"
        [ -n "$rules" ] || break

        echo "$rules" | while IFS= read -r rule; do
            [ -n "$rule" ] || continue
            # shellcheck disable=SC2086
            iptables -t "$table" $rule 2>/dev/null || true
        done
    done
}

stop_proxy() {
    log_info "开始清理 fw3/iptables TPROXY 策略..."

    delete_chain_refs mangle PREROUTING "$CHAIN"

    if iptables -t mangle -L "$CHAIN" >/dev/null 2>&1; then
        iptables -t mangle -F "$CHAIN" 2>/dev/null
        iptables -t mangle -X "$CHAIN" 2>/dev/null
        log_info "已清空并删除 mangle 表中的 $CHAIN 链"
    fi

    # 清理旧版脚本残留。旧脚本的 TCP nat REDIRECT 会把原目标改成
    # 路由器本机:${PROXY_PORT}，导致 sniff 到域名后端口仍然是代理端口。
    delete_chain_refs nat PREROUTING "$LEGACY_NAT_CHAIN"
    if iptables -t nat -L "$LEGACY_NAT_CHAIN" >/dev/null 2>&1; then
        iptables -t nat -F "$LEGACY_NAT_CHAIN" 2>/dev/null
        iptables -t nat -X "$LEGACY_NAT_CHAIN" 2>/dev/null
        log_info "已清空并删除旧 nat 表链 $LEGACY_NAT_CHAIN"
    fi

    delete_chain_refs mangle PREROUTING "$LEGACY_MANGLE_CHAIN"
    if iptables -t mangle -L "$LEGACY_MANGLE_CHAIN" >/dev/null 2>&1; then
        iptables -t mangle -F "$LEGACY_MANGLE_CHAIN" 2>/dev/null
        iptables -t mangle -X "$LEGACY_MANGLE_CHAIN" 2>/dev/null
        log_info "已清空并删除旧 mangle 表链 $LEGACY_MANGLE_CHAIN"
    fi

    while ip rule del fwmark "${FWMARK}/${FWMARK}" table "$ROUTE_TABLE" 2>/dev/null; do
        log_info "已移除 fwmark ${FWMARK}/${FWMARK} -> table ${ROUTE_TABLE}"
    done

    ip route del local default dev lo table "$ROUTE_TABLE" 2>/dev/null &&
        log_info "已删除 table ${ROUTE_TABLE} 的 local default 路由"

    log_info "透明代理策略已清理完成"
}

add_bypass_rules() {
    log_info "配置绕过规则..."

    # 防回环：已经带代理 mark 的包不再处理。
    iptables -t mangle -A "$CHAIN" -m mark --mark "${FWMARK}/${FWMARK}" -j RETURN

    # 目标是局域网/本机/保留地址时不代理，避免访问路由器和内网设备异常。
    iptables -t mangle -A "$CHAIN" -d 0.0.0.0/8 -j RETURN
    iptables -t mangle -A "$CHAIN" -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A "$CHAIN" -d 100.64.0.0/10 -j RETURN
    iptables -t mangle -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A "$CHAIN" -d 169.254.0.0/16 -j RETURN
    iptables -t mangle -A "$CHAIN" -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A "$CHAIN" -d "$LAN_SUBNET" -j RETURN
    iptables -t mangle -A "$CHAIN" -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A "$CHAIN" -d 240.0.0.0/4 -j RETURN
    iptables -t mangle -A "$CHAIN" -d 255.255.255.255/32 -j RETURN

    # 不抓代理程序自己的监听端口，避免误拦截本机端口探测。
    iptables -t mangle -A "$CHAIN" -p tcp --dport "$PROXY_PORT" -j RETURN
    iptables -t mangle -A "$CHAIN" -p udp --dport "$PROXY_PORT" -j RETURN

    # DNS/DHCP 通常由路由器本机处理。若你明确要代理 DNS，可删掉 53 两行。
    iptables -t mangle -A "$CHAIN" -p tcp --dport 53 -j RETURN
    iptables -t mangle -A "$CHAIN" -p udp --dport 53 -j RETURN
    iptables -t mangle -A "$CHAIN" -p udp --dport 67:68 -j RETURN
    iptables -t mangle -A "$CHAIN" -p udp --sport 67:68 -j RETURN

    resolve_bypass_hosts
    for ip in $BYPASS_IPS; do
        if is_ipv4 "$ip"; then
            iptables -t mangle -A "$CHAIN" -d "$ip" -j RETURN
            log_info "已绕过目标 IP: $ip"
        else
            log_warn "忽略非 IPv4 绕过地址: $ip"
        fi
    done
}

start_proxy() {
    [ -n "$TARGET_IPS" ] || {
        log_err "未指定任何需要代理的客户端 IP"
        usage
        exit 1
    }

    require_cmd iptables
    require_cmd ip

    log_info "检测并清理旧规则..."
    stop_proxy

    log_info "启用 IPv4 转发..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    log_info "尝试加载 TPROXY 相关内核模块..."
    modprobe xt_TPROXY 2>/dev/null || true
    modprobe xt_socket 2>/dev/null || true
    modprobe nf_tproxy_ipv4 2>/dev/null || true

    log_info "配置策略路由: fwmark ${FWMARK}/${FWMARK} -> table ${ROUTE_TABLE}"
    ip route add local default dev lo table "$ROUTE_TABLE"
    ip rule add fwmark "${FWMARK}/${FWMARK}" table "$ROUTE_TABLE"

    log_info "创建 mangle 链: $CHAIN"
    iptables -t mangle -N "$CHAIN"

    add_bypass_rules

    log_info "按 ShellCrash 风格配置客户端源地址匹配和 TPROXY -> :${PROXY_PORT}"
    for ip in $TARGET_IPS; do
        iptables -t mangle -A "$CHAIN" -p tcp -s "$ip" -j TPROXY \
            --on-port "$PROXY_PORT" --tproxy-mark "${FWMARK}/${FWMARK}"
        iptables -t mangle -A "$CHAIN" -p udp -s "$ip" -j TPROXY \
            --on-port "$PROXY_PORT" --tproxy-mark "${FWMARK}/${FWMARK}"
    done

    for ip in $TARGET_IPS; do
        log_info "客户端 IP 已在 ${CHAIN} 内匹配: $ip"
    done

    iptables -t mangle -I PREROUTING 1 -p tcp -j "$CHAIN"
    iptables -t mangle -I PREROUTING 1 -p udp -j "$CHAIN"
    log_info "已将 PREROUTING 的 TCP/UDP 流量跳转到 ${CHAIN}"

    log_info "启动完成。请确认 forward 已以 -T ${PROXY_PORT} 运行。"
}

show_status() {
    require_cmd iptables
    require_cmd ip

    echo "=== ip rule ==="
    ip rule show | grep -F "fwmark ${FWMARK}" || true
    echo
    echo "=== route table ${ROUTE_TABLE} ==="
    ip route show table "$ROUTE_TABLE" || true
    echo
    echo "=== iptables mangle ${CHAIN} ==="
    iptables -t mangle -S "$CHAIN" 2>/dev/null || true
    echo
    echo "=== iptables mangle PREROUTING references ==="
    iptables -t mangle -S PREROUTING | grep -- "-j ${CHAIN}" || true
    echo
    echo "=== legacy nat REDIRECT references that must be empty ==="
    iptables -t nat -S PREROUTING | grep -- "-j ${LEGACY_NAT_CHAIN}" || true
    iptables -t nat -S "$LEGACY_NAT_CHAIN" 2>/dev/null || true
}

parse_start_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -p|--port)
                [ -n "$2" ] || { log_err "$1 需要端口参数"; exit 1; }
                PROXY_PORT="$2"
                shift 2
                ;;
            -m|--mark)
                [ -n "$2" ] || { log_err "$1 需要 mark 参数"; exit 1; }
                FWMARK="$2"
                shift 2
                ;;
            -t|--table)
                [ -n "$2" ] || { log_err "$1 需要 table 参数"; exit 1; }
                ROUTE_TABLE="$2"
                shift 2
                ;;
            -l|--lan)
                [ -n "$2" ] || { log_err "$1 需要 CIDR 参数"; exit 1; }
                LAN_SUBNET="$2"
                shift 2
                ;;
            -r|--remote-host)
                [ -n "$2" ] || { log_err "$1 需要域名参数"; exit 1; }
                append_unique BYPASS_HOSTS "$2"
                shift 2
                ;;
            -b|--bypass-ip)
                [ -n "$2" ] || { log_err "$1 需要 IP 参数"; exit 1; }
                append_unique BYPASS_IPS "$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                log_err "未知参数: $1"
                usage
                exit 1
                ;;
            *)
                append_unique TARGET_IPS "$1"
                shift
                ;;
        esac
    done

    while [ "$#" -gt 0 ]; do
        append_unique TARGET_IPS "$1"
        shift
    done
}

case "$1" in
    start)
        shift
        parse_start_args "$@"
        start_proxy
        ;;
    stop)
        stop_proxy
        ;;
    status)
        show_status
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
