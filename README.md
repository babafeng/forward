# forward

forward 是一个用 Go 编写的安全、轻量、高性能的端口转发工具。支持 TCP/UDP 端口转发、内网穿透以及多种转发协议

## 功能特性

* **端口转发**：支持 TCP/UDP 转发，并支持转发链。
* **内网穿透**：通过反向隧道将本地服务暴露到公网（TLS/HTTPS/HTTP3/QUIC/VLESS+REALITY）。
* **服务器**：支持 HTTP/SOCKS5/HTTPS(TLS)/HTTP2/HTTP3/VMess/VLESS+REALITY/Hysteria2/Shadowsocks 服务端。
* **传输协议**：支持 TCP/UDP/TLS/DTLS/HTTP2/HTTP3/QUIC(Raw) 作为底层传输通道；其中 `quic` / `+quic` 当前主要用于上游链路与反向穿透。
* **转发路由**：基于规则将流量路由到多个上游转发节点（INI 配置）。
* **多路复用**：反向穿透控制面使用 Yamux，VLESS/VMess 上游支持 Xray Mux

## 安装

```bash
# 从源码安装
git clone https://github.com/babafeng/forward.git
cd forward
go build -o forward ./cmd/forward && chmod +x forward
```

```bash
# 安装最新版本
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/install.sh) --install
```

```bash
# 安装指定版本
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/install.sh)
```

## 作为系统服务运行

你可以使用提供的脚本在 Linux（systemd）或 macOS（launchd）上将 `forward` 注册为系统服务。

```bash
# 将创建 systemd unit 并设置为开机自启
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/register-service.sh) --name forward -- -L tcp://:8080/1.2.3.4:80

# 注销/移除服务
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/register-service.sh) --name forward --remove
```

## 认证（Auth）

你可以在转发 URL 中设置用户名和密码用于认证。

```bash
forward -L socks5://user:pass@:1080
forward -F tls://user:pass@your.server.com:2333
```

## 证书（Cert）

你可以为 tls 类别服务设置证书。

```bash
# 支持 tls / https / http2 / http3 / h2 / h3 / dtls
forward -L "tls://user:pass@your.server.com:2333?cert=/path/to/cert.cer&key=/path/to/private.key"

# HTTP/3 监听（标准 HTTP/3）
forward -L http3://:443 --debug

# SOCKS5 over HTTP/3 传输隧道
forward -L socks5+h3://:443 --debug

# 需要逐跳排障时再开启高噪音详细日志
forward -L http://:1080 -F tls://your.server.com:2333 --debug --debug-verbose

# 客户端：如果是自签证书，设置 ca 选项
forward -L http://:1080 -F "tls://user:pass@your.server.com:2333?ca=/path/to/rootca.cer&sni=your.server.com"
```

## 使用方法（Usage）

### 端口转发（Port Forwarding）

将本地端口转发到远端主机。

本地 8080 --> 1.2.3.4:80，访问 8080 == 访问 1.2.3.4:80

```bash
# 转发 TCP
forward -L tcp://:8080/1.2.3.4:80
forward -L tcp://:8080 -F tcp://1.2.3.4:80

# 转发 UDP
forward -L udp://:5353/8.8.8.8:53
forward -L udp://:5353 -F udp://8.8.8.8:53
```

### 服务器（Proxy Server）

启动一个服务器，支持 http / socks5 / https(tls) / http2 / http3 / vmess / vless+reality（别名：reality）/ hysteria2（别名：hy2）/ ss

```bash
forward -L http://:1080
forward -L vless+reality://:443
forward -L reality://:443
forward -L vmess://auto:11111111-1111-1111-1111-111111111111@:10086?alterId=0
forward -L ss://aes-256-gcm:your-password@:8388
forward -L "hysteria2://your-auth@:443?cert=/path/to/fullchain.pem&key=/path/to/privkey.pem&obfs=salamander&obfs-password=your-obfs-password"

# 可选参数：uuid / dest / sni / sid / key
forward -L vless+reality://uuid@:443?dest=swscan.apple.com:443&sni=swscan.apple.com&sid=12345678&key=private.key
```

说明：
* `vmess://` 监听格式为 `vmess://<security>:<uuid>@:port?alterId=0`（`security` 在用户名，`uuid` 在密码）。
* `ss://` 监听格式为 `ss://<method>:<password>@:port`；当前 `ss` 入站/出站以 TCP 为主，入站 UDP 尚未实现。
* `hysteria2://` 监听格式为 `hysteria2://<auth>@:port?...`；建议显式配置 `cert` 和 `key`。
* `hy2://` 是 `hysteria2://` 的别名。
* `quic://` 与 `+quic` 当前用于上游链路和 `bind=true` 反向穿透，不作为普通 `-L` 代理监听 scheme。

**进阶用法-转发链:**

使用 `-F` 参数依次指定转发链中的节点，顺序为**从近到远**（先经过的节点先写）：

```bash
# 单跳转发链：本地 -> S1 -> 目标
forward -L http://127.0.0.1:1080 -F tls://proxy.com:1080

# 双跳转发链：本地 -> S2 -> S1 -> 目标
forward -L http://127.0.0.1:8080 -F http://S2:8080 -F http://S1:8080

# 三跳转发链：本地 -> S3 -> S2 -> S1 -> 目标
forward -L http://:8080 -F http://S3:8080 -F http://S2:8080 -F http://S1:8080

# 使用 Hysteria2 节点作为上游
forward -L http://:1080 -F "hysteria2://uuid@remote:443?peer=sni&insecure=1"
```

**支持的协议组合：**

| 基础协议        | 可链接协议                | 说明                         |
| --------------- | ------------------------- | ---------------------------- |
| http/https/tls  | http/https/tls/socks5     | 标准 TCP 链式转发            |
| vmess/vmess+tls | http/https/tls/socks5     | 仅支持 TCP 传输              |
| vless/reality   | http/https/tls/socks5     | 仅支持 TCP 传输 (`type=tcp`) |
| hysteria2/hy2   | http/socks5/tcp/udp       | 原生 QUIC 转发，支持 TCP/UDP |
| tcp             | quic                      | Raw QUIC 隧道                |
| socks5          | quic/http3/http/https/tls | SOCKS5 支持 UDP，可承载 QUIC |

**QUIC/HTTP3 多跳示例：**

```bash
# QUIC 多跳需要 UDP-capable 的 base（如 socks5）
forward -L http://127.0.0.1:8080 -F socks5://S2:1080 -F quic://S1:443
forward -L socks5://127.0.0.1:1080 -F quic://S2:1080 -F quic://S1:443
```

**注意事项：**

* QUIC/HTTP3 协议需要底层支持 UDP，因此不能直接建在纯 TCP 转发（如 http）上
* VLESS 协议在多跳场景下仅支持 TCP 传输模式

### VLESS/VMess 数据面 Mux 复用（转发链）

`mux` 参数用于 `-F` 上游 URL（转发端），不是 `-L` 监听 URL。

```bash
# 单跳示例（VLESS）
forward -L http://:1080 \
  -F "vless://uuid@node:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=swscan.apple.com&sid=xxxx&fp=chrome&type=tcp&mux=true&mux_max_streams=64&mux_idle=120s"

# 双跳示例（两个 -F 都可开启 mux）
forward -L http://:1000 \
  -F "vless://uuid@127.0.0.1:1443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=swscan.apple.com&sid=xxxx&fp=chrome&type=tcp&mux=true&mux_max_streams=64&mux_idle=120s" \
  -F "vless://uuid@127.0.0.1:2443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=swscan.apple.com&sid=xxxx&fp=chrome&type=tcp&mux=true&mux_max_streams=64&mux_idle=120s"
```

参数说明：
* `mux=true`：开启数据面 mux 复用。
* `mux_max_streams=64`：单 mux 连接最大并发子流数。
* `mux_idle=120s`：mux 空闲超时（可写秒数，如 `120`）。
* 兼容别名：`mux_concurrency` 等价 `mux_max_streams`，`mux_idle_timeout` 等价 `mux_idle`。

兼容性说明：
* 服务端需支持 VLESS/VMess `RequestCommandMux`（`v1.mux.cool` 数据面）。
* 若 mux 建链失败，会自动 fallback 到普通转发（直连模式）。

### DialPool 预热池（默认关闭）

为避免空闲预热连接带来的额外开销，DialPool 现已默认关闭。仅在显式配置时启用。

```bash
# 显式开启预热池
forward -L http://:1080 -F "socks5://node:1080?pool=true&pool_size=16&pool_ttl=120s"

# 显式关闭（即使带了 pool_size/pool_ttl 也会强制关闭）
forward -L http://:1080 -F "socks5://node:1080?pool=false&pool_size=16&pool_ttl=120s"
```

说明：
* `pool=true`：开启预热池。
* `pool_size` / `pool_ttl`：分别表示池大小和空闲连接 TTL。
* 在 `vless/vmess + mux=true` 场景下，会自动跳过 DialPool，避免重复连接复用层。

### H2/H3 PHT 首字节延迟优化

PHT 客户端写入批处理默认不再额外等待 `2ms` 时间窗（改为立即 drain 队列发送），用于降低交互型流量首字节延迟。

**订阅节点支持：**

你可以使用 `-S` 或 `--subscribe` 提供订阅链接，并通过 `--filter` 指定过滤表达式。
`-S/--subscribe` 支持重复传入，也支持在单个参数里用逗号分隔多个订阅链接。
订阅响应支持：Clash YAML、base64 编码 YAML、base64 编码 URI 列表、纯文本 URI 列表。
目前可直接构建为运行中上游的节点协议：vmess、vless、hysteria2、ss 等；其余协议即使被解析到，也会在构建路由时被自动忽略。

过滤表达式语法（单个 `--filter` 参数）：
* `|` 表示 OR，如 `美国|US`
* `&` 表示 AND，如 `香港&?!01`
* `?!` 表示 NOT，如 `?!日本&?!JP`
* `()` 用于分组，如 `(?!日本试用|JP试用)&(美国|US|日本|JP)`

说明：
* `--filter` 不是可重复叠加参数；重复传入时以后一个值为准。
* 多个订阅源会先聚合，再统一过滤和去重；只要至少一个订阅源成功，就会继续构建可用节点。

```bash
# 获取订阅中的所有可用节点进行智能建连
forward -L http://:1080 -S "https://sub.website.com/api/v1/client/subscribe?token=xxxx"

# 多订阅：推荐重复使用 -S
forward -L http://:1080 \
  -S "https://sub-a.website.com/api/v1/client/subscribe?token=xxxx" \
  -S "https://sub-b.website.com/api/v1/client/subscribe?token=xxxx"

# 多订阅：也支持单个 -S 里使用逗号分隔
forward -L http://:1080 \
  -S "https://sub-a.website.com/api/v1/client/subscribe?token=xxxx, https://sub-b.website.com/api/v1/client/subscribe?token=xxxx"

# 结合过滤规则，仅使用节点名包含 "Hong Kong" 且不含 "01" 的节点
forward -L http://:1080 --subscribe "https://sub.website.com/api/v1/client/subscribe?token=xxxx" --filter "Hong Kong&?!01"

# 支持复杂过滤表达式
forward -L http://:1080 -S "https://sub.website.com/api/v1/client/subscribe?token=xxxx" --filter "(?!日本试用|JP试用)&(美国|US|日本|JP)"

# 订阅节点 + 固定上游链：先走订阅筛选节点，再走 -F 指定上游
forward -L http://local:8080 -S "https://sub.website.com/api/v1/client/subscribe?token=xxxx" --filter "日本" -F https://jp.proxy.com:443

# 同样支持作为单双跳转发链节点结合使用
forward -L tcp://:2222/127.0.0.1:22 -S "https://sub.website.com/api/v1/client/subscribe?token=xxxx"
```

JSON 配置文件同样支持多订阅：

```json
{
  "listen": "http://:1080",
  "subscribes": [
    "https://sub-a.website.com/api/v1/client/subscribe?token=xxxx",
    "https://sub-b.website.com/api/v1/client/subscribe?token=xxxx"
  ],
  "filter": "日本"
}
```

兼容说明：
* 旧的 `subscribe` 字段保持不变，继续接受单个字符串。
* 新增的 `subscribes` 字段接受字符串数组。

### 内网反向转发（Intranet Reverse Proxy）

**服务端（公网 IP）：**

启动一个反向转发服务端，监听 2333 端口。

```bash
# reverse server 目前支持：tls / https / http3 / quic / reality
forward -L tls://user:passwd@:2333?bind=true

# VLESS+REALITY（别名：reality）
forward -L reality://uuid@:2333?bind=true&key=xxxx&sid=xxxxx&sni=swscan.apple.com
```

**客户端（内网）：**

连接到服务端，在公网侧绑定端口，再回连到客户端本地目标地址。

```bash
# 映射：远端 2222 -> 本地 127.0.0.1:22
forward -L rtcp://:2222/127.0.0.1:22 -F tls://your.server.com:2333

# VLESS+REALITY
forward -L rtcp://:2222/127.0.0.1:22 -F "reality://uuid@your.server.com:2333?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=xxx&security=reality&sid=xxxx&sni=swscan.apple.com&type=tcp"
```

现在，访问 `your.server.com:2222` 将会到达内网机器的 `127.0.0.1:22`。

* `reality://` 是 `vless+reality://` 的别名。
* 内网穿透服务端需要 `bind=true`。
* 内网穿透客户端必须使用 `rtcp://` 或 `rudp://` 作为监听 scheme。
* 反向客户端监听 URL 中的路径部分（如 `/127.0.0.1:22`）就是客户端本地实际目标地址。
* `key` 是服务端私钥；`pbk` 是客户端公钥；`sid` 是 short ID；`sni` 是服务端名称。

### 多监听（Multiple Listeners）

你可以一次启动多个服务。

```bash
forward -L tcp://:8080/1.2.3.4:80 -L socks5://:1080
```

### JSON 配置文件（JSON Config File）

在复杂环境中，使用 JSON 配置文件替代命令行参数

```bash
# 使用配置文件
forward -C config.json

# 默认配置路径（无参数时自动探测）：
#   ~/.forward/forward.json
#   ~/forward.json
```

**简单配置格式：**

```json
{
  "listen": "http://:1080",
  "forward": "tls://user:pass@remote.com:443",
  "insecure": false,
  "debug": false,
  "debug_verbose": false
}
```

**订阅配置格式：**

```json
{
  "listen": "http://:1080",
  "subscribe": "https://sub-a.website.com/api/v1/client/subscribe?token=xxxx",
  "subscribes": [
    "https://sub-b.website.com/api/v1/client/subscribe?token=yyyy",
    "https://sub-c.website.com/api/v1/client/subscribe?token=zzzz"
  ],
  "filter": "日本|JP",
  "update": 60
}
```

说明：

* `subscribe` 继续接受单个字符串，保持兼容旧配置。
* `subscribes` 接受字符串数组，用于声明多个订阅源。
* 当 `subscribe` 与 `subscribes` 同时存在时，会合并后一起拉取。
* 当存在订阅源时，JSON / INI 中的 `update` 缺省或设为 `0` 都会回落到默认的 60 分钟；若要显式关闭自动刷新，请使用 CLI `--sub-update 0`。

**链式转发示例：**

```json
{
  "listen": "http://:8080",
  "forwards": ["http://S2:8080", "http://S1:8080"]
}
```

说明：

* `forward` 与 `forwards` 互斥；`forwards` 的顺序为从近到远。

**多节点配置格式：**

```json
{
  "nodes": [
    {
      "name": "proxy_server",
      "listen": "http://:8080",
      "forward": "tls://user:pass@remote.com:443",
      "insecure": false
    },
    {
      "name": "proxy_chain",
      "listen": "http://:8081",
      "forwards": ["http://S2:8080", "http://S1:8080"]
    },
    {
      "name": "port_forward",
      "listen": "tcp://:2222/10.0.0.1:22"
    },
    {
      "name": "port_forward",
      "listeners": [
        "tcp://:2222/10.0.0.1:22",
        "http://:8080",
        "socks5://:1080"
      ]
    }
  ],
  "debug": true,
  "debug_verbose": false
}
```

每个 node 都有独立的 `listeners`/`listen`、`forward`/`forwards` 与 `insecure` 设置。

### 路由（Proxy Route）

使用独立的 INI 配置文件启动基于规则的路由器。该模式会在本地监听，并将流量路由到不同的上游转发节点。

```bash
forward -R proxy-route.conf
```

**示例配置：**

```ini
[General]
listen = socks5://0.0.0.0:1080, http://0.0.0.0:8080
tproxy = 12345
debug = false
debug-verbose = false
skip-proxy = 192.168.0.0/16, 127.0.0.1/32
dns-server = 8.8.8.8, 8.8.4.4
mmdb-path = ~/.forward/Country.mmdb
mmdb-link = https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb

[TProxy]
network = tcp,udp
sniffing = true
dest-override = http,tls,quic

[Proxy]
PROXY_JP = vless+reality://uuid@jp.example.com:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=...&security=reality&sid=...&sni=swscan.apple.com&type=tcp
PROXY_SG = socks5://user:pass@sg.example.com:1080

[Rule]
DOMAIN,ifconfig.me,PROXY_JP
DOMAIN-SUFFIX,google.com,PROXY_SG
DOMAIN,ipconfig.me,PROXY_SG,PROXY_JP
IP-CIDR,1.1.1.0/24,PROXY_SG
GEOIP,CN,DIRECT
FINAL,DIRECT
```

* 规则自上而下匹配；命中第一条后即停止
* `Rule` 支持转发链：`DOMAIN,ipconfig.me,PROXY_2,PROXY_1` 表示 `PROXY_1 -> PROXY_2 -> 目标`（最后一个节点作为前置加速节点）
* 若希望基于域名的规则在本地 DNS 解析前生效，请在客户端使用 `socks5h://`
* 路由器会在 INI 文件变更时自动热重载（每秒轮询一次）
* `tproxy` 仅支持 Linux（TPROXY），需要配合 `fw4 + nftables` 设置透明转发规则
* `sniffing` 默认开启，用于从 HTTP Host / TLS SNI 中提取域名以匹配 DOMAIN 规则（QUIC 嗅探暂未实现）

**fw4 + nftables 示例（简化版）**

```bash
# policy routing
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# nftables (示例：将 TCP/UDP 导流到 12345)
nft add table inet tproxy
nft 'add chain inet tproxy prerouting { type filter hook prerouting priority mangle; policy accept; }'
nft 'add rule inet tproxy prerouting meta l4proto { tcp, udp } tproxy to :12345 mark set 1'
```

> 注：实际规则需结合白名单/保留地址/本地网段等进行调整。
