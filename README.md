# forward

forward is a security & lightweight & high-performance port forwarding and proxy tool written in Go. It supports TCP/UDP port forwarding, intranet penetration (reverse proxy), and multiple proxy protocols (HTTP, SOCKS5, TLS).

## Features

* **Port Forwarding**: TCP/UDP forwarding with support for proxy chains.
* **Intranet Penetration (Reverse Proxy)**: Expose local services to the internet via a reverse tunnel (TLS/QUIC/VLESS+REALITY).
* **Proxy Server**: HTTP/SOCKS5/TLS/QUIC/VLESS+REALITY proxy server.
* **Proxy Routing**: Rule-based routing to multiple upstream proxies (INI config).
* **Multiplexing**: Uses Yamux for TCP and QUIC for UDP (planned) to improve performance.

## Installation

```bash
# From source code
git clone https://github.com/babafeng/forward.git
cd forward
go build -o forward ./cmd/forward && chmod +x forward
```

```bash
# install latest version
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/install.sh) --install
```

```bash
# install specific version
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/install.sh)
```

## Run as Service

You can register `forward` as a system service on Linux (systemd) or macOS (launchd) using the provided script.

```bash
# This will create a systemd unit and enable it on boot
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/register-service.sh) --name forward -- -L tcp://:8080/1.2.3.4:80

# Unregister/Remove service
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/scripts/register-service.sh) --name forward --remove
```

## Auth

You can set username and password for authentication in proxy URLs.

```bash
forward -L socks5://user:pass@:1080
forward -F tls://user:pass@your.server.com:2333
```

## Cert

You can set cert for tls category service.

```bash
# support tls / quic / http2 / http1 / http3
forward -L "tls://user:pass@your.server.com:2333?cert=/path/to/cert.cer&key=/path/to/private.key"

# And client, If self-signed cert, set ca option
forward -L http://:1080 -F "tls://user:pass@your.server.com:2333?ca=/path/to/rootca.cer&sni=your.server.com"
```

## Usage

### Port Forwarding

Forward local port to remote host.

Forward local 8080 --> 1.2.3.4:80, access 8080 == 1.2.3.4:80

```bash
# Forward TCP
forward -L tcp://:8080/1.2.3.4:80
forward -L tcp://:8080 -F tcp://1.2.3.4:80

# Forward UDP
forward -L udp://:5353/8.8.8.8:53
forward -L udp://:5353 -F udp://8.8.8.8:53
```

### Proxy Server

Start a proxy server supporting http / socks5 / https / quic / tls / vless+reality (alias: reality)

```bash
forward -L http://:1080
forward -L vless+reality://:443
forward -L reality://:443

# Optional parameters: uuid / dest / sni / sid / key
forward -L vless+reality://uuid@:443?dest=swscan.apple.com:443&sni=swscan.apple.com&sid=12345678&key=private.key
```

Advanced usage

```bash
# —L forward tcp/udp port
# -F forward to remote host
forward -L http://:1080 -F tls://user:pass@your.server.com:443
```

### Intranet Reverse Proxy

**Server Side (Public IP):**

Start a reverse proxy server listening on port 2333.

```bash
# support all proxy schemes, but recommend using secure ones below: tls / quic / https
forward -L tls://user:passwd@:2333?bind=true

# VLESS+REALITY (alias: reality)
forward -L reality://uuid@:2333?bind=true&key=xxxx&sid=xxxxx&sni=swscan.apple.com
```

**Client Side (Intranet):**

Connect to the server and map remote port 11080 to local 1080.

```bash
# Map remote 2222 -> local 127.0.0.1:22
forward -L tcp://:2222/127.0.0.1:22 -F tls://your.server.com:2333

# VLESS+REALITY (target defaults to server address, override with target=host:port if needed)
forward -L tcp://:2222/127.0.0.1:22 -F "reality://uuid@your.server.com:2333?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=xxx&security=reality&sid=xxxx&sni=swscan.apple.com&type=tcp"
```

Now, accessing `your.server.com:2222` will reach the intranet machine's `127.0.0.1:22`.

Notes:
* `reality://` is an alias of `vless+reality://`.
* Reverse server requires `bind=true`.
* Reverse client `target=host:port` sets the VLESS request target (default: server host:port).
* `key` is server private key; `pbk` is client public key; `sid` is short ID; `sni` is server name.

### Proxy Chaining

Forward traffic through a proxy chain (repeat `-F` for multi-hop).

```bash
# Single hop
forward -L http://127.0.0.1:1080 -F tls://proxy.com:1080

# Multi-hop (S2 -> S1)
forward -L http://127.0.0.1:8080 -F http://S2:8080 -F http://S1:8080
```

Notes:
* Multi-hop chaining is supported for http/https/tls/socks5.
* QUIC/HTTP3 chaining requires a UDP-capable base (e.g. socks5).
* VLESS chaining only supports TCP transport (`type=tcp`).

```bash
# QUIC/HTTP/3 多跳：本地 -> SOCKS5(S2) -> QUIC(S1)
forward -L http://127.0.0.1:8080 -F socks5://S2:1080 -F quic://S1:443
forward -L socks5://127.0.0.1:1080 -F quic://S2:1080 -F quic://S1:443
```

### Multiple Listeners

You can start multiple services at once.

```bash
forward -L tcp://:8080/1.2.3.4:80 -L socks5://:1080
```

### JSON Config File

Use a JSON config file instead of command-line arguments.

```bash
# Use config file
forward -C config.json

# Default config paths (auto-detected when no arguments):
#   ~/.forward/forward.json
#   ~/forward.json
```

**Simple config format:**

```json
{
  "listeners": ["http://:1080", "socks5://:1081"],
  "forward": "tls://user:pass@remote.com:443",
  "insecure": false,
  "debug": false
}
```

**Chained forward example:**

```json
{
  "listeners": ["http://:8080"],
  "forwards": ["http://S2:8080", "http://S1:8080"]
}
```

Notes:
* `forward` and `forwards` are mutually exclusive; `forwards` order is closest to farthest.

**Multi-node config format:**

```json
{
  "nodes": [
    {
      "name": "proxy_server",
      "listeners": ["http://:8080"],
      "forward": "tls://user:pass@remote.com:443",
      "insecure": false
    },
    {
      "name": "proxy_chain",
      "listeners": ["http://:8081"],
      "forwards": ["http://S2:8080", "http://S1:8080"]
    },
    {
      "name": "port_forward",
      "listeners": ["tcp://:2222/10.0.0.1:22"]
    }
  ],
  "debug": true
}
```

Each node has independent `listeners`, `forward`/`forwards`, and `insecure` settings.

### Proxy Route (INI)

Start a rule-based proxy router with a dedicated INI config file. This mode listens locally and routes traffic to different upstream proxies.

```bash
forward -R proxy-route.conf
```

**Example config:**

```
[General]
listen = socks5://0.0.0.0:1080, http://0.0.0.0:8080
debug = false
skip-proxy = 192.168.0.0/16, 127.0.0.1/32
dns-server = 8.8.8.8, 8.8.4.4
mmdb-path = ~/.forward/Country.mmdb
mmdb-link = https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb

[Proxy]
PROXY_JP = vless+reality://uuid@jp.example.com:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=...&security=reality&sid=...&sni=swscan.apple.com&type=tcp
PROXY_SG = socks5://user:pass@sg.example.com:1080

[Rule]
DOMAIN,ifconfig.me,PROXY_JP
DOMAIN-SUFFIX,google.com,PROXY_SG
IP-CIDR,1.1.1.0/24,PROXY_SG
GEOIP,CN,DIRECT
FINAL,DIRECT
```

Notes:
* Rules are matched top-to-bottom; first match wins.
* Use `socks5h://` on clients if you want domain-based rules to match before local DNS resolution.
* The router auto-reloads when the INI file changes (polled every second).
