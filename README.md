# forward

forward is a security & lightweight & high-performance port forwarding and proxy tool written in Go. It supports TCP/UDP port forwarding, intranet penetration (reverse proxy), and multiple proxy protocols (HTTP, SOCKS5, SSH, TLS) with protocol sniffing on the same port.

## Features

* **Port Forwarding**: TCP/UDP forwarding with support for proxy chains.
* **Intranet Penetration (Reverse Proxy)**: Expose local services to the internet via a reverse tunnel.
* **Proxy Server**: HTTP/SOCKS5/SSH/TLS proxy server with protocol sniffing (multiplexing on same port).
* **Multiplexing**: Uses Yamux for TCP and QUIC for UDP (planned) to improve performance.

## Installation

```bash
# From source code
git clone https://github.com/babafeng/forward.git
cd forward
go build -o forward ./cmd/forward && chmod +x forward
```

```bash
# 安装最新版本
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/install.sh) --install
```

```bash
# 选择要安装的版本
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/install.sh)
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
forward -F "tls://user:pass@your.server.com:2333?cert=/path/to/cert.cer&key=/path/to/private.key"
```

## Usage

### Port Forwarding

Forward local port to remote host.

Forward local 8080 --> 1.2.3.4:80, access 8080 == 1.2.3.4:80

```bash
# Forward TCP
forward -L tcp://:8080//1.2.3.4:80

# Forward UDP
forward -L udp://:5353//8.8.8.8:53

```

Advanced usage

```bash
# —L forward tcp/udp port
# -F specify proxy to use, proxy protocols supported: socks5, tls, ssh, quic
# quic      - only UDP
# socks5    - TCP and UDP
# tls / ssh - only TCP
forward -L tcp://:8080//1.2.3.4:80 -F tls://proxy.com:1080
```

8080 --> proxy.com:1080(tls) --> 1.2.3.4:80

### Proxy Server

Start a proxy server supporting http / socks5 / https / quic / tls / ssh

```bash
forward -L http://:1080

forward -L :1080  # http socks5 http1 http2 https quic tls ssh
```

### Intranet Reverse Proxy

**Server Side (Public IP):**

Start a reverse proxy server listening on port 2333.

```bash
# support all proxy schemes, but recommend using secure ones below: tls / ssh / quic
forward -L tls://user:passwd@:2333?bind=true
```

**Client Side (Intranet):**

Connect to the server and map remote port 11080 to local 1080.

```bash
# Map remote 11080 -> local 127.0.0.1:1080
forward -L tcp://11080//127.0.0.1:1080 -F tls://your.server.com:2333
```

Now, accessing `your.server.com:11080` will reach the intranet machine's `127.0.0.1:1080`.

### Proxy Chaining

Forward traffic through a proxy chain.

```bash
forward -L http://127.0.0.1:1080 -F tls://proxy.com:1080
```

### Multiple Listeners

You can start multiple services at once.

```bash
forward -L tcp://:8080//1.2.3.4:80 -L socks5://:1080
```
