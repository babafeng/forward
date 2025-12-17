# Go-Forward

forward is a lightweight and high-performance port forwarding and proxy tool written in Go. It supports TCP/UDP port forwarding, intranet penetration (reverse proxy), and multiple proxy protocols (HTTP, SOCKS5, SSH, TLS) with protocol sniffing on the same port.

## Features

* **Port Forwarding**: TCP/UDP forwarding with support for proxy chains.
* **Intranet Penetration (Reverse Proxy)**: Expose local services to the internet via a reverse tunnel.
* **Proxy Server**: HTTP/SOCKS5/SSH/TLS proxy server with protocol sniffing (multiplexing on same port).
* **Multiplexing**: Uses Yamux for TCP and QUIC for UDP (planned) to improve performance.

## Installation

```bash
go build -o forward ./cmd/forward
```

```bash
go build -o forward ./cmd/forward
```

```bash
# 安装最新版本
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/install.sh) --install
```

```bash
# 选择要安装的版本
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/install.sh)
```

## Usage

### 1. Port Forwarding

Forward local port to remote host.

```bash
# Forward local 8080 to 1.2.3.4:80
forward -L tcp://:8080//1.2.3.4:80

# Forward UDP
forward -L udp://:5353//8.8.8.8:53
```

### 2. Proxy Server

Start a proxy server supporting HTTP, SOCKS5, and TLS on the same port.

```bash
forward -L http://:1080
forward -L socks5://:1080
forward -L https://:1080
forward -L quic://:1080
forward -L tls://:1080
forward -L ssh://:1080
```

### 3. Intranet Penetration (Reverse Proxy)

**Server Side (Public IP):**

Start a reverse proxy server listening on port 2333.

```bash
forward -L tls://:2333?bind=true
forward -L ssh://:2333?bind=true
forward -L quic://:2333?bind=true
```

**Client Side (Intranet):**

Connect to the server and map remote port 11080 to local 1080.

```bash
# Map remote 11080 -> local 127.0.0.1:1080
forward -L tcp://11080//127.0.0.1:1080 -F tls://your.server.com:2333
```

Now, accessing `your.server.com:11080` will reach the intranet machine's `127.0.0.1:1080`.

### 4. Proxy Chaining

Forward traffic through a proxy chain.

```bash
forward -L http://127.0.0.1:1080 -F tls://proxy.com:1080
```

### 5. Multiple Listeners

You can start multiple services at once.

```bash
forward -L tcp://:8080//1.2.3.4:80 -L socks5://:1080
```

## Security Suggestions

1. **Authentication**: Currently, the demo supports basic SOCKS5/HTTP auth structure but requires configuration. Ensure to enable user/password authentication in production.
2. **TLS**: Use TLS for all connections over public networks.
   * Use `tls://` or `ssh://` (planned) to encrypt the tunnel.
   * Replace self-signed certificates with valid CA-signed certificates.
3. **Firewall**: Restrict access to the control ports (e.g., the reverse server port 2333) to known IPs if possible.
