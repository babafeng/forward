# forward

forward is a security & lightweight & high-performance port forwarding and proxy tool written in Go. It supports TCP/UDP port forwarding, intranet penetration (reverse proxy), and multiple proxy protocols (HTTP, SOCKS5, TLS) with protocol sniffing on the same port.

## Features

* **Port Forwarding**: TCP/UDP forwarding with support for proxy chains.
* **Intranet Penetration (Reverse Proxy)**: Expose local services to the internet via a reverse tunnel.
* **Proxy Server**: HTTP/SOCKS5/TLS proxy server with protocol sniffing (multiplexing on same port).
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
bash <(curl -fsSL https://github.com/babafeng/forward/raw/main/install.sh) --install
```

```bash
# install specific version
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
forward -L "tls://user:pass@your.server.com:2333?cert=/path/to/cert.cer&key=/path/to/private.key"

# And client, If self-signed cert, set ca option
forward -L http://:1080 -F "tls://user:pass@your.server.com:2333?ca=/path/to/rootca.cer"
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

Advanced usage

```bash
# —L forward tcp/udp port
# -x specify proxy to use, proxy protocols supported: socks5, tls, quic
# quic      - only UDP
# socks5    - TCP and UDP
# tls - only TCP
forward -L tcp://:8080//1.2.3.4:80 -x tls://proxy.com:1080
```

8080 --> proxy.com:1080(tls) --> 1.2.3.4:80

### Proxy Server

Start a proxy server supporting http / socks5 / https / quic / tls

```bash
forward -L http://:1080
```

### Intranet Reverse Proxy

**Server Side (Public IP):**

Start a reverse proxy server listening on port 2333.

```bash
# support all proxy schemes, but recommend using secure ones below: tls / quic
forward -L tls://user:passwd@:2333?bind=true
```

**Client Side (Intranet):**

Connect to the server and map remote port 11080 to local 1080.

```bash
# Map remote 2222 -> local 127.0.0.1:22
forward -L tcp://:2222//127.0.0.1:22 -F tls://your.server.com:2333
```

Now, accessing `your.server.com:2222` will reach the intranet machine's `127.0.0.1:22`.

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
