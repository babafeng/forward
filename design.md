# Go Forward 设计文档

> 一个安全、轻量级、高性能的端口转发和代理工具
> 说明：当前仓库同时保留 inner（旧实现）与 internal（新四层实现）。本文以 internal 为主，base 为公共基础层。

---

## 目录

- [项目概述](#项目概述)
- [架构设计](#架构设计)
- [核心模块](#核心模块)
- [支持的协议](#支持的协议)
- [详细使用方式](#详细使用方式)
- [配置文件](#配置文件)
- [路由规则](#路由规则)
- [扩展开发](#扩展开发)

---

## 项目概述

### 核心功能

| 功能           | 描述                                                                |
| -------------- | ------------------------------------------------------------------- |
| **端口转发**   | TCP/UDP 端口转发，支持灵活的转发链配置                              |
| **代理服务器** | HTTP/SOCKS5/HTTPS/HTTP2/HTTP3/DTLS 代理协议（tls:// 视为 https://） |
| **内网穿透**   | 支持反向代理，将内网服务安全暴露到公网                              |
| **智能路由**   | 基于域名、IP、GeoIP 的精细化流量分流规则                            |
| **安全强化**   | 默认启用 TLS 验证，支持 TLS/DTLS 加密传输                           |

### 设计哲学

1.  **四层解耦 (Four Layers)**:
    *   **Listener (入站)**: 负责监听与接入连接。
    *   **Handler (入站协议)**: 解析协议并驱动转发。
    *   **Dialer (传输层)**: 负责建立物理连接 (TCP/UDP/TLS/DTLS/H2/H3/HTTP3)。
    *   **Connector (连接层)**: 负责协议握手和隧道建立 (HTTP CONNECT, SOCKS5)。
    *   通过 Transport 组合 Dialer + Connector，可实现 "SOCKS5 over TLS/DTLS" 或 "HTTP over H2/H3" 的灵活组合。
2.  **接口优先**: 所有核心组件（Listener, Handler, Dialer, Connector）均通过接口定义，便于扩展和测试。
3.  **链式架构**: 通过 `chain` 包统一管理转发节点，支持无限级联的代理链。
4.  **配置驱动**: 支持命令行参数、JSON 配置文件、INI 路由规则三种配置方式，满足不同场景需求。

---

## 架构设计

### 整体架构

```mermaid
graph TD
    User[用户/客户端] --> Listener[Listener 层]
    Listener --> Handler[Handler 层]
    Handler --> Router[Router 层]
    Router -->|选择路由| Chain[转发链 Chain]
    Chain -->|组合| Transport[Transport]
    Transport -->|1. 建立连接| Dialer[Dialer 层]
    Transport -->|2. 协议握手| Connector[Connector 层]
    Connector --> Target[目标服务器/下一跳]

    subgraph "核心流程"
    Listener
    Handler
    Router
    Chain
    end

    subgraph "出站实现"
    Dialer
    Connector
    end
```

### 分层架构体系

```text
Layer 1: 入口与配置 (Entry & Config)
    ├── cmd/forward/          # internal 入口
    ├── cmd/forward-inner/    # inner 入口 (保留)
    ├── base/app/             # internal 生命周期管理
    └── internal/config/      # 配置解析 (INI/JSON/Flags)

Layer 2: 服务监听 (Service Layer)
    ├── internal/service/     # 服务编排 (Listener + Handler)
    ├── internal/listener/    # 入站连接监听 (TCP/UDP/HTTP2/HTTP3/H2/H3/DTLS)
    └── internal/handler/     # 入站协议处理 (HTTP(含 H2/H3)/SOCKS5/TCP/UDP)

Layer 3: 路由决策 (Routing Layer)
    ├── internal/router/      # 路由管理器
    ├── base/route/           # 路由规则库
    └── internal/chain/       # 转发链管理

Layer 4: 出站连接 (Outbound Layer)
    ├── internal/chain/       # Transport 封装
    ├── internal/dialer/      # 传输层拨号 (TCP/UDP/TLS/DTLS/H2/H3/HTTP3)
    ├── internal/connector/   # 协议层连接 (HTTP CONNECT/HTTP2/HTTP3/SOCKS5/TCP)
    ├── internal/h2/          # HTTP/2 PHT 共享封装
    ├── internal/h3/          # HTTP/3 PHT 共享封装
    └── internal/dtls/        # DTLS conn 封装

Layer 5: 基础设施 (Infrastructure)
    ├── base/logging/         # 日志系统
    ├── base/auth/            # 认证管理
    ├── base/endpoint/        # 端点解析
    └── base/pool/            # 缓冲池优化
```

注：`inner/` 为历史实现，保留兼容；`internal/` 为当前四层实现，`base/` 提供公共基础能力。

---

## 核心模块

### 1. Listener (入站监听器)

**定位**：负责监听入站连接，并将连接交给 Service/Handler。

**接口定义**：
```go
type Listener interface {
    Init(metadata.Metadata) error
    Accept() (net.Conn, error)
    Addr() net.Addr
    Close() error
}
```

**主要实现**：
*   `tcp`: TCP 监听。
*   `udp`: UDP 会话化监听（按客户端地址维护会话）。
*   `http2`: HTTP/2 代理监听（TLS + CONNECT）。
*   `http3`: HTTP/3 代理监听（QUIC + CONNECT）。
*   `h2`: HTTP/2 传输隧道监听（TLS + PHT）。
*   `h3`: HTTP/3 传输隧道监听（QUIC + PHT）。
*   `quic`: Raw QUIC 监听（纯 QUIC 传输）。
*   `dtls`: DTLS 监听（UDP + DTLS）。

### 2. Handler (入站处理器)

**定位**：解析协议，确定目标地址并驱动转发。

**主要实现**：
*   `http`: HTTP/1.1/2/3 CONNECT/普通代理，支持 `X-Forward-Protocol: udp` + `udptun` 的 UDP 隧道。
*   `socks5`: 支持 CONNECT 与 UDP ASSOC。
*   `tcp`: 端口转发。
*   `udp`: UDP 端口转发。

### 3. Dialer (传输层拨号器)

**定位**：建立到下一跳/目标的底层连接，可包含握手阶段。

**接口定义**：
```go
type Dialer interface {
    Init(metadata.Metadata) error
    Dial(ctx context.Context, addr string, opts ...DialOption) (net.Conn, error)
}
```

**主要实现**：
*   `tcp`: 基础 TCP 连接。
*   `udp`: 基础 UDP 连接。
*   `tls`: 在 TCP 之上封装 TLS 握手。
*   `dtls`: 在 UDP 之上封装 DTLS 握手。
*   `h2`: HTTP/2 传输隧道（TLS + PHT，多路复用）。
*   `h3`: HTTP/3 传输隧道（QUIC + PHT，多路复用）。
*   `quic`: Raw QUIC 拨号（纯 QUIC 传输）。
*   `http3`: HTTP/3 代理拨号（QUIC）。

### 4. Connector (协议层连接器)

**定位**：在已建立的连接（由 Dialer 提供）之上，执行特定协议的握手或隧道建立操作。

**接口定义**：
```go
type Connector interface {
    Init(metadata.Metadata) error
    Connect(ctx context.Context, conn net.Conn, network, address string, opts ...ConnectOption) (net.Conn, error)
}
```

**主要实现**：
*   `http`: HTTP CONNECT（支持 H1/H2），支持 UDP 隧道。
*   `http2`: HTTP/2 CONNECT（强制 H2）。
*   `http3`: HTTP/3 CONNECT。
*   `socks5`: SOCKS5 握手与命令交互。
*   `tcp`: 直通（无握手）。

### 5. Transport (传输组合)

**定位**：`internal/chain` 包中的核心概念，将 `Dialer` 和 `Connector` 组合成一个完整的出站能力。

*   每个转发节点（Node/Hop）都由一个 `Transport` 实例表示。
*   代理链本质上是一组有序的 `Transport`。

---

## 支持的协议

| 方案               | Listener (入站) | Dialer (传输) | Connector (出站握手) | 说明                            |
| :----------------- | :-------------: | :-----------: | :------------------: | :------------------------------ |
| **TCP**            |        ✅        |       ✅       |          ✅           | 端口转发/直连                   |
| **UDP**            |        ✅        |       ✅       |          -           | UDP 端口转发；代理可走 UDP 隧道 |
| **HTTP**           |        ✅        |       -       |          ✅           | HTTP 代理 / CONNECT             |
| **HTTP+TLS/HTTPS** |        ✅        |    ✅ (tls)    |          ✅           | HTTP over TLS (H1/H2)           |
| **HTTP+DTLS**      |        ✅        |   ✅ (dtls)    |          ✅           | HTTP over DTLS                  |
| **SOCKS5**         |        ✅        |       -       |          ✅           | 标准 SOCKS5                     |
| **SOCKS5H**        |        ✅        |       -       |          ✅           | SOCKS5 (服务端解析域名)         |
| **SOCKS5+TLS**     |        ✅        |    ✅ (tls)    |          ✅           | SOCKS5 over TLS                 |
| **SOCKS5+DTLS**    |        ✅        |   ✅ (dtls)    |          ✅           | SOCKS5 over DTLS                |
| **TCP+TLS**        |        ✅        |    ✅ (tls)    |          ✅           | 加密端口转发                    |
| **TCP+DTLS**       |        ✅        |   ✅ (dtls)    |          ✅           | 加密端口转发                    |
| **HTTP2 (代理)**   |        ✅        |    ✅ (tls)    |      ✅ (http2)       | HTTP/2 代理 (CONNECT over h2)   |
| **HTTP3 (代理)**   |        ✅        |   ✅ (http3)   |      ✅ (http3)       | HTTP/3 代理 (CONNECT over h3)   |
| **H2 (隧道)**      |        ✅        |    ✅ (h2)     |          ✅           | HTTP/2 传输隧道 (PHT，多路复用) |
| **H2 (隧道)**      |        ✅        |    ✅ (h2)     |          ✅           | HTTP/2 传输隧道 (PHT，多路复用) |
| **H3 (隧道)**      |        ✅        |    ✅ (h3)     |          ✅           | HTTP/3 传输隧道 (PHT，多路复用) |
| **Raw QUIC**       |        ✅        |   ✅ (quic)    |          -           | 原始 QUIC 传输 (无 HTTP 语义)   |
| **VLESS+Reality**  |        ✅        |  ✅ (reality)  |      ✅ (vless)       | VLESS 代理 + Reality 传输       |
| **RTCP**           |        -        |       -       |          -           | 反向 TCP 穿透客户端 (rtcp)      |
| **RUDP**           |        -        |       -       |          -           | 反向 UDP 穿透客户端 (rudp)      |

说明：
*   `https://` 等价 `http+tls://`，`tls://` 等价 `https://`，`dtls://` 等价 `tcp+dtls://`。
*   `http2://` 与 `http3://` 是协议代理；`h2://` 等价 `http+h2://`，`h3://` 等价 `http+h3://`。
*   `socks5+h2://`、`socks5+h3://`、`tcp+h2://`、`tcp+h3://` 用于 H2/H3 传输隧道承载。
*   反向穿透：公网侧 `tls://`/`https://`/`http3://`/`quic://`/`reality://`/`vless+reality://` 需加 `?bind=true`；内网侧使用 `rtcp://` 或 `rudp://` 并指定目标地址。
*   `udp+tls`/`udp+dtls` 当前不支持。

---

## 功能清单与测试矩阵

### 功能清单（internal 实现）

- **运行模式**：端口转发、代理服务器、反向穿透（服务端/客户端）
- **协议代理**：HTTP/HTTPS/TLS、HTTP/2、HTTP/3、SOCKS5/SOCKS5H、VLESS+Reality
- **传输隧道**：`+tls`/`+dtls`/`+h2`/`+h3`（HTTP/SOCKS5/TCP 组合）
- **端口转发**：TCP/UDP（含 TCP over TLS/DTLS/H2/H3）
- **反向穿透**：`rtcp`/`rudp` + `tls`/`https`/`http3`/`quic`/`reality`/`vless+reality`
- **路由能力**：静态路由、链式转发、基于规则的分流
- **认证与安全**：HTTP/SOCKS5 用户密码、VLESS UUID、TLS/DTLS/Reality 加密
- **UDP 能力**：UDP 端口转发；HTTP CONNECT + `X-Forward-Protocol: udp` 与 SOCKS5 UDP ASSOC

### E2E 测试矩阵（`tests/`）

| 功能                  | 覆盖测试                    | 说明                                           |
| --------------------- | --------------------------- | ---------------------------------------------- |
| TCP 转发 + 传输层组合 | `TestPortForwardTransports` | 覆盖 tcp/tls/dtls/h2/h3                        |
| UDP 端口转发          | `TestUDPPortForward`        | 覆盖 udp forward                               |
| 代理协议（基础）      | `TestProxySchemesTCP`       | 覆盖 http/https/tls/http2/http3/socks5/socks5h |
| 传输隧道代理          | `TestProxyTransportTunnels` | 覆盖 socks5+tls/h2/h3                          |
| 反向穿透              | `TestReverseTCPOverTLS`     | 覆盖 rtcp + tls                                |
| VLESS+Reality 代理    | `TestProxyVlessReality`     | 覆盖 reality 传输 + vless 握手                 |

说明：反向 `rudp`、反向 `quic/http3` 与更多路由规则的 e2e 链路暂未覆盖，可按需补充。

---

## 详细使用方式

### 1. 命令行快速模式

**简单转发**
```bash
# 将本地 8080 端口转发到 1.2.3.4:80
forward -L tcp://:8080/1.2.3.4:80

# UDP 端口转发
forward -L udp://:5353/1.1.1.1:53
```

**加密转发**
```bash
# TCP over TLS
forward -L tcp+tls://:9000/1.2.3.4:22 --debug

# TCP over DTLS
forward -L tcp+dtls://:9000/1.2.3.4:22 --debug
```

**启动代理服务器**
```bash
# 启动 HTTP 和 SOCKS5 混合代理
forward -L http://:8080 -L socks5://:1080

# HTTPS 代理（HTTP/1.1 + HTTP/2）
forward -L https://:8443 --debug

# HTTP/3 代理（QUIC）
forward -L http3://:443 --debug

# HTTP/2 代理（TLS + CONNECT）
forward -L http2://:443 --debug

# SOCKS5 over TLS / DTLS
forward -L socks5+tls://:1080 --debug
forward -L socks5+dtls://:1080 --debug

# SOCKS5 over H2/H3 传输隧道
forward -L socks5+h2://:1080 --debug
forward -L socks5+h3://:1080 --debug
```

**使用代理链**
```bash
# 本地 -> 代理A -> 代理B -> 目标
forward -L tcp://:8080/target:80 -F socks5://proxyA:1080 -F http://proxyB:8080

# HTTP/3 链路
forward -L http://:1080 -F http3://proxyA:443 -F http3://proxyB:443 --insecure --debug

# HTTP/2 链路
forward -L http://:1080 -F http2://proxyA:443 -F http2://proxyB:443 --insecure --debug

# SOCKS5 over H2/H3 传输隧道链路
forward -L socks5://:1080 -F socks5+h2://proxyA:443 -F socks5+h3://proxyB:443 --insecure --debug
```

**内网穿透（反向转发）**
```bash
# 公网服务端（要求用户名密码或 vless uuid）
forward -L tls://user:pass@:2333?bind=true --debug
forward -L vless+reality://uuid@:2333?bind=true&pbk=PUBKEY&sid=SID --debug

# 内网客户端（反向 TCP）
forward -L rtcp://:2222/10.1.1.2:22 -F tls://user:pass@public.example.com:2333 --insecure --debug
forward -L rtcp://:2222/10.1.1.2:22 -F vless+reality://uuid@public.example.com:2333?pbk=PUBKEY&sid=SID --debug

# 内网客户端（反向 UDP）
forward -L rudp://:5353/10.1.1.2:53 -F tls://user:pass@public.example.com:2333 --insecure --debug
```

### 2. 配置文件模式

推荐使用 JSON 配置文件管理复杂配置。

**config.json 示例**：
```json
{
  "nodes": [
    {
      "name": "main_proxy",
      "listen": "socks5+tls://:1080",
      "forward_chain": [
        "socks5://10.0.0.1:1080",
        "http3://proxy.example.com:443"
      ]
    },
    {
      "name": "web_tunnel",
      "listen": "http+dtls://:8080"
    }
  ],
  "route": {
    "proxies": {
      "US_NODE": "socks5://us.example.com:1080"
    }
  }
}
```

---

## 路由规则

支持基于域名的精细化路由控制。使用 `-R route.ini` 加载。

### 规则语法
```ini
[General]
listen = socks5://:7890

[Proxy]
MyVPS = socks5+tls://user:pass@host:443

[Rule]
# 语法: 类型, 匹配值, 动作
DOMAIN-SUFFIX, google.com, MyVPS
DOMAIN-KEYWORD, twitter, MyVPS
GEOIP, CN, DIRECT
FINAL, MyVPS
```

*   **DIRECT**: 直连
*   **REJECT**: 拒绝连接
*   **ProxyName**: 转发到 [Proxy] 段定义的节点

---

## 扩展开发

### 添加新协议支持

得益于 Listener/Handler/Dialer/Connector 分层架构，添加新协议非常简便：

**场景 1：添加新的传输协议 (如 WebSocket)**
1.  在 `internal/dialer/<name>` 实现 `Dialer`/`Handshaker` 接口。
2.  在 `registry.DialerRegistry().Register` 中注册 scheme。
3.  在 `internal/builder/route.go` 中新增 scheme 映射。

**场景 2：添加新的代理协议 (如 Shadowsocks)**
1.  在 `internal/handler/<name>` 实现入站 Handler。
2.  在 `internal/connector/<name>` 实现出站 Connector。
3.  在 `registry.HandlerRegistry().Register` 与 `registry.ConnectorRegistry().Register` 中注册，并在 `base/app`/`internal/builder/route.go` 中新增 scheme 映射。

### 源码编译

```bash
# 或者是 make build
go build -o forward cmd/forward/main.go
```

---

## 配置项适用范围

> [!IMPORTANT]
> 部分配置项仅对特定协议生效，使用时请注意。

### 超时配置

| 配置项              | 适用范围                  | 默认值 | 说明             |
| ------------------- | ------------------------- | ------ | ---------------- |
| `DialTimeout`       | 所有出站连接              | 10s    | 连接建立超时     |
| `HandshakeTimeout`  | TLS/DTLS/SOCKS5/HTTP 代理 | 5s     | 协议握手超时     |
| `ReadHeaderTimeout` | HTTP/1.1 handler          | 10s    | 读取请求头超时   |
| `IdleTimeout`       | HTTP/1.1 handler          | 2min   | 连接空闲超时     |
| `UDPIdleTimeout`    | SOCKS5 UDP / UDP 转发     | 2min   | UDP 会话空闲超时 |
| `DNSTimeout`        | 路由规则 DNS 解析         | 5s     | DNS 查询超时     |

### 限制配置

| 配置项           | 适用范围              | 默认值 | 说明             |
| ---------------- | --------------------- | ------ | ---------------- |
| `MaxHeaderBytes` | HTTP/1.1 handler      | 1MB    | 请求头最大字节数 |
| `MaxConnections` | Reverse handler       | 4096   | 最大并发连接数   |
| `MaxUDPSessions` | SOCKS5 UDP / UDP 转发 | 1024   | 最大 UDP 会话数  |

### 缓冲区配置

| 配置项              | 适用范围     | 默认值 | 说明               |
| ------------------- | ------------ | ------ | ------------------ |
| `DefaultCopyBuffer` | TCP 双向复制 | 32KB   | 流复制缓冲区大小   |
| `DefaultUDPBuffer`  | UDP 转发     | 65535  | UDP 报文最大缓冲区 |

### 未使用的配置项

以下配置项已定义但当前**未被使用**（保留用于未来扩展）：

- `ReadDeadline` - 仅在部分内部逻辑中使用
- `DialKeepAlive` - TCP KeepAlive 设置，当前未传递

> [!NOTE]
> 如需使用这些配置项，请检查对应的 handler/dialer 实现是否支持。
