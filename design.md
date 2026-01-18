# Go Forward 设计文档

> 一个安全、轻量级、高性能的端口转发和代理工具

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

| 功能           | 描述                                        |
| -------------- | ------------------------------------------- |
| **端口转发**   | TCP/UDP 端口转发，支持代理链                |
| **代理服务器** | HTTP/SOCKS5/TLS/QUIC/VLESS+Reality 代理协议 |
| **内网穿透**   | 反向代理，将内网服务暴露到公网 TCP/UDP      |
| **智能路由**   | 基于规则的流量分流（域名/IP/GeoIP）         |

### 设计原则

1. **结构分层**: Listener / Handler / Dialer
2. **模块化设计**：Dialer 和 Listener 使用工厂模式，易于扩展新协议
3. **零配置启动**：支持命令行参数快速启动
4. **安全优先**：认证使用 constant-time 比较，TLS 默认验证证书
5. **高性能**：使用连接池、缓冲区复用、多路复用（Yamux/QUIC）

---

## 架构设计

### 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                           cmd/forward                           │
│                         (程序入口 main.go)                       │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                          internal/app                            │
│    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│    │   app.go     │  │  forward.go  │  │  version.go  │         │
│    │  (主逻辑)     │  │  (工厂初始化) │  │  (版本信息)  │         │
│    └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                                  │
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────┐
│     Listener 层     │ │      Handler 层     │ │    Dialer 层    │
│  (接收入站连接)      │ │   (处理协议逻辑)     │ │  (建立出站连接)  │
└─────────────────────┘ └─────────────────────┘ └─────────────────┘
```

### 分层架构

```
Layer 1: 入口层 (Entry)
    └── cmd/forward/main.go
    └── internal/app/app.go

Layer 2: 网络层 (Network)
    ├── internal/listener/     # 监听器（接收连接）
    │   ├── tcp/              # TCP 监听
    │   ├── udp/              # UDP 监听
    │   ├── http/             # HTTP/HTTPS 监听
    │   ├── http3/            # HTTP/3 (QUIC) 监听
    │   ├── socks5/           # SOCKS5 监听
    │   ├── vless/            # VLESS+REALITY 监听
    │   └── reverse/          # 反向代理监听
    │
    └── internal/dialer/       # 拨号器（建立连接）
        ├── direct/           # 直连
        ├── http/             # HTTP CONNECT 代理
        ├── socks5/           # SOCKS5 代理
        ├── tls/              # TLS 加密
        ├── quic/             # QUIC/HTTP3
        └── vless/            # VLESS 协议

Layer 3: 协议层 (Protocol)
    └── internal/handler/      # 协议处理器
        ├── http/             # HTTP 代理处理
        ├── socks5/           # SOCKS5 处理
        ├── tcp/              # TCP 转发处理
        ├── udp/              # UDP 转发处理
        └── reverse/          # 反向代理处理

Layer 4: 路由层 (Routing)
    └── internal/route/        # 路由规则引擎
        ├── route.go          # 规则匹配
        ├── store.go          # 规则存储
        └── via.go            # 路由决策

Layer 5: 基础设施层 (Infrastructure)
    ├── internal/config/       # 配置管理
    ├── internal/auth/         # 认证
    ├── internal/logging/      # 日志
    ├── internal/pool/         # 缓冲区池
    └── internal/io/net/       # IO 工具
```

---

## 核心模块

### 1. Dialer 拨号器

**功能**：建立到目标的出站连接

**接口定义**：
```go
type Dialer interface {
    DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
```

**工厂注册**：

```go
// 在 init() 中注册
dialer.Register("http", newDialer)
dialer.Register("https", newDialer)
dialer.Register("socks5", newDialer)
```

**支持的 Scheme**：

| Scheme          | 实现            | 说明              |
| --------------- | --------------- | ----------------- |
| `direct`        | `dialer/direct` | 直接连接          |
| `http`          | `dialer/http`   | HTTP CONNECT 代理 |
| `https`         | `dialer/http`   | HTTPS 代理（TLS） |
| `socks5`        | `dialer/socks5` | SOCKS5 代理       |
| `tls`           | `dialer/tls`    | TLS 加密连接      |
| `quic`          | `dialer/quic`   | QUIC/HTTP3 连接   |
| `vless`         | `dialer/vless`  | VLESS 协议        |
| `vless+reality` | `dialer/vless`  | VLESS+REALITY     |
| `reality`       | `dialer/vless`  | `vless+reality` 别名 |

---

### 2. Listener 监听器

**功能**：接收入站连接并分发给 Handler 处理

**接口定义**：

```go
type Runner interface {
    Run(ctx context.Context) error
}
```

**支持的 Scheme**：

| Scheme   | 实现              | 说明               |
| -------- | ----------------- | ------------------ |
| `tcp`    | `listener/tcp`    | TCP 端口转发       |
| `udp`    | `listener/udp`    | UDP 端口转发       |
| `http`   | `listener/http`   | HTTP 代理服务      |
| `https`  | `listener/http`   | HTTPS 代理服务     |
| `socks5` | `listener/socks5` | SOCKS5 代理服务    |
| `http3`  | `listener/http3`  | HTTP/3 代理服务    |
| `vless+reality` | `listener/vless` | VLESS+REALITY 服务 |
| `reality` | `listener/vless` | `vless+reality` 别名 |

---

### 3. Handler 处理器

**功能**：处理具体协议逻辑

| Handler   | 功能                                  |
| --------- | ------------------------------------- |
| `http`    | HTTP/HTTPS 代理请求处理、CONNECT 隧道 |
| `socks5`  | SOCKS5 CONNECT 和 UDP ASSOCIATE       |
| `tcp`     | TCP 端口转发（双向数据传输）          |
| `udp`     | UDP 数据报转发                        |
| `reverse` | 反向代理服务端（Yamux 多路复用）      |

---

### 4. Route 路由引擎

**功能**：根据规则决定流量走向

**规则类型**：

| 类型             | 示例             | 说明                          |
| ---------------- | ---------------- | ----------------------------- |
| `DOMAIN`         | `google.com`     | 精确匹配域名                  |
| `DOMAIN-SUFFIX`  | `google.com`     | 匹配域名后缀                  |
| `DOMAIN-KEYWORD` | `google`         | 匹配域名关键字                |
| `IP-CIDR`        | `192.168.0.0/16` | 匹配 IP 地址段                |
| `GEOIP`          | `CN`             | 匹配国家/地区（需 MaxMindDB） |
| `FINAL`          | -                | 兜底规则                      |

**动作类型**：

| 动作         | 说明         |
| ------------ | ------------ |
| `DIRECT`     | 直接连接     |
| `REJECT`     | 拒绝连接     |
| `PROXY:name` | 使用指定代理 |

---

### 5. 反向代理架构

```
┌─────────────────┐         ┌─────────────────┐
│   内网客户端      │         │   公网服务器     │
│                 │ TLS/QUIC/REALITY │                 │
│  reverse/client │◀───────▶│ reverse/server  │
│                 │  Yamux  │                 │
└────────┬────────┘         └────────┬────────┘
         │                           │
         │ 拨号本地目标                │ 绑定公网端口
         ▼                           ▼
   ┌───────────┐              ┌───────────┐
   │ 内网服务   │              │ 外部客户端  │
   │ (SSH/Web) │              │ (用户访问) │
   └───────────┘              └───────────┘
```

**通信流程**：

1. 内网客户端连接公网服务器建立隧道
2. 使用 SOCKS5 BIND 协议注册要暴露的端口
3. 使用 Yamux 多路复用处理多个并发连接
4. 外部流量通过隧道转发到内网

---

## 支持的协议

### 代理协议对比

| 协议   | 端口    | 加密    | UDP | 认证      | 特点      |
| ------ | ------- | ------- | --- | --------- | --------- |
| HTTP   | 80/8080 | ❌       | ❌   | Basic     | 最通用    |
| HTTPS  | 443     | TLS     | ❌   | Basic     | 加密 HTTP |
| SOCKS5 | 1080    | ❌       | ✅   | User/Pass | 支持 UDP  |
| TLS    | 443     | TLS     | ❌   | Basic     | 加密隧道  |
| QUIC   | 443     | TLS1.3  | ✅   | Basic     | 0-RTT     |
| VLESS  | 443     | REALITY | ✅   | UUID      | 抗检测    |

---

## 详细使用方式

### 1. 基础命令

```bash
# 查看帮助
forward -h

# 查看版本
forward -version

# 启用调试日志
forward -debug -L ...
```

### 2. 端口转发

```bash
# TCP 转发：本地 8080 -> 远程 80
forward -L tcp://:8080/1.2.3.4:80

# 等价写法
forward -L tcp://:8080 -F tcp://1.2.3.4:80

# UDP 转发：本地 5353 -> 8.8.8.8:53
forward -L udp://:5353/8.8.8.8:53
```

### 3. 代理服务器

```bash
# HTTP 代理
forward -L http://:8080

# SOCKS5 代理
forward -L socks5://:1080

# 带认证的代理
forward -L socks5://user:pass@:1080

# TLS 代理（自定义证书）
forward -L "tls://:443?cert=server.crt&key=server.key"

# QUIC/HTTP3 代理
forward -L "quic://:443?cert=server.crt&key=server.key"

# VLESS+REALITY（高隐蔽性，reality 为别名）
forward -L "vless+reality://uuid@:443?dest=swscan.apple.com:443&sni=swscan.apple.com&sid=12345678&key=private.key"
forward -L "reality://uuid@:443?dest=swscan.apple.com:443&sni=swscan.apple.com&sid=12345678&key=private.key"

# 参数说明
# - key: 服务端私钥（可省略自动生成，建议保存）
# - pbk: 客户端公钥（由服务端私钥派生）
# - sid: Short ID，可用逗号分隔多个
# - sni: 伪装域名（Server Name）
# - dest: REALITY 回落目标（仅服务端）
# - flow: 默认 xtls-rprx-vision
```

### 4. 代理链

```bash
# 单跳
forward -L http://:8080 -F tls://user:pass@remote.com:443

# 多跳（S2 -> S1）
forward -L http://:8080 -F http://S2:8080 -F http://S1:8080
```

说明：
* `-F` 可重复，顺序从近到远。
* 多跳链仅支持 http/https/tls/socks5 作为中继协议。
* QUIC/HTTP3 多跳需要 UDP-capable base（如 socks5）。
* VLESS 多跳仅支持 TCP 传输（`type=tcp`）。

### 5. 内网穿透

**服务端（公网）**：

```bash
# 启动反向代理服务器
forward -L "tls://user:pass@:443?bind=true&cert=server.crt&key=server.key"

# VLESS+REALITY 反向服务器（reality 为别名，需 bind=true）
forward -L "reality://uuid@:2333?bind=true&key=xxxx&sid=xxxxx&sni=swscan.apple.com"
```

**客户端（内网）**：

```bash
# 将远程 2222 端口映射到本地 22
forward -L tcp://:2222/127.0.0.1:22 -F tls://user:pass@server.com:443

# 将远程 8080 端口映射到本地 80
forward -L tcp://:8080/127.0.0.1:80 -F tls://user:pass@server.com:443

# VLESS+REALITY 反向客户端（target 默认使用服务端 host:port，可用 target=host:port 覆盖）
forward -L tcp://:2222/127.0.0.1:22 -F "reality://uuid@server.com:2333?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=xxx&security=reality&sid=xxxx&sni=swscan.apple.com&type=tcp"

# 说明：
# - 反向服务端必须设置 bind=true
# - target 用于指定 VLESS 请求目标，仅客户端使用（默认服务端 host:port）
```

**访问方式**：

```bash
# 通过公网服务器访问内网 SSH
ssh -p 2222 server.com
```

### 6. 多监听

```bash
# 同时启动多个服务
forward -L http://:8080 -L socks5://:1080 -L tcp://:2222/10.0.0.1:22
```

### 7. TLS 自定义

```bash
# 服务端：使用证书
forward -L "tls://:443?cert=/path/to/cert.cer&key=/path/to/private.key"

# 客户端：自签名 CA
forward -L http://:8080 -F "tls://server.com:443?ca=/path/to/ca.cer&sni=server.com"

# 客户端：跳过证书验证（仅测试）
forward -L http://:8080 -F tls://server.com:443 -insecure
```

---

## 配置文件

### JSON 配置

**简单格式**：

```json
{
  "listen": "http://:8080",  // 监听单个
  "forward": "tls://user:pass@remote.com:443", // 单跳转发
  "forwards": ["http://S2:8080", "http://S1:8080"], // 多跳转发（与 forward 互斥）
  "listeners": ["http://:8080", "socks5://:1080"],  // 监听多个
  "insecure": false,
  "debug": false
}
```

**多节点格式**：

```json
{
  "nodes": [
    {
      "name": "proxy_server",
      "listen": "http://:8080",
      "forward": "tls://remote.com:443"
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

**使用方式**：

```bash
# 默认读取 ~/.forward/forward.json or ~/forward.json
forward -C config.json
```

### 路由配置

**格式**：

```ini
[General]
listen = http://0.0.0.0:8000, socks5://0.0.0.0:1080
debug = false
skip-proxy = 192.168.0.0/16, 127.0.0.1/32
dns-server = 8.8.8.8,8.8.4.4
mmdb-path=~/.forward/Country.mmdb
mmdb-link=https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb

DOMAIN,ifconfig.me,PROXY_JP
[Proxy]
PROXY_SG = vless://uuid@sg.example.com:443?...
PROXY_JP = vless://uuid@jp.example.com:443?...
PROXY_01 = https://user:pass@:443?...

[Rule]
# - Rules type: DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / GEOIP
# - Action: PROXY_NAME DIRECT REJECT FINAL

DOMAIN-SUFFIX, google.com, PROXY_SG
DOMAIN-KEYWORD, youtube, PROXY_SG
GEOIP, CN, DIRECT
IP-CIDR, 192.168.0.0/16, DIRECT
FINAL, PROXY_JP
```

**使用方式**：

```bash
forward -R route.conf
```

---

## 路由规则

### 规则语法

```text
类型, 匹配值, 动作
```

### 规则示例

```ini
# 域名精确匹配
DOMAIN, www.google.com, PROXY_SG

# 域名后缀匹配
DOMAIN-SUFFIX, google.com, PROXY_SG

# 域名关键字匹配
DOMAIN-KEYWORD, youtube, PROXY_SG

# IP 地址段匹配
IP-CIDR, 192.168.0.0/16, DIRECT
IP-CIDR, 10.0.0.0/8, DIRECT

# 国家/地区匹配（需要 MMDB）
GEOIP, CN, DIRECT
GEOIP, US, PROXY_US

# 兜底规则（必须放最后）
FINAL, PROXY_JP
```

### 规则优先级

规则按配置顺序匹配，**先匹配先生效**。建议顺序：

1. 特定域名规则
2. 域名后缀规则
3. 域名关键字规则
4. IP-CIDR 规则
5. GEOIP 规则
6. FINAL 兜底规则

---

## 扩展开发

### 添加新的 Dialer

1. 创建 `internal/dialer/myproto/` 目录
2. 实现 `Dialer` 接口
3. 在 `register.go` 中注册

```go
package myproto

import (
    "forward/internal/dialer"
)

func init() {
    dialer.Register("myproto", New)
}

func New(cfg config.Config) (dialer.Dialer, error) {
    return &Dialer{...}, nil
}

type Dialer struct {}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
    // 实现拨号逻辑
}
```

### 添加新的 Listener

1. 创建 `internal/listener/myproto/` 目录
2. 实现 `Runner` 接口
3. 在 `register.go` 中注册

```go
package myproto

import (
    "forward/internal/listener"
)

func init() {
    listener.Register("myproto", New)
}

func New(cfg config.Config, d dialer.Dialer) (listener.Runner, error) {
    return &Listener{...}, nil
}

type Listener struct {}

func (l *Listener) Run(ctx context.Context) error {
    // 实现监听逻辑
}
```

---

## 依赖说明

| 依赖                                   | 用途               |
| -------------------------------------- | ------------------ |
| `github.com/quic-go/quic-go`           | QUIC 协议支持      |
| `github.com/hashicorp/yamux`           | TCP 多路复用       |
| `github.com/xtls/xray-core`            | VLESS/REALITY 协议 |
| `github.com/oschwald/maxminddb-golang` | GeoIP 地址库       |
| `golang.org/x/crypto`                  | SSH/TLS 加密       |

---

## 安全建议

1. **始终使用认证**：生产环境必须设置用户名密码
2. **使用 TLS/QUIC**：明文协议仅用于测试
3. **定期更新证书**：避免使用自签名证书
4. **限制绑定地址**：使用 `127.0.0.1` 而非 `0.0.0.0`
5. **启用路由规则**：避免成为开放代理

---

**文档版本：1.0 | 最后更新：2026-01-12**
