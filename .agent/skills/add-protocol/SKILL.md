---
name: add-protocol
description: 添加新协议到 go-forward 项目，遵循 gost 四层架构设计（Dialer/Connector/Handler/Listener）
---

# 添加新协议 Skill

本 skill 指导如何在 go-forward 项目中添加新的网络协议支持，严格遵循 gost 的四层架构设计原则，可以直接参考和使用 gost 的具体实现。

---

## 架构概览

```text
┌─────────────────────────────────────────────────────────────────┐
│                        核心四层架构                               │
├──────────────┬──────────────────────────────────────────────────┤
│   Listener   │ 入站监听层 - 监听并接受客户端连接                   │
│              │ 接口: Init(), Accept(), Addr(), Close()           │
├──────────────┼──────────────────────────────────────────────────┤
│   Handler    │ 入站处理层 - 解析协议并路由转发                     │
│              │ 接口: Init(), Handle(ctx, conn)                   │
├──────────────┼──────────────────────────────────────────────────┤
│   Dialer     │ 传输层 - 建立底层网络连接 (TCP/TLS/QUIC)           │
│              │ 接口: Init(), Dial(ctx, addr)                     │
├──────────────┼──────────────────────────────────────────────────┤
│   Connector  │ 连接层 - 在已建立连接上执行协议握手                 │
│              │ 接口: Init(), Connect(ctx, conn, network, addr)   │
└──────────────┴──────────────────────────────────────────────────┘
```

### 设计原则

1. **职责分离**: Dialer 负责传输层连接，Connector 负责协议层握手
2. **接口优先**: 所有组件通过接口定义，便于扩展和测试
3. **注册机制**: 使用 `registry` 包统一管理协议注册
4. **Option 模式**: 使用函数选项模式进行配置

---

## 添加新协议的步骤

### 场景一：添加新的 **传输协议** (如 WebSocket, KCP)

> 传输协议只需实现 Dialer，可复用现有 Connector

#### 1. 创建目录结构

```bash
mkdir -p internal/dialer/<protocol-name>
```

#### 2. 实现 Dialer 接口

创建 `internal/dialer/<protocol-name>/dialer.go`：

```go
package <protocol_name>

import (
    "context"
    "net"
    
    "forward/internal/dialer"
    "forward/internal/metadata"
    "forward/internal/registry"
)

// 在 init() 中注册协议
func init() {
    registry.DialerRegistry().Register("<protocol>", NewDialer)
}

type Dialer struct {
    // 协议特定的配置字段
    timeout time.Duration
    // ...
}

// NewDialer 使用 Option 模式创建实例
func NewDialer(opts ...dialer.Option) dialer.Dialer {
    options := dialer.Options{}
    for _, opt := range opts {
        opt(&options)
    }
    
    return &Dialer{
        timeout: options.Timeout,
        // 从 options 中提取配置...
    }
}

// Init 可用于从 metadata 中读取额外配置
func (d *Dialer) Init(md metadata.Metadata) error {
    if md == nil {
        return nil
    }
    // 从 md 中读取配置...
    return nil
}

// Dial 建立底层连接
func (d *Dialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
    // 实现连接逻辑
    // 1. 可能需要先通过 TCP Dialer 建立基础连接
    // 2. 在基础连接之上建立协议特定的连接
    return nil, nil
}

// 可选：如果协议需要额外握手，实现 Handshaker 接口
func (d *Dialer) Handshake(ctx context.Context, conn net.Conn, opts ...dialer.HandshakeOption) (net.Conn, error) {
    // TLS 握手等
    return conn, nil
}
```

#### 3. 参考现有实现

- **TCP Dialer**: `internal/dialer/tcp/dialer.go` - 最简单的基础实现
- **TLS Dialer**: `internal/dialer/tls/dialer.go` - 在 TCP 之上增加 TLS 握手

---

### 场景二：添加新的 **代理协议** (如 Shadowsocks, VMess, Trojan)

> 代理协议需要实现 Connector，可运行在任意 Dialer 之上

#### 1. 创建目录结构

```bash
mkdir -p internal/connector/<protocol-name>
```

#### 2. 实现 Connector 接口

创建 `internal/connector/<protocol-name>/connector.go`：

```go
package <protocol_name>

import (
    "context"
    "net"
    
    "forward/internal/connector"
    "forward/internal/metadata"
    "forward/internal/registry"
)

func init() {
    registry.ConnectorRegistry().Register("<protocol>", NewConnector)
}

type Connector struct {
    // 认证信息、加密配置等
    username string
    password string
    timeout  time.Duration
}

func NewConnector(opts ...connector.Option) connector.Connector {
    options := connector.Options{}
    for _, opt := range opts {
        opt(&options)
    }
    
    var user, pass string
    if options.Auth != nil {
        user = options.Auth.Username()
        pass, _ = options.Auth.Password()
    }
    
    return &Connector{
        username: user,
        password: pass,
        timeout:  options.Timeout,
    }
}

func (c *Connector) Init(md metadata.Metadata) error {
    return nil
}

// Connect 在已建立的连接上执行协议握手
func (c *Connector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
    // 1. 执行协议握手
    // 2. 发送目标地址
    // 3. 返回可用于双向传输的连接
    
    // 示例：设置超时
    if deadline := deadlineFromContext(ctx, c.timeout); !deadline.IsZero() {
        _ = conn.SetDeadline(deadline)
    }
    
    // 执行握手逻辑...
    
    // 清除超时
    _ = conn.SetDeadline(time.Time{})
    
    return conn, nil
}
```

#### 3. 参考现有实现

- **HTTP Connector**: `internal/connector/http/connector.go` - HTTP CONNECT 隧道
- **SOCKS5 Connector**: `internal/connector/socks5/connector.go` - 完整的 SOCKS5 实现（含 UDP）

---

### 场景三：添加新的 **入站协议** (如 Trojan Server, VMess Server)

> 入站协议需要实现 Handler，处理客户端请求

#### 1. 创建目录结构

```bash
mkdir -p internal/handler/<protocol-name>
```

#### 2. 实现 Handler 接口

创建 `internal/handler/<protocol-name>/handler.go`：

```go
package <protocol_name>

import (
    "context"
    "net"
    
    "forward/base/logging"
    "forward/internal/chain"
    "forward/internal/handler"
    "forward/internal/metadata"
    "forward/internal/registry"
    "forward/internal/router"
)

func init() {
    registry.HandlerRegistry().Register("<protocol>", NewHandler)
}

type Handler struct {
    options handler.Options
    // 协议特定配置
}

func NewHandler(opts ...handler.Option) handler.Handler {
    options := handler.Options{}
    for _, opt := range opts {
        opt(&options)
    }
    
    h := &Handler{
        options: options,
    }
    
    // 设置默认路由器
    if h.options.Router == nil {
        h.options.Router = router.NewStatic(chain.NewRoute())
    }
    
    return h
}

func (h *Handler) Init(md metadata.Metadata) error {
    return nil
}

func (h *Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
    defer conn.Close()
    
    // 1. 读取并解析客户端请求
    // 2. 提取目标地址
    // 3. 通过 Router 获取转发路由
    // 4. 建立上游连接并进行双向转发
    
    // 示例流程：
    target := "解析得到的目标地址"
    
    route, err := h.options.Router.Route(ctx, "tcp", target)
    if err != nil {
        return err
    }
    if route == nil {
        route = chain.NewRoute()
    }
    
    upstream, err := route.Dial(ctx, "tcp", target)
    if err != nil {
        return err
    }
    defer upstream.Close()
    
    // 双向转发
    // inet.Bidirectional(ctx, conn, upstream)
    
    return nil
}
```

#### 3. 参考现有实现

- **HTTP Handler**: `internal/handler/http/handler.go` - HTTP 代理服务器
- **SOCKS5 Handler**: `internal/handler/socks5/handler.go` - SOCKS5 服务器（含 UDP）

---

## 核心组件说明

### Registry 注册中心

`internal/registry/registry.go` 提供四种注册表：

```go
// 获取注册表
registry.ListenerRegistry()   // Listener 注册表
registry.HandlerRegistry()    // Handler 注册表  
registry.DialerRegistry()     // Dialer 注册表
registry.ConnectorRegistry()  // Connector 注册表

// 注册新协议
registry.DialerRegistry().Register("myprotocol", NewDialer)

// 获取已注册的协议
factory := registry.DialerRegistry().Get("myprotocol")
dialer := factory(opts...)
```

### Option 模式

每个组件都有对应的 Option 类型：

```go
// internal/dialer/option.go
type Options struct {
    Timeout   time.Duration
    TLSConfig *tls.Config
    Logger    *logging.Logger
}

type Option func(*Options)

func TimeoutOption(t time.Duration) Option {
    return func(o *Options) { o.Timeout = t }
}

// 使用示例
d := NewDialer(
    dialer.TimeoutOption(10*time.Second),
    dialer.TLSConfigOption(tlsCfg),
)
```

### Router 路由

Handler 通过 Router 决定如何转发流量：

```go
// 获取转发路由
route, err := h.options.Router.Route(ctx, "tcp", "example.com:443")

// 通过路由建立连接
upstream, err := route.Dial(ctx, "tcp", "example.com:443")
```

### Chain 代理链

代理链由多个 Node 组成，每个 Node 包含 Dialer + Connector：

```go
// internal/chain/
chain.NewRoute()           // 创建空路由（直连）
chain.NewRoute(nodes...)   // 创建带节点的路由
route.Dial(ctx, network, addr)  // 通过代理链拨号
```

---

## 关键文件索引

| 文件                              | 用途                  |
| --------------------------------- | --------------------- |
| `internal/registry/registry.go`   | 协议注册中心          |
| `internal/dialer/dialer.go`       | Dialer 接口定义       |
| `internal/dialer/option.go`       | Dialer Option 定义    |
| `internal/connector/connector.go` | Connector 接口定义    |
| `internal/connector/option.go`    | Connector Option 定义 |
| `internal/handler/handler.go`     | Handler 接口定义      |
| `internal/handler/option.go`      | Handler Option 定义   |
| `internal/listener/listener.go`   | Listener 接口定义     |
| `internal/chain/route.go`         | 路由和代理链实现      |
| `design.md`                       | 项目整体设计文档      |

---

## 验证清单

添加新协议后，确保：

- [ ] 在 `init()` 中正确注册到对应的 Registry
- [ ] 实现所有接口方法（`Init`, `Dial`/`Connect`/`Handle`）
- [ ] 使用 Option 模式接收配置
- [ ] 正确处理超时（从 context 或 Options 中获取）
- [ ] 错误时清理资源（使用 defer）
- [ ] 添加必要的日志记录
- [ ] 编写单元测试

---

## 示例命令

```bash
# 验证编译
go build ./...

# 运行测试
go test ./internal/dialer/... -v
go test ./internal/connector/... -v
go test ./internal/handler/... -v
go test ./internal/listener/... -v

# 使用新协议
forward -L <new-protocol>://:8080
forward -L http://:8080 -F <new-protocol>://server:port -F <new-protocol>://server:port
forward -L socks5://:8080 -F <new-protocol>://server:port -F <new-protocol>://server:port
```
