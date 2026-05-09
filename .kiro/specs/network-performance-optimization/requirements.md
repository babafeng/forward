# forward 网络性能优化 · Requirements

> 本规格基于对仓库主要网络路径（`base/io/net`、`base/pool`、`base/transport/pht`、`internal/chain`、`internal/dialer`、`internal/listener`、`internal/connector`、`internal/handler`、`internal/hysteria2`、`internal/netmark`、`internal/reverse`、`internal/xraymux`、`internal/subscribe` 等）的静态审阅得出。  
> 产出物为 Kiro Spec 三件套，用户审阅后再决定是否进入实施阶段。本轮**不修改**任何 `base/` 与 `internal/` 源码。

## 1. 背景与现状定位

`forward` 是一个用 Go 编写的轻量级网络转发/代理工具，功能面非常宽：TCP/UDP 端口转发、反向穿透、VMess/VLESS+REALITY/SS/Hysteria2/HTTP/SOCKS5 等入站协议、HTTP2/HTTP3/QUIC/PHT/DTLS/Reality 等传输通道、INI 规则路由、订阅与延迟探测。代码整体已有较好的分层（Listener → Service → Handler → Route → Dialer → Connector → `Bidirectional`），并沉淀了若干通用优化：

- `base/io/net/copy.go` 使用 `sync.Pool` 复用 64KB `CopyBuffer`，并做了半关闭与兜底超时；
- `base/pool/pool.go` 提供统一 64KB 池；
- `base/transport/pht/conn.go` 默认 `WriteBatchWait=0`（即时 drain）来降低首字节延迟；
- `internal/chain/pool.go` 提供可选的 DialPool 预热池（README 默认关闭）；
- `internal/chain/balancer.go` 对订阅节点做并发延迟探测与动态排序；
- `internal/connector/muxshared` 与 `internal/xraymux` 复用 Xray Mux；
- `internal/netmark` 提供 `SO_MARK` 自绕行标记以避免 TPROXY 回环。

然而，从网络性能的角度仍存在多处可量化改进点，涵盖 **IO 拷贝路径、TCP 传输层参数、TLS 握手、QUIC/H3 流控与批量 IO、Mux 行为、DialPool 策略、UDP 数据面、DNS/路由、日志与 GC、订阅热路径** 等层面。本 Spec 目标是把这些改进点沉淀为有据可查的设计与任务清单。

## 2. 优化目标（按优先级）

1. **降低交互式流量首字节延迟（TTFB）**  
   聚焦：TLS ClientHello 重用、QUIC 0-RTT（`DialAddrEarly` 已在 h3 用上但未全局）、PHT 首字节行为、Happy Eyeballs、DNS 缓存命中率、TCP_NODELAY。
2. **提升大流量吞吐（Throughput）**  
   聚焦：`io.Copy` 路径上的 `splice(2)` / `ReadFrom` 启用条件、QUIC 拥塞控制与 GSO、H2/H3 流控窗口、拷贝缓冲区大小与对齐。
3. **减少每连接/每包内存分配与 GC 压力**  
   聚焦：热路径 `make([]byte, ...)`、每次 `postBatch` 重新 `bytes.Buffer`、`hysteria2`/`quic` 每包 `append([]byte(nil), ...)`、`fmt.Sprintf` 在禁用日志级别仍被执行、`runtime.Caller` 在 debug 级别的开销。
4. **降低连接建立成本与并发抖动**  
   聚焦：DialPool 的填充策略（串行填充、无抖动）、`tls.Config` 缺少 `ClientSessionCache`、每次握手 `cfg.Clone()`、balancer 探测只做握手不做业务 RTT。
5. **提升 UDP 会话规模与拥塞行为**  
   聚焦：`ReadFrom` 单线程串行读取、UDP 批量收发（`recvmmsg/sendmmsg`）缺失、`rate_limit` map 每秒整表重建、session 轮询超时。
6. **反向穿透与 Mux 路径效率**  
   聚焦：yamux `MaxStreamWindowSize` 默认、Xray Mux `MaxConcurrency` 固定、PHT 读循环 base64 编解码与 `bufio.NewWriter` 每次分配。

## 3. 成功指标（Success Metrics）

以下指标作为验收参照，实际数字需在实施阶段的基准测试（go test -bench / 独立 perf harness）中测定，不在本 Spec 中预先承诺具体提升幅度：

- **TTFB**：对同一链路，单次 HTTP/1.1 CONNECT + 443 TLS 目标，在代理端部署优化前后的首字节时间；
- **稳态吞吐**：iperf3 或 `curl --limit-rate 0` 单流吞吐 Mbps；
- **短连接 QPS**：`wrk -c 200 -d 30s` 经过 forward 时每秒完成连接数；
- **CPU/allocation**：`go test -bench -benchmem` 在 `base/io/net` 与 PHT/QUIC 热路径的 `B/op` 与 `allocs/op`；
- **握手开销**：启用 session resumption 后 TLS full vs abbreviated 比例。

## 4. 不做的事（Out of Scope）

- 不引入新的第三方依赖（`go.mod` 保持现状；沙箱 `INTEGRATIONS_ONLY` 也不允许 `go mod download`）。除非显式说明，否则所有改动只使用标准库或现有依赖提供的 API。
- 不改变现有 URL scheme、查询参数语义和配置文件格式（`JSON`/`INI`）。新增的行为必须为 opt-in 或默认值保持向后兼容。
- 不重写协议实现（VMess/VLESS/Hysteria2 等），只在"使用方式"和"缓冲/拷贝路径"上优化。
- 不调整 `.github/workflows/release.yml` 构建矩阵、不新增 `Dockerfile`。
- 不修改 `xray-core` / `quic-go` / `hysteria2` 等上游行为；涉及 `quic.Config` 等可调参数只做封装。
- 不承诺具体性能提升百分比，除非实施阶段真实测得。

## 5. 兼容性与风险底线

- **配置不破坏**：新增字段在缺省情况下必须与现有行为一致，或者明确在 README/design.md 中说明新默认值。
- **安全底线**：TLS `MinVersion=TLS1.2`、REALITY 相关参数不放宽；`InsecureSkipVerify` 默认 false；session cache 只在 client 侧启用。
- **观测可回退**：每个可能影响行为的优化（批量 UDP、splice、Fast Open、0-RTT、session cache）需提供 opt-out 开关或可观测降级。
- **多平台兼容**：涉及 `syscall.SetsockoptInt` 的改动必须在 `*_linux.go` 与 `*_other.go` 之间正确拆分，保持 macOS/Windows 可编译。
- **TPROXY / netmark 回环**：任何新增 socket option 都要保证不与 `SO_MARK=0x80` 冲突、不破坏 `SelfBypassMark` 的 policy-routing 语义。
- **反向穿透**：Yamux 的 KeepAlive 间隔和窗口调整必须双端同步（`helpers.go` 是唯一入口，已集中维护）。

## 6. 成功完成的判定

- 本 Spec 的三份文档落盘到 `.kiro/specs/network-performance-optimization/`；
- 任务列表（`tasks.md`）中每个条目都可独立分配给 coder 实施，且清楚列出"涉及文件 / 体量 / 验证方式 / 依赖关系 / 风险"；
- design.md 中每项优化都能在仓库里精确定位到文件与函数；
- 规格内所有陈述均基于对当前代码的实际阅读，未引入虚构 API。
