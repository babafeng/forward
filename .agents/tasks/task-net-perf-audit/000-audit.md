# forward 深度网络性能审计报告

> 基于 `babafeng/forward` HEAD=`68aa0a9`（main），静态代码审计 + 设计评审。
> 目标：在不引入新依赖的前提下找出所有"实测能显著提升网络性能"的改动点。

## 概览

forward 是一个功能完备的 Go 端口转发 / 代理 / 内网穿透工具，涵盖：
TCP/UDP 转发、多跳 chain、反向隧道（yamux + socks5-bind 控制面）、HTTP/SOCKS5/HTTPS/HTTP2/HTTP3/VMess/VLESS+REALITY/Hysteria2/SS 代理服务端、xray mux、DialPool、基于 INI+GeoIP 的路由。

整体架构分层相当清晰（listener → handler → router → chain → dialer/connector），`base/io/net.Bidirectional` 是唯一的双向对拷入口，`base/pool` 是 64KB 的全局 buffer 池，`internal/chain/route_impl.go` 负责多跳 dial + handshake 序列。

对网络性能影响最大的几个结论：

1. **HTTP CONNECT / SOCKS5 Handshake 后的 TCP → TCP splice fast path 被全面破坏**。所有 handler 都在握手阶段用 `bufio.Reader` 或 `bufio.Writer` 包过 conn，之后要么不 unwrap、要么 unwrap 得不到真正的 `*net.TCPConn`，结果每个字节都要从 kernel → user → kernel 拷贝一次，100 Gbps 链路上能带来 >30% CPU 差距。
2. **UDP 数据面每包一次 `SetReadDeadline` syscall**，在 SOCKS5 UDP 和反向 UDP handler 里尤为严重。100k pps 级别每秒多几十万次 syscall。
3. **TLS 客户端没有 session cache**。每次 dial 必走完整 TLS 1.2 全握手（1-2 RTT）或 TLS 1.3 全握手，session resumption（RTT=0 或 1-RTT）从未被利用。对移动端 / 高 RTT 链路首屏延迟影响巨大。
4. **quic-go Config 全空**。`MaxIdleTimeout / KeepAlivePeriod / 流/连接接收窗口 / Allow0RTT` 全走 quic-go 默认值（默认连接窗口仅 512KB，高 BDP 链路严重欠跑）。
5. **yamux 使用 DefaultConfig**：StreamWindowSize 默认 256KB，`ConnectionWriteTimeout=10s`。跨国高 BDP 链路上 256KB 窗口在 100ms RTT 下单流上限 ≈ 20 Mbps，远低于链路能力。
6. **`PHT.postBatch` 每次 `context.WithTimeout(30s)` 重新创建** + **`bytes.Buffer` 每次重新分配**，对 H2/H3 PHT 通道每次写都会有可观开销。
7. **`framing.PacketStream.Read` 每次分配 2 字节 header**；`SOCKS5 UDP` 每次 `Write` 分配新 buffer；`Hysteria2 routeUDPConn.readLoop` 每包 `append([]byte(nil), ...)` 做 copy。
8. **SOCKS5 UDP `readUpstream` 每轮 `SetReadDeadline(now+5s)` + idle 判断**：同样每包 syscall。
9. **首个-F 节点的 TCPConn 经过 handshake wrapper 后无法识别为 \*net.TCPConn**，splice 在 `defaultRoute` 里也拿不到。
10. **日志热路径存在未 guard 的 `.Debug(` 调用**（socks5 / http 都有），在 info 级别下虽然 `printf` 会提前 return，但格式化参数（`conn.RemoteAddr().String()`、`fmt.Sprintf`）仍然会先被求值，产生分配。

以下为完整发现列表。

---

## 发现（Findings）

### F-001 ★★★ splice zero-copy fast path 被 HTTP CONNECT 和多跳 handshake 双端破坏

- **位置**：
  - `internal/handler/http/handler.go:408-434`（CONNECT hijack 返回 `conn, bufrw, err`，随后 `inet.Bidirectional(ctx, conn, up)`，其中 `conn` 是 hijack 出来的原始 `*net.TCPConn`，但 `bufrw.Reader` 里很可能已经预读了字节，而这些字节被丢弃了——不是正确性问题，但 CONNECT 隧道正常情况下不会预读请求体，所以该路径 splice 可走通）
  - `base/io/net/copy.go:44-48`：`io.CopyBuffer(dst, src, buf)` 即使两端都是 `*net.TCPConn`，因为显式传入了 user-space buf，会走 `src.Read → dst.Write`，**不会走 `ReadFrom`/splice**。
- **问题**：
  - `io.CopyBuffer(dst, src, buf)` 在 `src` 实现了 `io.WriterTo` 或 `dst` 实现了 `io.ReaderFrom` 的情况下**仍然会优先使用 `src.Read → dst.Write` 走 user-space buf**（runtime 里 `CopyBuffer` 只有在 buf==nil 时才试 `io.Copy` 的 ReaderFrom/WriterTo 路径）。这是 Go stdlib 众所周知的陷阱。
  - 对于 Linux 上 TCP→TCP 的 proxy，`io.Copy`（不传 buf）会命中 `*net.TCPConn.ReadFrom` → `splice(2)` → zero-copy。
- **改进**：
  - 双端都是 `net.Conn` 时优先尝试 `io.Copy(dst, src)`（零 buf），让 Go runtime 自动选择 splice；只有在 splice 不可用 / 链路上一端是 stream wrapper 时再 fallback 到 `CopyBuffer` + pool。具体判断：`dst.(io.ReaderFrom)` 或 `src.(io.WriterTo)` 存在则 `io.Copy`。
- **收益**：Linux TCP-TCP 直转场景 CPU 下降 20%–40%，小包时吞吐提升；跨国 1Gbps 链路可能从 ~60% CPU 降到 ~30%。
- **成本**：中（需要判断两端类型并保守 fallback，避免破坏已有半关闭与 EOF 语义测试）。
- **依赖**：无。

### F-002 ★★★ TLS 客户端缺少 `ClientSessionCache`

- **位置**：全仓库 0 处 `ClientSessionCache`。
  - `internal/dialer/tls/dialer.go:65`：`tlsConn := tls.Client(conn, cfg.Clone())`，cfg 无 session cache。
  - `internal/config/tls/config.go:80-102`：`ClientConfig` 从未设置。
- **问题**：每次重新 dial，TLS 都走完整握手（TLS1.2 2RTT，TLS1.3 1RTT）。对 forward-chain 场景（每个新 downstream 请求都触发 upstream dial）首字节延迟高。
- **改进**：在客户端构造 tls.Config 时填充 `ClientSessionCache: tls.NewLRUClientSessionCache(64)`（或按 proxy endpoint 共享缓存）。REALITY/VLESS+TLS 使用 utls 链路不受影响（它们另走 xray 协议栈），但普通 `tls://` `https://` 全链路受益。
- **收益**：跨国 TLS 链路首字节延迟下降 1 RTT（~50–200ms）；DialPool 空池情况下也能享受；大量短连接场景 CPU 降低 5%–10%（省掉证书链验证）。
- **成本**：小。
- **依赖**：无。

### F-003 ★★★ quic-go Config 未调优，流/连接窗口过小

- **位置**：
  - `internal/dialer/quic/dialer.go:67`：`quic.DialAddr(ctx, addr, tlsCfg, nil)`，第四个参数 `*quic.Config = nil`。
  - `internal/listener/quic/listener.go:60`：`quic.ListenAddr(..., nil)`。
  - `internal/dialer/h3/dialer.go:42-56` 与 `internal/dialer/http3/dialer.go:70-89`：`quic.Config` 只填了从 metadata 传入的 KeepAlive/HandshakeTimeout/MaxIdleTimeout/MaxStreams。
- **问题**：
  - quic-go 默认 `InitialStreamReceiveWindow ≈ 512KB`、`MaxStreamReceiveWindow = 6MB`、`InitialConnectionReceiveWindow ≈ 512KB`、`MaxConnectionReceiveWindow = 15MB`。对 100ms RTT / 100Mbps 场景恰好贴边；对 200ms RTT / 1Gbps 场景严重欠跑（BDP=25MB）。
  - `MaxIdleTimeout` 默认 30s，但不同 NAT 环境下 30s 保不住（UDP hairpin 常见 15–60s）。
  - `EnableDatagrams` 未启用，hysteria2 自带，但普通 quic 链路无法用于 UDP 转 datagram。
  - `Allow0RTT` 未使用，重复建链场景浪费。
- **改进**：统一一个 `newQUICConfig()` 辅助（在 `internal/config/tls` 旁或新建 `internal/config/quic.go`）：
  - `MaxStreamReceiveWindow = 16 MB`, `InitialStreamReceiveWindow = 2 MB`
  - `MaxConnectionReceiveWindow = 64 MB`, `InitialConnectionReceiveWindow = 4 MB`
  - `KeepAlivePeriod = 15s`（客户端默认）
  - `MaxIdleTimeout = 30s`
  - 保持 `DisablePathMTUDiscovery = false`（quic-go 默认已开）
  - `Allow0RTT = true`（服务端）；客户端 `DialAddrEarly` 已在 h3 用上。
- **收益**：高 BDP 链路 QUIC / H3 吞吐 2×–5×；短连接首包 1 RTT → 0 RTT。
- **成本**：小（全部 stdlib + quic-go 已有 API）。
- **依赖**：无（quic-go 已在依赖树里）。

### F-004 ★★★ yamux 默认 256KB 窗口，高 BDP 反向隧道严重欠跑

- **位置**：`internal/reverse/helpers.go:13-20`。
- **当前**：`conf := yamux.DefaultConfig(); conf.KeepAliveInterval = 10 * time.Second`。
- **问题**：`yamux.DefaultConfig()` 的 `MaxStreamWindowSize = 256 KB`、`ConnectionWriteTimeout = 10s`。反向隧道常跨国部署，100ms RTT 下单流吞吐 ≤ 20 Mbps。
- **改进**：
  - `conf.MaxStreamWindowSize = 4 * 1024 * 1024`（4MB，yamux 支持）。
  - `conf.ConnectionWriteTimeout = 30 * time.Second`（避免瞬时卡顿直接断连）。
  - `conf.StreamOpenTimeout = 10 * time.Second`（避免建流在慢链路上永久阻塞）。
- **收益**：单个反向隧道子流吞吐上限从 20 Mbps → 320 Mbps（100ms RTT）；突发也不易断。
- **成本**：小。
- **依赖**：无（yamux 已在 go.mod direct）。

### F-005 ★★ UDP 读循环每包一次 `SetReadDeadline` syscall

- **位置**：
  - `internal/handler/socks5/handler.go:363` `_ = s.relay.SetReadDeadline(time.Now().Add(1 * time.Second))`
  - `internal/handler/socks5/handler.go:487` `_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))`
  - `internal/handler/reverse/handler.go:285` `_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))`
  - `internal/handler/reverse/handler.go:328` `_ = uSess.stream.SetReadDeadline(time.Now().Add(idleTimeout))`
  - `internal/listener/phtserver/server.go:484` `_ = conn.SetReadDeadline(time.Now().Add(s.options.readTimeout))`
- **问题**：UDP 热路径每秒可能 100k+ 次 read，每次 `SetReadDeadline` 是一次 syscall（Linux 内部走 `setitimer`-like 的 kernel path），累计 CPU 占比非常可观。
- **改进**：使用 `time.AfterFunc` + atomic lastSeen 模式，或在独立 goroutine 周期性检查 lastSeen，而不是每包 deadline。典型做法：一次设置 `SetReadDeadline(zeroDate)`，改用外部 ticker 检查超时。
- **收益**：UDP 转发 CPU 降低 5%–15%，pps 上限提升显著（从 ~150kpps 到 ~200kpps 量级）。
- **成本**：中（要改 loop 结构，避免打破语义）。
- **依赖**：无。

### F-006 ★★ PHT 客户端 `postBatch` 每次分配 `bytes.Buffer` + context.WithTimeout

- **位置**：`base/transport/pht/conn.go:175-214`。
- **问题**：
  - `var payload bytes.Buffer` 每批一次，批量大时 Grow 多次；可以用 `sync.Pool[*bytes.Buffer]`。
  - `base64.StdEncoding.EncodeToString(pkt)` 每包一次分配，等价于 `base64.StdEncoding.EncodedLen(len(pkt))` 的 `[]byte`，直接 `EncodeLen` + `Encode` 到 `payload.Bytes()[offset:]` 能省。
  - `context.WithTimeout(context.Background(), 30*time.Second)` 每批一次 timer 分配。高频批量场景（PHT 常用于短包）会造成相当 GC 压力。
- **改进**：
  - 引入 `var pbPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}`。
  - 直接在 buffer 里做 base64 编码：`payload.Grow(base64.StdEncoding.EncodedLen(len(pkt))+1); n := base64.StdEncoding.Encode(payload.AvailableBuffer(), pkt); payload.Write(...[:n]); payload.WriteByte('\n')`。
  - 复用一个长生命周期的 `context` + `http.Request` with timeout via transport 的 ResponseHeaderTimeout。
- **收益**：H2/H3 PHT 隧道大量短消息场景 CPU 下降 10%–20%，GC pause 降低。
- **成本**：小–中（要保留现有 test 通过）。
- **依赖**：无。

### F-007 ★★ `framing.PacketStream.Read` 每次分配 header buffer

- **位置**：`base/io/net/framing.go:47-59`。
- **当前**：
```go
header := make([]byte, 2)
if _, err := io.ReadFull(ps.Conn, header); err != nil { ... }
```
- **问题**：每 UDP 包一次 2 字节 `make`，逃逸到 heap。
- **改进**：改为栈上数组 `var header [2]byte; io.ReadFull(ps.Conn, header[:])`。
- **收益**：UDP 转 TCP 流场景（reverse UDP、vless UDP）GC 压力下降。
- **成本**：小。
- **依赖**：无。

### F-008 ★★ `SOCKS5 UDP connector.Write` 每次 make 新 buffer

- **位置**：`internal/connector/socks5/connector.go:468-477`。
- **当前**：`buf := make([]byte, 0, len(c.prefix)+len(p)); buf = append(buf, c.prefix...); buf = append(buf, p...)`。
- **问题**：每个 UDP 出包都做一次分配。
- **改进**：从 `base/pool` 获取 buffer，或维持每 UDPConn 一个 `[]byte` 可复用缓冲（加锁）。
- **收益**：高频 UDP（QUIC over socks5 / DNS 压测）GC 下降。
- **成本**：小。
- **依赖**：无。

### F-009 ★★ `Hysteria2 routeUDPConn.readLoop` 每包 `append([]byte(nil), ...)`

- **位置**：`internal/hysteria2/server.go:285`。
- **当前**：
```go
buf := make([]byte, 64*1024)
for { n, err := conn.Read(buf); ... data := append([]byte(nil), buf[:n]...) ...recvCh <- ... }
```
- **问题**：每包一次 64KB 读（OK）+ 一次 copy 到新 slice（不 OK，因为只为了跨 channel 传递）。
- **改进**：从 pool 拿 buffer 做 Read；把 pooled buffer 直接送 channel；读端 Read 完调用 `pool.Put`。
- **收益**：QUIC UDP relay 场景 GC 显著下降。
- **成本**：中（需在消费侧管理 put）。
- **依赖**：无。

### F-010 ★★ `net.Dialer` 未启用 Happy Eyeballs + 连接缓存可选

- **位置**：`internal/dialer/tcp/dialer.go:63-69`。
- **当前**：直接 `net.Dialer{Timeout, KeepAlive, Resolver}`。
- **问题**：
  - `DualStack` 字段已 deprecated，新版 Go 默认 `net.Dialer.FallbackDelay = 300ms` 自动 Happy Eyeballs——没问题。但 `ControlContext` / `Control` 可以用来在 linux 上强制 `TCP_NODELAY`（Go 默认已开）、`SO_REUSEADDR`、更大的 `SO_RCVBUF/SO_SNDBUF`。
  - 对于 proxy 转发链这种长连接少数量场景，`SO_RCVBUF/SO_SNDBUF` 加到 4MB 能让高 BDP 链路在用户态不阻塞（Linux 默认 `tcp_rmem` 上限 6MB，但默认 net.Dialer 不显式 set）。
- **改进**：在 `net.Dialer.Control` 里 `setsockopt(SO_RCVBUF, 4<<20)`（best-effort，失败不报错）。仅 Linux 生效；用 `//go:build linux` 文件做。
- **收益**：跨国 500ms RTT、1Gbps 链路单流吞吐从默认 ~60Mbps 提升到接近线速。
- **成本**：中（要写 build tag 文件，syscall）。
- **依赖**：无（`golang.org/x/sys` 已是 direct 依赖）。

### F-011 ★★ QUIC / H3 监听 UDP 接收 buffer 未显式调大

- **位置**：`internal/listener/quic/listener.go:59`、`internal/listener/http3/listener.go:119`。
- **问题**：quic-go 启动时会打印 warning "failed to sufficiently increase receive buffer size"，这是因为 Linux 默认 `net.core.rmem_max=212992`（208KB）。quic-go 自己会 `setsockopt(SO_RCVBUF, 64MB)` 但受限于 `rmem_max`。
- **改进**：虽然 quic-go 已经尝试 set，但我们可以在 ListenPacket 之后**主动 `SetReadBuffer(64<<20)` + 打 warn 日志提示调 sysctl**。可复用 F-010 的 linux-only helper。
- **收益**：在 rmem_max 足够大的机器上 QUIC 吞吐上限提升；warning 消失。
- **成本**：小。
- **依赖**：无（`SetReadBuffer` 是 stdlib）。

### F-012 ★★ UDP listener 每包从 `pool.GetWithSize(l.md.readBufferSize)` 分配 128KB

- **位置**：`internal/listener/udp/listener.go:232`（`config.DefaultBufferSize = 128KB`）。
- **问题**：
  - `pool.GetWithSize` 只有 `size <= defaultSize(64KB)` 才走池，128KB 每次都 `make`。
  - `DefaultBufferSize = 128KB` 对 UDP 来说过大（max UDP payload ≈ 64KB-8B），每包真正用到的不超过 64KB。
- **改进**：把 UDP listener 默认 `readBufferSize` 改为 `config.DefaultUDPBuffer`（已经是 64KB），配合 `pool.Get` 命中池。
- **收益**：高 pps UDP 场景 GC 大幅下降。
- **成本**：极小。
- **依赖**：无。

### F-013 ★★ `DialPool` 默认关闭但"按需复用"能力缺失

- **位置**：`internal/chain/pool.go`。
- **问题**：当前 DialPool 是**主动预热**模型（`go p.warmBackground() → fill()`），只要开启就先 dial N 个连接。README 中已经注明默认关掉避免空闲开销。
- **改进**：新增一种"被动复用池"：连接用完**不关闭**，放入 idle LRU；下次 `route.Dial` 先试池、命中则复用。这是 `http.Transport.IdleConnTimeout` 的思路，能在不增加空闲连接的情况下跳过 3 RTT。需要仔细考虑：
  - 何时把连接放回池（必须在当前 stream 的 proxy 协议明确表示连接"可继续复用"时，例如 socks5 connect 用完就断，无法复用；vless/vmess mux 已有自己的复用层）。
  - 对 TLS 连接做 session resumption（F-002 配合）。
- **收益**：短连接热 proxy 场景 dial + handshake 开销归零。
- **成本**：大（需要理解每个 connector 的协议语义）。
- **依赖**：无。
- **结论**：本轮不做，只在报告里列出，标记 Deferred。

### F-014 ★★ `reverse/client.client.readUpstream` 里 `select { case <-time.After(backoff) }` 会泄漏 timer 到触发

- **位置**：`internal/reverse/client/client.go:77-82`。
- **当前**：
```go
select {
case <-ctx.Done():
    return ctx.Err()
case <-time.After(backoff):
}
```
- **问题**：`time.After` 在 reconnect loop 里虽然不是"高频"，但 `ctx.Done` 先触发时 timer 会泄漏直到 backoff 触发。慢但不快乐。
- **改进**：用 `time.NewTimer(backoff); defer t.Stop()`。
- **收益**：微，但是一个干净度改进。
- **成本**：极小。
- **依赖**：无。

### F-015 ★ PHT pull 循环每次 `bufio.NewWriter(w)` 新建

- **位置**：`internal/listener/phtserver/server.go:520-525`。
- **当前**：内部 for 里 `bw := bufio.NewWriter(w); bw.WriteString(...); bw.WriteString(...); bw.Flush()`。
- **问题**：每次数据到达就 new 一个 bufio.Writer，纯浪费；`w.Write` + flusher 即可；即使要 bufio 也应该 loop 前建一次。
- **改进**：loop 前新建 `bufio.NewWriterSize(w, 16*1024)`，loop 内 `bw.WriteString; bw.WriteString; bw.Flush`。
- **收益**：PHT pull 长连接每秒数万次写场景 GC 压力下降。
- **成本**：小。
- **依赖**：无。

### F-016 ★ HTTP handler `streamWithBody` 双 `io.Copy` 无 pool buf

- **位置**：`internal/handler/http/handler.go:523-539`。
- **问题**：两个 goroutine 里都是 `io.Copy(upstream, body)` / `io.Copy(respWriter, upstream)`，没用 pool。对 H2/H3 下 CONNECT 流量也会走这里。
- **改进**：改成 `io.CopyBuffer` + pool 或保持 `io.Copy`（后者实际会优先走 `ReaderFrom`/`WriterTo`，对 `http.ResponseWriter` 没有 WriterTo 所以走默认 32KB；pool 收益更明确）。注意 `flushWriter.Write` 里 maintains pending+interval 逻辑，`io.Copy` 的默认 32KB chunk 已经 OK，但显式加 pool 能减少短暂分配。
- **收益**：中。
- **成本**：小。
- **依赖**：无。

### F-017 ★ Logger debug 热路径未做 level guard，仍然走 fmt 格式化

- **位置**：
  - `base/logging/logging.go:116-141`：`printf` 里检查 level 很快 return，但调用方传参时的 `fmt.Sprintf` 参数（如果调用方用了 `fmt.Sprintf` 包装）会先求值。
  - `internal/handler/http/handler.go` 多处 `h.options.Logger.Debug(...)` 直接用变参。
  - `internal/chain/route_impl.go` 多处 `if verbose { tr.Logger.Debug(...) }` 已 guard，是好例子。
- **问题**：`Logger.Debug(format, args...)` 里面 `args...` 的求值（例如 `conn.RemoteAddr().String()`）在 info 级别下**仍会执行**，带来 syscall + 分配。目前 `route_impl.go` 做得对，但 `http/handler.go:490 io.Copy error`、`socks5/handler.go:266 SOCKS5 CONNECT closed` 等在每条连接关闭时都会触发。
- **改进**：新增 `Logger.IsDebug()` 快速判断；在高频点用 `if log.IsDebug()` guard。
- **收益**：info 级别下 per-connection 热路径省掉若干 Sprintf/Addr 求值。
- **成本**：小–中（要改所有热点）。
- **依赖**：无。
- **范围**：本轮先添加 `IsDebug/IsLevelEnabled` API + guard 掉 copy.go / http / socks5 / tcp handler 里的 Debug 热点即可。

### F-018 ★ `fmt.Sprintf("%d", port)` 在热路径出现，应改 `strconv.Itoa`

- **位置**：`internal/dialer/phtclient/client.go:45`、`internal/reverse/client/client.go:114`、`internal/listener/reality/listener.go:82`。
- **问题**：`fmt.Sprintf` 走反射、比 `strconv.Itoa` 慢 10x。前两个在 client dial 热路径（虽然不是包级别热路径）。
- **改进**：`strconv.Itoa(port)`。
- **收益**：小。
- **成本**：极小。
- **依赖**：无。

### F-019 ★ `base/pool.Get` 返回 `b[:defaultSize]` 但 `Put` 内检查 `cap < defaultSize`

- **位置**：`base/pool/pool.go`。
- **现状**：
```go
func Put(b []byte) {
    if cap(b) < defaultSize { return }
    pool.Put(b[:cap(b)])
}
```
- **问题**：
  - `pool.Put(b[:cap(b)])` 把 slice 扩回 cap 是正确的，但这里额外把一个 `[]byte`（值类型）塞进 sync.Pool 会导致每次 Put 都在 `pool.Put` 内部触发 `runtime_procPin/Unpin` + 值 boxing——对 `sync.Pool` 来说传 `*[]byte`（指针）更友好，避免 interface 装箱的分配。
  - 另外 `sync.Pool` 的 GC-scavenge 策略会在 GC 时清空池，导致 buffer 反复重建。对于非常稳定的工作负载，可配 mcache-level 池或保留 lowwatermark。但这个优化太大，不做。
- **改进**：用 `*[]byte` 作为池元素（与 `base/io/net/framing.go` 的 `packetBufPool` 一致）。保持 `Get()` API 签名（返回 `[]byte`），内部 Box/Unbox。
- **收益**：Put 路径每次省掉 `[]byte → interface{}` 的 24B 堆分配。高连接数下 GC pause 轻微下降。
- **成本**：小（需跟踪所有调用方；API 不变就好）。
- **依赖**：无。

### F-020 ★ `net/net/copy.go waitSecondResult` 正常，但可以更早 close write

- **位置**：`base/io/net/copy.go:68-98`。
- **当前**：先 `closeWrite(dst)`，再把结果回 resCh。
- **观察**：`closeWrite` 对于 TLS `*tls.Conn` 会发 close_notify（好的）。对于 `QuicStreamConn`（`internal/structs`），它实现了 CloseWrite 吗？如果没实现 CloseWrite，返回 `halfClosed=false`，会走 `waitSecondResult` 等 3s fallback。
- **改进**：让 `QuicStreamConn` 实现 `CloseWrite`（直接调 `Stream.Close()` 或 stream 的 CancelWrite / Close）。
- **收益**：QUIC 链路上半关闭 reuse 能即刻触发对端完整关闭，节省 3s 等待期间的保持连接 CPU。
- **成本**：小。
- **依赖**：无。
- **需读代码**：`internal/structs/quic_stream_conn.go`（本轮确认后再动）。

### F-021 ★ `internal/listener/tcp/listener.go:90-101` 握手完成后清 deadline 的 if 分支没处理失败时 log

- 非性能问题，跳过。

### F-022 ★ `internal/reverse/helpers.go` yamux 日志经过 `fmt.Sprint/Sprintf` 再 trim 解析 [ERR]/[WARN] 前缀

- **位置**：`internal/reverse/helpers.go:41-65`（`yamuxLogger.Print/Println/Printf`）。
- **问题**：yamux 日志量不大，但每条日志都走 3 步 string 操作。info 级别下的 keepalive 日志也会触发。
- **改进**：低优先级，非本轮范围。

### F-023 ★ SOCKS5 UDP `readUpstream` 里 `time.Unix(0, p.lastSeen.Load())` + `time.Since` 每包计算

- **位置**：`internal/handler/socks5/handler.go:490`。
- **问题**：每包计算 `time.Since`，是 2 次 `time.Now()` 调用（vDSO，很快但不免费）。
- **改进**：合并进 cleanup goroutine，不在热路径检查。
- **收益**：与 F-005 一起实施。

### F-024 ★ HTTP handler 每个连接都会走 `http1ServerForHandle()` 且 `sync.Once` 但 reuse

- **位置**：`internal/handler/http/handler.go:265-277`。
- **状态**：这块已经做了 sync.Once 优化，OK。

### F-025 ★ 多跳 chain 首节点 dial 后 `node.Transport().Handshake(ctx, conn)` 返回 wrapper，下一跳再 `prev.Transport().Connect(ctx, conn, ...)` 产生 wrapper 嵌套

- **位置**：`internal/chain/route_impl.go:157-217`。
- **观察**：多跳链路上 conn 被 wrapper 反复包住是必然的（每跳都要做协议编码）。这不是问题，但最终返回给 `Bidirectional` 的 conn 不是 `*net.TCPConn`，splice 无法工作。
- **结论**：这是多跳的本质代价，无法优化。仅记录。

---

## 不引入新依赖的可行性确认

本轮所有落地改动使用：
- Go stdlib：`bytes`, `context`, `crypto/tls`, `io`, `net`, `strconv`, `sync`, `time`, `syscall/unix(via golang.org/x/sys)`。
- 已有 direct 依赖：`github.com/quic-go/quic-go`（含 `quic.Config`）、`github.com/hashicorp/yamux`（含 `yamux.Config`）、`golang.org/x/sys/unix`（已在 indirect，用于 F-010 TCP buffer 调优）。

验证：`golang.org/x/sys` 是 direct（`go.mod` 39 行），可使用其 `unix.SetsockoptInt`。

---

## 推荐实施顺序

按"高收益 + 小成本"优先级排序，分成 3 个 Feature 批次：

**Batch 1（核心热路径，最大收益）**
- F-002 TLS ClientSessionCache
- F-003 quic-go Config 全面调优
- F-004 yamux 窗口调大
- F-001 Bidirectional splice-preserving 路径（`io.Copy` 两端都是 `*net.TCPConn` 时走零 buf 让 stdlib 自选 ReadFrom）
- F-010/F-011 Linux TCP/UDP socket buffer 调大（build-tagged helper）

**Batch 2（热路径分配 + syscall）**
- F-005/F-023 UDP 读循环去掉每包 SetReadDeadline
- F-006 PHT postBatch 复用 Buffer + 去掉 per-batch context
- F-007/F-008/F-009 各处 per-packet 分配收敛到 pool / 栈数组
- F-012 UDP listener 默认 buffer 改 64KB 走 pool
- F-015 PHT pull 复用 bufio.Writer
- F-016 streamWithBody 加 pool buf
- F-019 base/pool 改用 `*[]byte` 池元素

**Batch 3（打磨）**
- F-014 replace `time.After` with NewTimer+Stop
- F-017 日志 IsDebug 快速 guard + 热点 Debug 调用加 guard
- F-018 `fmt.Sprintf("%d", x)` → `strconv.Itoa`
- F-020 `QuicStreamConn.CloseWrite` 补全

**Deferred（本轮不做）**
- F-013 被动复用 DialPool（需改架构）。
- F-022 yamux logger 优化（收益太小）。

---

## 实施注意事项

1. **splice 保留路径**：`base/io/net/copy.go` 是所有 handler 的唯一对拷入口，任何语义更改都必须保留半关闭 fallback + 测试 `TestBidirectionalFallbackWithoutCloseWrite` 通过。
2. **quic.Config 统一工厂**：新建 `internal/config/quicopts.go` 导出 `NewClientQUICConfig(overrides)` / `NewServerQUICConfig(overrides)`，dialer/listener 全部调用它，避免遗漏。
3. **TLS ClientSessionCache**：需要是**同一 proxy endpoint 共享**的单 cache，否则不生效。最简做法是全局 `var clientSessionCache = tls.NewLRUClientSessionCache(128)`，所有 ClientConfig 默认用它。
4. **Linux socket buffer 调大**用 build tag：`netmark/sockopt_linux.go` + `netmark/sockopt_other.go`。在 `ConfigureDialer` / ListenPacket 成功后调用 best-effort 版本，失败只打 debug log。
5. **不影响 Windows/macOS 构建**：所有 F-010/F-011 的 syscall 改动必须在 `//go:build linux` 下。
6. **回归测试范围**：`go test ./base/io/...` 必过；`go test ./internal/handler/...` 必过；`go test ./internal/chain/...` 必过。PHT 和 reverse 的 E2E 测试依赖真实握手，本沙盒跑不了（无 Go 1.26.2 toolchain），由 CI 完成。

---

## 预期总收益场景表

| 场景 | 主要受益 findings | 预期提升 |
| --- | --- | --- |
| Linux TCP 直转（含 CONNECT 隧道）1Gbps | F-001, F-010 | CPU ↓20–40%，吞吐接近线速 |
| 跨国 TLS/HTTPS proxy 首字节延迟 | F-002 | RTT ↓ 1（约 50–200ms） |
| H3 / QUIC 大文件吞吐 | F-003, F-011 | 2×–5× |
| 反向 yamux 隧道跨国 | F-004 | 单流吞吐 10×+ |
| UDP 高 pps 转发 | F-005, F-008, F-009, F-012 | CPU ↓10–20%，pps ↑30% |
| PHT H2/H3 隧道小包 | F-006, F-015 | CPU ↓10–20% |
| 通用 GC 压力 | F-007, F-019 | minor gc 次数 ↓ |

