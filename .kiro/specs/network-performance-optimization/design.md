# forward 网络性能优化 · Design

> 本文档配合同目录下的 `requirements.md` 使用。所有优化项仅做设计说明，不在本轮交付中实施；具体任务拆分见 `tasks.md`。
>
> 书写约定：涉及的文件路径、函数、类型名都用反引号包裹；收益按定性描述给出（吞吐 / 延迟 / 内存 / GC），不承诺具体百分比。

## 优化项索引表

| 编号 | 主题 | 涉及模块 | 影响度 | 实施成本 |
| ---- | ---- | -------- | ------ | -------- |
| 1 | `Bidirectional` 启用 splice 零拷贝 | `base/io/net` | 高 | 小 |
| 2 | TLS Client `ClientSessionCache` | `internal/config/tls`、`internal/dialer/{tls,h2,h3,http3,quic}` | 高 | 小 |
| 3 | QUIC/H3 窗口与 0-RTT 一致化 | `internal/dialer/{quic,h3,http3}`、`internal/listener/{quic,h3,http3}` | 高 | 中 |
| 4 | Hysteria2 UDP readLoop 池化 | `internal/hysteria2`、`internal/connector/hysteria2` | 中 | 中 |
| 5 | PHT `postBatch` 流式 base64 + 池化 | `base/transport/pht` | 中 | 中 |
| 6 | Yamux 窗口与超时配置化 | `internal/reverse` | 中 | 小 |
| 7 | DialPool 并发预热 + 抖动 | `internal/chain` | 中 | 小 |
| 8 | Balancer 可选 CONNECT+204 测速 | `internal/chain`、`internal/subscribe` | 低 | 中 |
| 9 | UDP 限流改令牌桶 | `internal/listener/udp` | 低 | 小 |
| 10 | 日志热路径 level gate 与前缀表 | `base/logging`、`internal/chain` | 低 | 小 |
| 11 | DNS / MMDB 缓存统一 | `base/route`、`base/mmdb`、`internal/chain`、`internal/dialer` | 中 | 中 |
| 12 | UDP `recvmmsg` / `sendmmsg` 可行性 | `internal/listener/udp` | 中（Linux）| 大 |

建议实施顺序：2 → 1 → 3 → 6 → 4 → 5 → 7 → 11 → 10 → 9 → 8 → 12。先落地风险较小、收益面广的"会话恢复"和"零拷贝"两项，再推进与上游/listener 对齐的窗口调整，最后处理 opt-in 较多、跨平台差异较大的探索性条目。

---

## 1. `Bidirectional` 拷贝路径启用 splice 零拷贝（TCP ↔ TCP）

### 现状（Current）

`base/io/net/copy.go` 的 `Bidirectional` 在 `pipe` 内部调用 `io.CopyBuffer(dst, src, buf)`，其中 `buf` 来自 64KB 的 `sync.Pool`。标准库 `io.copyBuffer` 的实现规则是：一旦显式传入 buffer，就不会再检测 `io.ReaderFrom` / `io.WriterTo` 快路径；Linux 上 `*net.TCPConn.ReadFrom` 本来可以触发 `splice(2)` 零拷贝，但在当前调用形态下永远走不进。

### 改动建议（Proposed Change）

在 `pipe` 内加一次类型识别：

- 如果 `dst` 实现 `io.ReaderFrom`，同时 `src` 是 `*net.TCPConn`（或实现 `syscall.Conn` 的裸 TCP 连接），则调用 `io.Copy(dst, src)` 让标准库自行选择 `splice`；
- 否则保留原有 `io.CopyBuffer(dst, src, buf)` + 池化缓冲的路径。

落点建议：在 `base/io/net/copy.go` 中新增一个内部辅助函数 `copyWithHint(dst, src)`，`pipe` 内根据两端类型决定分支。对于 VLESS / Reality / TLS 等被包裹后的连接，类型判断自然失败，会自动降级到带缓冲的路径，因此不会破坏任何加密协议。

### 预期收益（Expected Gain）

在 TCP 明文转发（`tcp://`、HTTP CONNECT、无 TLS 的反向穿透 payload 路径）上减少用户态和内核态之间的数据拷贝次数，预计提升稳态吞吐并降低 CPU 占用。对小报文或已加密流量无显著影响。

### 风险（Risks）

- 若下游包装连接不正确实现 `io.ReaderFrom`（例如吞字节、错误处理半关闭），`io.Copy` 路径可能与现有 `CopyBuffer` 语义不一致。
- 现有日志与统计逻辑基于 `io.CopyBuffer` 的单次返回值；切换到 `io.Copy` 后字节数与错误语义保持一致，但分支判断需要覆盖半关闭逻辑（现有 `closeWrite` 已处理）。
- 需要确保 `normalizeCopyError` 和 `waitSecondResult` 仍然被两条路径共享。

### 回退开关（Opt-out）

新增环境变量 `FORWARD_DISABLE_SPLICE=1`，在包初始化时读取并缓存；若设置，则永远走旧的 `CopyBuffer` 路径。默认不设置。

---

## 2. TLS Client `ClientSessionCache`（会话票据复用）

### 现状（Current）

`internal/config/tls/config.go` 的 `ClientConfig` 构造 `*tls.Config` 时只设置 `InsecureSkipVerify`、`NextProtos`、`ServerName`、`RootCAs`，没有设置 `ClientSessionCache`，也没有显式关闭 `SessionTicketsDisabled`（默认为 false，但缺少 cache 时票据依然无效）。

`internal/dialer/tls/dialer.go` 的 `Dialer.Handshake` 中每次 `cfg.Clone()` 后再 `tls.Client`，无状态的 `tls.Config.Clone` 会复制 cache 字段本身，但由于原始 cfg 从未注入 cache，克隆结果同样缺失，TLS 1.2 每次都走 full handshake，TLS 1.3 丢失 PSK resumption。

同类情况出现在：

- `internal/dialer/h2/dialer.go` 的 `DialTLSContext` 路径；
- `internal/dialer/h3/dialer.go`、`internal/dialer/http3/dialer.go` 构造 `tls.Config` 并交给 `http3.Transport`；
- `internal/dialer/quic/dialer.go` 的 `cloneTLSConfig` + `quic.DialAddr`。

Reality（`internal/dialer/reality/dialer.go`）走 xray 内部握手，不在本项范围内。

### 改动建议（Proposed Change）

1. 在 `internal/config/tls/config.go` 的 `ClientConfig` 中注入一个进程级共享的 `tls.ClientSessionCache`。建议以 `(ServerName, NextProtos 指纹)` 为维度的二级 map 维护多个 `tls.NewLRUClientSessionCache(128)` 实例，避免不同 SNI 跨指纹串扰。若实现复杂度过高，可先用单个容量 256 的 LRU 作为 MVP。
2. 在 `internal/dialer/tls/dialer.go` 的 `Handshake` 中调整复制策略：只有当需要覆写 `ServerName` 或 `NextProtos` 时才 `Clone`，其余路径直接复用 `d.tlsConfig`，避免多余的分配。
3. 给 QUIC 和 HTTP/3 侧同样挂载 cache：在 `internal/dialer/h3/dialer.go`、`internal/dialer/http3/dialer.go`、`internal/dialer/quic/dialer.go` 构造 `tls.Config` 的分支中，通过一个新的辅助函数（例如放在 `internal/dialer/transportutil` 中的 `EnsureClientSessionCache`）写入 `ClientSessionCache` 字段。QUIC 侧 `cloneTLSConfig` 的结果也需要经过同一路径，从而为后续 0-RTT 打下基础。
4. 新增 URL 查询参数 `tls_cache=false` 允许单跳禁用（经由 `endpoint.Endpoint.Query` 透传到 `ClientConfig`）。

### 预期收益（Expected Gain）

相同目的地反复建连（DialPool 填充、短连接代理场景、Balancer 重新探测）的 TLS 握手节省一个往返，长 RTT 链路体感提升明显。为后续 QUIC 0-RTT 铺路。

### 风险（Risks）

- 进程内共享 cache 需要避免不同 SNI 复用同一条目，否则可能造成指纹污染或握手失败；建议 key 使用 `ServerName + "\x00" + strings.Join(NextProtos, ",")`。
- 切换 SNI（例如通过订阅热更新）后，旧 cache 条目需要能被 GC；LRU 策略通常够用，必要时在 `UpdateCandidates` 路径上主动清理。
- 启用票据复用后，部分服务端的指纹检测可能观察到重复 PSK，属正常行为。

### 回退开关（Opt-out）

- URL 参数 `tls_cache=false` 单跳关闭；
- 环境变量 `FORWARD_DISABLE_TLS_CACHE=1` 全局关闭。
默认开启。

---

## 3. QUIC / H3 窗口与 0-RTT 行为一致化

### 现状（Current）

`internal/dialer/h3/dialer.go` 已经使用 `quic.DialAddrEarly`，可以在会话票据命中时走 0-RTT；但 `internal/dialer/quic/dialer.go` 的 `Dial` 仍然使用 `quic.DialAddr`，无法利用 0-RTT。两侧构造 `quic.Config` 时也只设置 `KeepAlivePeriod` / `HandshakeIdleTimeout` / `MaxIdleTimeout` / `MaxIncomingStreams`，未设置任何 receive window 与 MTU 相关字段。

listener 侧同样如此：`internal/listener/quic/listener.go` 完全传 `nil` 给 `quic.ListenAddr`；`internal/listener/h3/listener.go` 与 `internal/listener/http3/listener.go` 只设置时间类字段。quic-go 默认窗口 512KB，面向 BDP 较大的链路（跨境 / 高 RTT）会显著限速。

### 改动建议（Proposed Change）

1. 在 `internal/dialer/quic/dialer.go` 中把 `quic.DialAddr` 替换为 `quic.DialAddrEarly`，与 `h3` 保持一致。对应的 `tls.Config` 必须启用 `ClientSessionCache`（见第 2 项），否则 `DialAddrEarly` 退化为 1-RTT。
2. 抽一个公共构造函数，建议放在 `internal/dialer/transportutil` 中命名为 `BuildQUICConfig(md transportutil.TransportMetadata, opts ...Option)`，默认值：
   - `InitialStreamReceiveWindow = 2 MiB`
   - `InitialConnectionReceiveWindow = 4 MiB`
   - `MaxStreamReceiveWindow = 16 MiB`
   - `MaxConnectionReceiveWindow = 32 MiB`
   - `EnableDatagrams = false`
   - `DisablePathMTUDiscovery = false`
3. `internal/listener/h3/listener.go`、`internal/listener/http3/listener.go`、`internal/listener/quic/listener.go` 全部通过同一辅助函数构造 `quic.Config`，保持 dial/listen 两侧窗口对齐。`internal/listener/quic/listener.go` 需要额外把 `nil` 替换为构造结果。
4. 新增若干 URL 查询参数以便用户按需降配：`quic_stream_window`、`quic_conn_window`、`quic_max_stream_window`、`quic_max_conn_window`。解析逻辑在 `listener.ParseTransportMetadata` 与 dialer 侧的 `ParseTransportMetadata` 中补齐。

### 预期收益（Expected Gain）

QUIC 长流吞吐不再受限于默认 512KB 单流窗口，在高 RTT 条件下接近 TCP；`quic://` 与 `h3://` dialer 的 0-RTT 行为一致，短连接 TTFB 受益。

### 风险（Risks）

- 大窗口会线性增加每条连接的内存上限，高并发下总体内存预算需要在 README 中说明。
- 0-RTT 仅对幂等请求安全：PHT 的 push 为单向字节流，可接受；业务层若未来加入非幂等请求需要在调用侧关闭 0-RTT。
- `EnableDatagrams=false` 是保守选择，规避 quic-go 在部分版本出现的兼容性问题；若未来需要 MASQUE 类特性再打开。

### 回退开关（Opt-out）

- URL 参数 `quic_stream_window=256k` 等显式覆盖（数值支持 `k`/`m` 后缀）；
- URL 参数 `quic_0rtt=false` 仅关闭 0-RTT，仍保留新窗口。
默认使用新值。

---

## 4. Hysteria2 UDP `readLoop` 消除每包 `append` 分配

### 现状（Current）

`internal/hysteria2/server.go` 中 `routeUDPConn.readLoop` 的每次 `conn.Read` 之后都执行 `data := append([]byte(nil), buf[:n]...)`，然后投递到带 64 缓冲的 `recvCh`；`buf` 本身是 64KB 栈外切片，每包至少一次堆分配。

`internal/connector/hysteria2/connector.go` 的 `hyUDPNetConn.receiveLoop` 有同样的结构：每次 `conn.Receive()` 后 `data := append([]byte(nil), payload...)` 送入 `recvCh`。

### 改动建议（Proposed Change）

1. 把 read 端从 `buf := make([]byte, 64*1024)` 改成每次从 `base/pool.Get()` 取 64KB buffer；收到 `n` 字节后仅截取到 `[:n]` 就入队，消费方在 `ReadFrom` 读走后通过 `base/pool.Put` 归还。此模式已经在 `internal/listener/udpsession/session.go` 的 `Conn.ReadFrom` 中被验证有效（见其中的 `pool.Put(buf)` 调用）。
2. 为防止 close 边界上丢失已池化的 buffer，在 `routeUDPConn.Close` / `hyUDPNetConn.Close` 内 drain 一次 `recvCh`，把未消费的 buffer 全部 `pool.Put`。
3. `udpReadResult` / `udpPacket` 结构中的 `data` 字段语义改为"池化 buffer，消费后必须 Put"，并在相邻代码中加注释以避免后续贡献者误用。

### 预期收益（Expected Gain）

每条 UDP 包节省一次堆分配与一次 GC 触发点；高 PPS 的 UDP 中继（如 QUIC 代理、游戏流量）的长尾延迟更平稳。

### 风险（Risks）

- 生命周期管理是典型 footgun：若 double-put 会导致 `sync.Pool` 持有同一切片、下一次 `Get` 时形成 use-after-free。必须写 race test 覆盖 `switchConnLocked` 与 `Close` 两个边界。
- 64KB 池与 UDP MTU 严重不匹配会放大每包内存（不过与现有 listener 口径相同，问题不大）。

### 回退开关（Opt-out）

内部 const 开关（如 `const hysteria2PoolRecv = true`），保留旧路径便于 A/B 对比；默认开启，无需用户配置。

---

## 5. PHT 客户端 `postBatch` 复用 `bytes.Buffer` + base64 流式编码

### 现状（Current）

`base/transport/pht/conn.go` 中：

- `clientConn.Write` 对每次 `b` 做一次 `pkt := append([]byte(nil), b...)` 拷贝，再入队；
- `clientConn.postBatch` 每个 batch 新建 `var payload bytes.Buffer`，对每个 packet 调用 `base64.StdEncoding.EncodeToString(pkt)`（返回临时字符串）后 `WriteString`；
- `clientConn.readLoop` 服务端侧使用 `bufio.Scanner`，每行 `base64.StdEncoding.DecodeString(scanner.Text())` 返回新切片。

### 改动建议（Proposed Change）

1. 在 `base/transport/pht/conn.go` 顶部引入一个 `sync.Pool` 专门复用 `bytes.Buffer`（初始容量 8KB，`Reset` 后放回）。`postBatch` 从池中取出后改用 `base64.NewEncoder(base64.StdEncoding, buf)` 流式写入 + 每个 packet 末尾 `\n`，最终一次 `http.NewRequestWithContext` 使用 `buf` 作为 body。发送完成后 `buf.Reset()` 再 `Put` 回池。
2. `clientConn.Write` 中 `pkt := append([]byte(nil), b...)` 改为从 `base/pool.GetWithSize(len(b))` 取，消费方 `writeLoop` 在 `postBatch` 完成后把所有 `batch` 元素通过 `base/pool.Put` 归还。Batch slice 自身也可以池化。
3. 服务端读取侧：将 `base64.DecodeString(text)` 替换为 `base64.StdEncoding.DecodedLen(len(text))` 预估大小后 `pool.GetWithSize(size)`，再调用 `base64.StdEncoding.Decode(dst, []byte(text))`；将 `dst[:n]` 推入 `rxc`，`Read` 读完后 `pool.Put`。

改动全部集中在 `base/transport/pht/conn.go` 内部，不影响 `NewClientConn` / `NewServerConn` 公共签名。

### 预期收益（Expected Gain）

高 QPS 的 PHT 隧道显著减少 base64 相关的临时字符串分配，bench 热路径的 `B/op`、`allocs/op` 下降；在流量较小但频次高的交互式场景尤其明显。

### 风险（Risks）

- `sync.Pool` 持有的 `bytes.Buffer` 必须在 `postBatch` 失败路径上也能回收；建议统一在 `defer` 中 `Reset` + `Put`。
- `base/pool` 默认容量 64KB，PHT 单个 packet 若超过该阈值会退化为普通 `make`；对隧道语义无影响，但 bench 记录时要覆盖大 packet 场景。
- 池化对象泄漏会造成"看起来不分配、实际内存持续上涨"，合入前必须跑 race + bench 双轨验证。

### 回退开关（Opt-out）

内部 const 开关 `phtPooledBatch = true`，保留旧的 `bytes.Buffer{}` + `EncodeToString` 路径作为对照；默认开启。

---

## 6. Yamux 反向穿透窗口与超时配置化

### 现状（Current）

`internal/reverse/helpers.go` 中 `NewYamuxConfig` 基于 `yamux.DefaultConfig()`，只显式覆盖 `KeepAliveInterval = 10s`。其余字段全部保留默认：`MaxStreamWindowSize = 256 KB`、`StreamCloseTimeout = 5m`、`ConnectionWriteTimeout = 10s`、`StreamOpenTimeout` 继承默认。对于高 RTT 反向穿透链路，单 stream 的上限约为 `window / RTT`，256KB 窗口在 200ms 往返上只有约 10Mbps。

### 改动建议（Proposed Change）

在 `internal/reverse/helpers.go` 中给 `NewYamuxConfig` 添加一个 `YamuxTuning` 结构，字段含 `MaxStreamWindowSize`、`StreamOpenTimeout`、`ConnectionWriteTimeout`、`EnableKeepAlive`、`KeepAliveInterval`，默认值改为：

- `MaxStreamWindowSize = 4 MiB`
- `StreamOpenTimeout = 30s`
- `ConnectionWriteTimeout = 15s`
- `EnableKeepAlive = true`
- `KeepAliveInterval = 10s`（保持现状）

调用方（`internal/reverse/client/client.go` 及 server 端的等价入口）通过 URL 查询参数注入覆盖：

- `yamux_window`
- `yamux_open_timeout`
- `yamux_write_timeout`
- `yamux_keepalive_interval`

数值解析复用 `internal/metadata` 的 `IntValue` / `DurationValue`；字节类数值支持 `k`/`m` 后缀。

### 预期收益（Expected Gain）

反向穿透的跨境 / 高延迟链路上，单 stream 吞吐不再被 256KB 窗口卡住；KeepAlive 行为在 NAT 老化较快的网络上更稳定。

### 风险（Risks）

- 大窗口会抬高每个 stream 的内存上限，当 stream 数量很多（例如批量 scp）时需要在 README 中给出内存预算说明。
- 旧客户端与新服务端混跑时，window 值由建连方宣告，不会造成协议不兼容，但需要在回归测试里覆盖"服务端 4MB、客户端保持默认"的组合。

### 回退开关（Opt-out）

URL 查询参数显式传入旧值即可（例如 `?yamux_window=256k`）。不引入全局 env。

---

## 7. DialPool 并发预热与抖动

### 现状（Current）

`internal/chain/pool.go` 中 `DialPool.fill` 以 `for i := 0; i < need; i++` 形式串行 `dial` + `Handshake`；`warmBackground` 的 ticker 固定 30 秒，无随机化。`Get` 在池为空时直接发起同步 `dial`，等价于把拐点处的单个请求打成 "TLS 完整握手 + 业务 RTT" 的线性串联。

### 改动建议（Proposed Change）

1. `fill` 改为并发版：用 `golang.org/x/sync/errgroup`（`go.mod` 的 direct require 中已存在 `golang.org/x/sync v0.19.0`）启动最多 `need` 个 goroutine 并行拨号；同时引入一个容量 4 的信号量 channel 作为并发上限，避免瞬间打爆上游。
2. `warmBackground` 的 ticker 周期加 ±20% 抖动：`next := 30*time.Second * (0.8 + rand.Float64()*0.4)`，每次 `Reset` 后用新周期。`rand` 使用 `math/rand/v2`，避免引入 seed 全局状态。
3. `Get` 中"池为空则同步 dial" 的路径保留，但额外触发一次非阻塞的异步 `fill()`（通过 `select { case trigger <- struct{}{}: default: }`），减少下一次 `Get` 仍为空的概率。

### 预期收益（Expected Gain）

冷启动阶段完成预热所需时间下降（从 `N * handshake_RTT` 降到约 `handshake_RTT`）；稳态下多实例部署不再因 30s 整点同步造成上游压力尖峰。

### 风险（Risks）

- 并发预热会在冷启动瞬间向上游多打几个握手，需要确认 `maxIdle` 严格封顶，避免实际超出。
- 抖动带来日志时间不规整，对依赖"每 30s 一次心跳"的观测需要做说明。

### 回退开关（Opt-out）

URL 查询参数 `pool_parallel=1` 回到串行路径；`pool_jitter=false` 关闭抖动。默认并发 + 抖动。

---

## 8. Balancer 测速从握手级升级为 CONNECT+204（可选）

### 现状（Current）

`internal/chain/balancer.go` 的 `testAll` 对每个候选只执行 `Transport.Dial` + `Transport.Handshake` 然后立刻 `conn.Close()`，不经过上游 Connector，也不发业务请求。对 mux / Reality 等场景，握手时间与真实业务 RTT 存在显著偏差。

`internal/subscribe/connect_test_node.go` 中已经有完整的 "CONNECT + GET `gstatic.com/generate_204`" 测速实现（`testNodeBestLatency`），逻辑完善且有预热轮，但仅用于订阅阶段，没有被 Balancer 复用。

### 改动建议（Proposed Change）

1. 给 `BalancerRoute`（或 `BalancerCandidate`）新增可选字段 `CheckURL string`。
2. 当 `CheckURL` 非空时，`testAll` 内部单 node 的探测从 "Dial+Handshake" 切换为 "经由该节点发起一次 CONNECT + GET 204" 的形态，实现上抽取一个复用函数放在 `internal/chain`（例如 `probeRoute(ctx, rt chain.Route, url string) time.Duration`），让 `internal/subscribe/connect_test_node.go` 也调用同一函数，保持行为一致。
3. 默认保持 `CheckURL == ""`，即继续走 Handshake-only，行为不变；仅在订阅 / 反向穿透等显式打开的场景生效。
4. 新增 URL 查询参数（balancer 入口）`probe_url=http://...`；env `FORWARD_BALANCER_PROBE_URL` 作为全局默认。

### 预期收益（Expected Gain）

对 Reality / Mux 场景下"TCP 握手耗时与业务 RTT 差距较大"的节点，排序更贴近真实可用性，降低调度失真。

### 风险（Risks）

- 引入定期探测流量，对目标 URL（如 gstatic）形成稳定的周期性请求，可能触发风控；默认必须 opt-in。
- 测速失败会把节点暂时标记为不可用，需保持现有 `time.Hour*24` 的失败哨兵值语义。

### 回退开关（Opt-out）

默认关闭。`CheckURL` 必须显式设置才生效。

---

## 9. UDP Listener rate limiter 用令牌桶替代每秒整表重建

### 现状（Current）

`internal/listener/udp/listener.go` 的 `rateLimiter.run` 每秒对 `rl.counts` 进行 `make(map[netip.Addr]int)` 整表重建。高并发 UDP 场景下该 map 可能持有数千条目，每秒一次 O(N) 分配与释放，会在 p99 路径上放大抖动。

### 改动建议（Proposed Change）

将 `counts` 的语义从"每秒窗口计数"改为令牌桶：

- 每 IP 关联一个 `tokens float64`（或 `int`）与 `lastRefill time.Time`；
- `allow(ip)` 在取锁后按 `now - lastRefill` 线性补充令牌，上限 `burst`；
- 删除 `run` 中 `rl.counts = make(...)` 的整表重建；改为懒清理：若某条目 10 分钟未被访问则在下一次 `allow` 命中同 IP 或周期性扫描时移除（避免内存泄漏）。

不引入新依赖（`golang.org/x/time/rate` 虽在间接依赖中可用，但为了避免升级为 direct require，使用内置实现更稳）。

### 预期收益（Expected Gain）

消除"每秒一次大 map 重建"带来的尖峰，GC 压力降低；限流精度由"整秒窗口"提升为"滑动窗口"。

### 风险（Risks）

- 需要给 map 条目设置最大 TTL（建议 10 分钟）避免泄漏；
- 令牌桶的 `burst` 参数取值需谨慎：沿用原 `limit` 作为速率，`burst = limit` 或 `limit * 2` 都是合理选择，建议在配置中允许调整。

### 回退开关（Opt-out）

URL 参数 `rate_limit_legacy=true` 保留整表重建路径；默认使用令牌桶。

---

## 10. 日志热路径 level-gate 与前缀字符串表

### 现状（Current）

`base/logging/logging.go` 的 `printf` 在日志级别不匹配时会提前 return，但调用处（例如 `internal/chain/route_impl.go` 中大量 `tr.Logger.Debug(...)`）仍然会先对格式参数求值（字符串拼接、`RouteSummary(r)` 等）。此外在 `LevelDebug` 下每条日志都调用 `runtime.Caller(2)` 与两次 `fmt.Sprintf`（一次常量前缀，一次带 file:line）。

### 改动建议（Proposed Change）

1. 在 `base/logging/logging.go` 中把 `[DEBUG]` / `[INFO]` / `[WARN]` / `[ERROR]` 这几个常量前缀预先放到一个 `var levelLabel = [...]string{"[DEBUG] ", "[INFO] ", "[WARN] ", "[ERROR] ", ""}` 表里，`printf` 中直接按 `msgLevel` 索引取用，避免 `fmt.Sprintf("[%s] ", strings.ToUpper(msgLevel.String()))` 在热路径上反复跑。
2. 当进入 `LevelDebug` 分支时，`runtime.Caller(2)` 仍需保留（信息价值大），但把 `fmt.Sprintf("[%s] %s:%d ", ...)` 改为 `strings.Builder` 拼接或 `appendInt` 风格，减少格式化开销。
3. 对 `internal/chain/route_impl.go`、`internal/chain/balancer.go`、`internal/xraymux/copy.go`、`internal/handler/tcp/handler.go`、`internal/handler/udp/handler.go` 中的热点 `Debug(...)` 调用加 `if tr.Verbose && tr.Logger.Level() <= logging.LevelDebug` 守卫，避免在非 debug 级别下构造 args（例如多次调用 `RouteSummary`、`labelNode`）。`Logger` 需要暴露 `Level()` 这一公开方法（已存在）。

### 预期收益（Expected Gain）

INFO 级稳态运行避免 `fmt.Sprintf` 常量前缀的重复分配；DEBUG 级下减少每条日志的字符串构造。对高 QPS 代理尤为有效。

### 风险（Risks）

- 代码冗余度上升（需要多处加 if 守卫），但 API 不变；可以考虑加一个 `logger.DebugEnabled()` 辅助方法降低重复。
- `levelLabel` 表若未来新增 Level 值需要同步更新。

### 回退开关（Opt-out）

纯优化，无需开关；回滚只需 revert。

---

## 11. DNS / MMDB 缓存统一

### 现状（Current）

- `base/route/route.go` 的 `resolver.lookupIPs` 已有 30 秒 `sync.Map` 缓存 + `singleflight.Group`，逻辑完善。
- `internal/chain/route_impl.go` 的 `SetDefaultResolver` 内联构造一个 `net.Resolver`，没有接入上述缓存，并且在每次 DNS 查询上先尝试 UDP 再尝试 TCP，串行 fallback。
- `internal/dialer/resolver.go` 的 `NewResolver` 同样独立实现，未复用。
- `base/mmdb/parse.go` 的 `CountryCode` 每次 `db.Lookup(ip, &rec)` 分配新的 `record`；虽然 maxminddb 已 mmap，但 regexp 规则引擎对同一 IP 重复查询时仍然会触发。

### 改动建议（Proposed Change）

1. 把 DNS 缓存下沉到一个新的 `base/dns` 包（或保持在 `base/route`，但对外暴露 `resolver` 的 Lookup API）。`internal/chain/route_impl.go` 与 `internal/dialer/resolver.go` 改为调用 `base/dns` 提供的函数，共享同一个缓存 + singleflight。
2. 在 `base/mmdb/parse.go` 中加一层小型缓存：`sync.Map[netip.Addr] struct{cc string; expireAt int64}`，容量软上限 4096、TTL 10 分钟。key 用 `netip.Addr` 避免 `net.IP` slice 拷贝；`Reader.CountryCode` 先查缓存再回落到 `db.Lookup`。
3. 新增 URL 参数 `dns_cache=false` 可局部禁用（目前无用户反馈指向过期问题，默认启用）。

### 预期收益（Expected Gain）

规则引擎热路径的 DNS / GEOIP 查询命中缓存后 O(1)；GEOIP 规则对高 QPS 代理不再成为瓶颈。

### 风险（Risks）

- DNS 缓存可能掩盖上游记录更新（例如 DDNS），TTL 已由 `defaultDNSCacheTTL = 30s` 兜底，改动时保持或缩短该值；
- MMDB 缓存只缓存 ISO country code，数据结构小，内存开销可控。

### 回退开关（Opt-out）

URL 参数 `dns_cache=false` 关闭 DNS 缓存；`mmdb_cache=false` 关闭 MMDB 缓存。默认开启。

---

## 12. UDP 批量收发（`recvmmsg` / `sendmmsg`）可行性研究

### 现状（Current）

`internal/listener/udp/listener.go` 的 `listenLoop` 对 `conn.ReadFrom(buf)` 做单包串行读取；`internal/listener/tproxy/listener_linux.go` 同样单包。quic-go 在支持平台上对自己的 socket 会启用 GSO，但 forward 的 UDP 转发路径不受益。

### 改动建议（Proposed Change）

本条仅做设计与开关占位，不在本轮实施：

1. 新增 `internal/listener/udp/batch_linux.go`（构建标签 `//go:build linux`），封装 `golang.org/x/sys/unix.Recvmmsg` / `Sendmmsg`，每次 syscall 最多 16 包。
2. `internal/listener/udp/batch_other.go` 提供空实现（直接委托回 `ReadFrom` / `WriteTo`），保持跨平台编译通过。
3. `Listener.listenLoop` 在 `l.md.udpBatch && runtime.GOOS == "linux"` 时切到批量路径，失败则降级。
4. URL 查询参数 `udp_batch=true` 显式启用；默认关闭。

### 预期收益（Expected Gain）

单节点 UDP 转发 PPS 预期显著提升，syscall 开销降幅按社区经验通常过半。对游戏、视频流、WireGuard 中继等高 PPS 场景收益最大。

### 风险（Risks）

- 内核与 glibc 兼容性差异大，需要在典型 Linux 发行版（Debian stable、Alma/Rocky、Ubuntu LTS）上实测；
- 批量路径下包的时序语义与单包 ReadFrom 不完全一致，需要保证现有 UDP session 关键逻辑不假设"一个事件一个包"。

### 回退开关（Opt-out）

默认 `udp_batch=false`。用户显式开启失败后自动降级为单包路径。

---

## 未采纳方向与原因

- **TCP Fast Open**：客户端侧 cookie 受服务端策略影响大，NAT 与中间盒兼容性不稳定；macOS / Windows 之间行为差异过大，不值得为边际收益引入跨平台分支。
- **`SO_REUSEPORT`**：当前每个 `Listener` 单实例架构下，多 listener 同端口会破坏 accept 均衡，无法直接受益；需要配套改造 handler 分发才有意义，暂不列入。
- **手动设置 `TCP_NODELAY`**：Go 标准库 `*net.TCPConn` 默认即 `TCP_NODELAY=1`，无需再调。
- **手动扩大 `SO_SNDBUF` / `SO_RCVBUF`**：现代 Linux 默认启用 `tcp_moderate_rcvbuf` 与 BBR，手动设置很多时候反而抑制自动伸缩；仅在确有 benchmark 证据时按需开关。
- **引入 `github.com/klauspost/reedsolomon` 等 FEC**：超出本 Spec 的"纯代理优化"边界，会显著增加依赖与 CPU，不纳入。
