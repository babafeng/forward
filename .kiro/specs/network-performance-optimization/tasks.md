# forward 网络性能优化 · Tasks

> 本文档把 `design.md` 中的 12 个优化项落成可独立领取的实施任务，按推荐顺序编号 T-01 至 T-12。每个任务包含以下固定字段：
>
> - **涉及文件**：仓库内精确路径列表
> - **预估规模**：S（<100 行）/ M（100-300 行）/ L（>300 行）
> - **依赖**：前置任务 ID
> - **验证方式**：`go test` 命令、bench 方案、必要的人工验证（即便本轮沙箱跑不起来，也写明实施时应当执行的命令）
> - **风险**：行为变更与回退开关
> - **类别**：feat / refactor / perf / chore
> - **验收清单**：3 至 6 条可 check 的条目
>
> 全部 12 个任务都仅允许修改 design.md 中约定的代码路径，不引入新的第三方依赖（`go.mod` 与 `go.sum` 不得修改）。

---

## T-01 TLS ClientSessionCache 基线（对应 design §2）

**类别**：perf

**涉及文件**：
- `internal/config/tls/config.go`
- `internal/dialer/tls/dialer.go`
- `internal/dialer/h2/dialer.go`
- `internal/dialer/h3/dialer.go`
- `internal/dialer/http3/dialer.go`
- `internal/dialer/quic/dialer.go`
- `internal/dialer/transportutil/`（新增辅助函数文件）
- `internal/config/tls/config_test.go`（新增或扩展）
- `internal/dialer/tls/dialer_test.go`（新增）
- `README.md` 的"新增可选参数"章节（仅追加一行说明）

**预估规模**：M

**依赖**：无

**验证方式**：
- `go test ./internal/config/tls/... ./internal/dialer/tls/... ./internal/dialer/h2/... ./internal/dialer/h3/... ./internal/dialer/http3/... ./internal/dialer/quic/...`
- `go test -race ./internal/...`（覆盖并发注入 / 取用 session cache 的场景）
- 本地 e2e：用 `tests/proxy_e2e_test.go` 启动 TLS 服务端，连续建连两次并打开 `tls.Config.KeyLogFile`，确认第二次握手命中 `Client-Random` 对应的 `TLS-Session-Key` 行（resumption）。

**风险**：
- 进程内共享 cache 若 key 设计不当可能导致跨 SNI 串扰；
- 回退开关：URL 参数 `tls_cache=false`、环境变量 `FORWARD_DISABLE_TLS_CACHE=1`；
- 默认启用对行为有影响（TLS 1.2 会显式发送票据、TLS 1.3 会附带 PSK），需在 README 中追加一行说明。

**验收清单**：
1. `internal/config/tls/config.go` 的 `ClientConfig` 在 `InsecureSkipVerify=false` 时注入共享 `ClientSessionCache`；`true` 时也可选择注入（默认注入，`tls_cache=false` 可关闭）。
2. TLS / H2 / H3 / HTTP3 / QUIC 五处 dialer 均通过同一 `transportutil` 辅助函数写入 cache，代码重复不得超过 1 处。
3. 新增 URL 查询参数 `tls_cache=false` 能在单跳关闭 cache，`FORWARD_DISABLE_TLS_CACHE=1` 能全局关闭。
4. 新增或扩展的 `_test.go` 覆盖："注入 cache 后第二次握手命中 resumption"、"关闭开关后回退 full handshake" 至少两个用例。
5. `go test ./internal/config/tls/... ./internal/dialer/tls/...` 全绿；`go vet ./...` 无新增 warning。
6. `README.md` 的"新增可选参数"小节追加一行对 `tls_cache` 的说明。

---

## T-02 Bidirectional splice 零拷贝快路径（对应 design §1）

**类别**：perf

**涉及文件**：
- `base/io/net/copy.go`
- `base/io/net/copy_test.go`

**预估规模**：S

**依赖**：无

**验证方式**：
- `go test ./base/io/net/...`
- `go test -race ./base/io/net/...`
- Bench：在 `copy_test.go` 中新增 `BenchmarkBidirectionalTCP` / `BenchmarkBidirectionalTLS`，实施时运行 `go test -bench . -benchmem -run '^$' ./base/io/net/`，对比启用前后 `ns/op` 与 `B/op`。
- 人工：在 Linux 上用 `strace -e splice,read,write -p $(pgrep forward)` 观察 TCP 明文转发路径是否调用 `splice`。

**风险**：
- 若包装连接不正确实现 `io.ReaderFrom`，可能导致吞字节或半关闭语义异常；
- 回退开关：环境变量 `FORWARD_DISABLE_SPLICE=1`；
- 需保持现有 `closeWrite` / `normalizeCopyError` / `waitSecondResult` 的语义一致。

**验收清单**：
1. `Bidirectional` 的 `pipe` 内先检测 `dst` 是否实现 `io.ReaderFrom`、`src` 是否为 `*net.TCPConn`，命中则走 `io.Copy(dst, src)`；否则保留 `io.CopyBuffer` + 池化路径。
2. 新增 `FORWARD_DISABLE_SPLICE` 环境变量识别（仅在包初始化时读取一次）。
3. `copy_test.go` 覆盖两条路径：纯 TCP（走 splice 路径）与封装连接（走 buffer 路径），断言字节数与错误语义一致。
4. `go test ./base/io/net/...` 全绿。
5. Bench 基线数据记录在 PR 描述中（实施阶段）。

---

## T-03 QUIC / H3 流控窗口与 DialAddrEarly 统一（对应 design §3）

**类别**：perf

**涉及文件**：
- `internal/dialer/quic/dialer.go`
- `internal/dialer/h3/dialer.go`
- `internal/dialer/http3/dialer.go`
- `internal/dialer/transportutil/`（抽出 `BuildQUICConfig`）
- `internal/listener/quic/listener.go`
- `internal/listener/h3/listener.go`
- `internal/listener/http3/listener.go`
- `internal/listener/phtlistener/base.go`（若已有 metadata 解析，扩展字段）
- `internal/listener/listener.go` 的 `ParseTransportMetadata`
- 对应 `_test.go` 新增 metadata 解析用例

**预估规模**：M

**依赖**：T-01（`DialAddrEarly` 的 0-RTT 前置依赖为 session cache）

**验证方式**：
- `go test ./internal/dialer/... ./internal/listener/...`
- `go test -race ./internal/listener/quic/... ./internal/listener/h3/... ./internal/listener/http3/...`
- e2e：在 `tests/listener_h3_pht_server_test.go` 附近加一个长流传输用例，注入 100ms `tc qdisc add dev lo root netem delay 100ms` 人工延迟，对比窗口调整前后 `wrk` 吞吐。
- 人工：通过 `ss -tun` / `quic-go` debug 日志观察窗口宣告值是否生效。

**风险**：
- 大窗口会抬高每连接内存上限，高并发下需 README 说明；
- 0-RTT 仅对幂等请求安全，默认开启但对 `quic://` 走字节流无影响；
- 回退开关：`quic_stream_window`、`quic_conn_window`、`quic_max_stream_window`、`quic_max_conn_window`、`quic_0rtt=false`。

**验收清单**：
1. `internal/dialer/quic/dialer.go` 的 `Dial` 切换到 `quic.DialAddrEarly`；与 `internal/dialer/h3/dialer.go` 行为一致。
2. 所有 dialer / listener 构造 `quic.Config` 通过同一 `transportutil.BuildQUICConfig` 辅助函数；默认值与 design §3 一致。
3. 新增四个 URL 查询参数（见 design §3）可覆盖窗口默认值，数值解析支持 `k`/`m` 后缀。
4. `internal/listener/quic/listener.go` 的 `quic.ListenAddr` 第三参不再为 `nil`。
5. `go test ./internal/dialer/... ./internal/listener/...` 全绿。
6. README "新增可选参数" 章节追加一段对新 QUIC 参数的说明。

---

## T-04 Yamux 窗口 / 超时配置化（对应 design §6）

**类别**：perf

**涉及文件**：
- `internal/reverse/helpers.go`
- `internal/reverse/client/client.go`
- `internal/reverse/` 下 server 入口（参照现有调用链）
- `internal/reverse/helpers_test.go`（新增）
- `README.md` 反向穿透段落追加一段说明

**预估规模**：S

**依赖**：无

**验证方式**：
- `go test ./internal/reverse/...`
- e2e：`tests/reverse_e2e_test.go` 中补一个大文件回传用例，注入 100ms 延迟验证单 stream 吞吐提升。
- 人工：通过 `tcpdump` 或 yamux debug 日志确认 WindowUpdate 帧宣告新值。

**风险**：
- 大窗口抬高每 stream 内存占用；
- 回退开关：URL 查询参数 `yamux_window` 等；
- 服务端 / 客户端混跑无需协议兼容改动，但需在回归测试覆盖。

**验收清单**：
1. `NewYamuxConfig` 接受一个可选的 tuning 结构，默认值按 design §6 设定（4MB 窗口等）。
2. 客户端 / 服务端入口均可通过 URL 查询参数 `yamux_window` / `yamux_open_timeout` / `yamux_write_timeout` / `yamux_keepalive_interval` 覆盖。
3. `helpers_test.go` 覆盖默认值与覆盖值两种情况。
4. `go test ./internal/reverse/...` 全绿。
5. README 追加"反向穿透高延迟链路调参"说明。

---

## T-05 Hysteria2 UDP readLoop 池化（对应 design §4）

**类别**：perf

**涉及文件**：
- `internal/hysteria2/server.go`
- `internal/connector/hysteria2/connector.go`
- 两者的 `_test.go`（新增或扩展，race test）
- `base/pool/pool.go`（若需要补充 `GetWithSize` 之外的 API，可小幅调整；原则上不改动）

**预估规模**：M

**依赖**：无

**验证方式**：
- `go test ./internal/hysteria2/... ./internal/connector/hysteria2/...`
- `go test -race ./internal/hysteria2/... ./internal/connector/hysteria2/...`
- Bench：`BenchmarkHysteria2UDPReadLoop` 模拟高 PPS，对比 `allocs/op`。
- 人工：在本地启动 hy2 server，`iperf3 -u -b 0` 打压，`go tool pprof -alloc_space` 查看分配热点是否消失。

**风险**：
- 生命周期 footgun；
- 回退开关：内部 const `hysteria2PoolRecv`（默认 true）；
- `Close` 必须 drain `recvCh` 并 Put 未消费 buffer，避免 leak。

**验收清单**：
1. `routeUDPConn.readLoop` 中 `buf := make([]byte, 64*1024)` 改为 `pool.Get()`；`udpReadResult.data` 从池化 buffer 借出。
2. `hyUDPNetConn.receiveLoop` 中 `data := append([]byte(nil), payload...)` 同样改为池化。
3. `routeUDPConn.Close` / `hyUDPNetConn.Close` drain `recvCh`，所有未消费 buffer `pool.Put`。
4. race test 覆盖 `switchConnLocked`、`Close`、超时三条生命周期路径。
5. `go test -race ./internal/hysteria2/... ./internal/connector/hysteria2/...` 全绿。
6. Bench 报告 `allocs/op` 相比基线下降。

---

## T-06 PHT postBatch / handlePush base64 流式 + 池化（对应 design §5）

**类别**：perf

**涉及文件**：
- `base/transport/pht/conn.go`
- `base/transport/pht/conn_test.go`（新增或扩展）
- `internal/listener/phtserver/server.go`（若服务端解码路径涉及 `DecodeString`，同步改动）

**预估规模**：M

**依赖**：无

**验证方式**：
- `go test ./base/transport/pht/... ./internal/listener/phtserver/...`
- `go test -race ./base/transport/pht/...`
- Bench：`BenchmarkPHTPostBatch` / `BenchmarkPHTHandlePush`，对比 `B/op`、`allocs/op`。
- 人工：`tests/listener_h3_pht_server_test.go` 复跑，关注成功率无变化。

**风险**：
- 池化对象泄漏会"看起来不分配、实际内存增长"，需 race + bench 双轨验证；
- 回退开关：内部 const `phtPooledBatch`（默认 true）。

**验收清单**：
1. `clientConn.postBatch` 使用 `sync.Pool` 复用 `bytes.Buffer`，并用 `base64.NewEncoder` 流式编码。
2. `clientConn.Write` 中 `pkt := append([]byte(nil), b...)` 替换为从 `base/pool.GetWithSize(len(b))` 取，消费完 `pool.Put`。
3. 服务端解码路径不再使用 `base64.DecodeString`，改为预分配 + `Decode` into。
4. 失败路径（HTTP 非 200、`context.DeadlineExceeded`）下 `buf.Reset()` + `Put` 正确执行，无泄漏。
5. `go test -race ./base/transport/pht/...` 全绿。
6. Bench 对比数据写入 PR 描述。

---

## T-07 DialPool 并发预热 + 抖动（对应 design §7）

**类别**：perf

**涉及文件**：
- `internal/chain/pool.go`
- `internal/chain/pool_test.go`（新增或扩展）
- `internal/builder/`（如果 DialPool 的配置入口在 builder，顺带接入新参数）

**预估规模**：S

**依赖**：T-01（池内预热连接应当命中 session resumption，否则并发握手收益打折）

**验证方式**：
- `go test ./internal/chain/...`
- `go test -race ./internal/chain/...`
- 人工：跑 `go test -run TestDialPoolWarm -count 5 ./internal/chain/` 观察冷启动时间分布；用 `strace -e connect` 确认并发 dial 数量符合预期。

**风险**：
- 并发预热瞬间会向上游多打几次握手，需保证 `maxIdle` 严格生效；
- 回退开关：URL 参数 `pool_parallel=1`、`pool_jitter=false`。

**验收清单**：
1. `DialPool.fill` 改为使用 `golang.org/x/sync/errgroup` 并发执行，上限 4。
2. `warmBackground` ticker 引入 ±20% 抖动，使用 `math/rand/v2`。
3. `Get` 池空时触发非阻塞 `fill` 信号，减少连续失败。
4. 新增 `pool_parallel` / `pool_jitter` URL 参数并在测试中覆盖。
5. `go test -race ./internal/chain/...` 全绿。

---

## T-08 DNS / MMDB 缓存统一（对应 design §11）

**类别**：refactor + perf

**涉及文件**：
- `base/route/route.go`（或抽出 `base/dns/` 新包）
- `base/mmdb/parse.go`
- `internal/chain/route_impl.go`（`SetDefaultResolver`）
- `internal/dialer/resolver.go`
- `base/route/route_test.go`、`base/mmdb/parse_test.go`（新增或扩展）

**预估规模**：M

**依赖**：无（独立路径）

**验证方式**：
- `go test ./base/route/... ./base/mmdb/... ./internal/chain/... ./internal/dialer/...`
- `go test -race ./base/route/...`
- 人工：开启 debug 日志，连续请求同一域名 / 同一 IP 50 次，确认只有第一次触发底层查询。

**风险**：
- DNS 缓存可能掩盖 DDNS 更新；TTL 保持 30 秒；
- MMDB 缓存容量与 TTL 需要在 README 声明；
- 回退开关：URL 参数 `dns_cache=false` / `mmdb_cache=false`。

**验收清单**：
1. `internal/chain/route_impl.go` 的 `SetDefaultResolver` 与 `internal/dialer/resolver.go` 的 `NewResolver` 都改为调用 `base/dns`（或 `base/route`）暴露的统一 lookup 函数，共享缓存 + singleflight。
2. `base/mmdb/parse.go` 引入容量 4096、TTL 10 分钟的 LRU 缓存；key 使用 `netip.Addr`。
3. 新增 URL 参数 `dns_cache` / `mmdb_cache`，默认开启。
4. 测试覆盖"命中缓存跳过查询"、"TTL 过期重查"、"singleflight 合并并发请求" 三类用例。
5. `go test ./base/route/... ./base/mmdb/...` 全绿。

---

## T-09 日志热路径 level gate + 前缀表（对应 design §10）

**类别**：perf

**涉及文件**：
- `base/logging/logging.go`
- `internal/chain/route_impl.go`
- `internal/chain/balancer.go`
- `internal/xraymux/copy.go`
- `internal/handler/tcp/handler.go`
- `internal/handler/udp/handler.go`
- `base/logging/logging_test.go`（新增）

**预估规模**：S

**依赖**：无

**验证方式**：
- `go test ./base/logging/... ./internal/chain/... ./internal/handler/...`
- Bench：`BenchmarkLoggerInfoDisabled` / `BenchmarkLoggerDebugEnabled`，对比 `ns/op` 与 `allocs/op`。
- 人工：grep `tr.Logger.Debug(` 确认所有热点调用加 `DebugEnabled()` 守卫。

**风险**：
- 代码冗余度上升，可通过 `logger.DebugEnabled()` 辅助方法缓解；
- 无开关，纯优化。

**验收清单**：
1. `base/logging/logging.go` 引入 `var levelLabel = [...]string{...}`，`printf` 按索引查表。
2. `Logger` 暴露 `DebugEnabled() bool` 辅助方法（若未来升级 `Level()` 判断）。
3. 热路径 `Debug(...)` 调用均加 `if tr.Verbose && tr.Logger.DebugEnabled()` 守卫。
4. 新增 `logging_test.go` 覆盖"级别过滤"与"前缀表"两类断言。
5. `go test ./base/logging/...` 全绿。

---

## T-10 UDP Listener 限流改令牌桶（对应 design §9）

**类别**：perf

**涉及文件**：
- `internal/listener/udp/listener.go`
- `internal/listener/udp/listener_test.go`（新增或扩展）

**预估规模**：S

**依赖**：无

**验证方式**：
- `go test ./internal/listener/udp/...`
- `go test -race ./internal/listener/udp/...`
- 人工：`hping3 --udp -i u1000 -c 100000 ...` 压测，观察 p99 延迟抖动是否下降。

**风险**：
- 懒清理未触发时可能导致 map 缓慢增长；实现时加 10 分钟 TTL 周期扫描；
- 回退开关：URL 参数 `rate_limit_legacy=true`。

**验收清单**：
1. `rateLimiter` 由每秒重建整表改为令牌桶；`counts` 值语义改为 `{tokens, lastRefill}`。
2. 新增 10 分钟 TTL 周期扫描，防止冷 IP 积累。
3. URL 参数 `rate_limit_legacy=true` 可回退到原实现。
4. 测试覆盖"突发流量耗尽令牌"、"10 分钟后冷 IP 被驱逐" 两类用例。
5. `go test -race ./internal/listener/udp/...` 全绿。

---

## T-11 Balancer 可选 CONNECT+GET 204 测速（对应 design §8）

**类别**：feat

**涉及文件**：
- `internal/chain/balancer.go`
- `internal/chain/` 下新增 `probe.go`（或合并到 `balancer.go`）
- `internal/subscribe/connect_test_node.go`（改为调用统一 probe 函数）
- `internal/chain/balancer_test.go`（新增或扩展）

**预估规模**：M

**依赖**：无（对 session cache 无强依赖，但同时启用收益更大）

**验证方式**：
- `go test ./internal/chain/... ./internal/subscribe/...`
- 人工：指定 `probe_url` 后观察 balancer 日志，确认每轮测速走完整 CONNECT + 204 请求。

**风险**：
- 引入周期性探测流量；
- 回退开关：默认 `CheckURL == ""` 即走 Handshake-only。

**验收清单**：
1. `BalancerRoute` 支持可选 `CheckURL` 字段；为空时行为不变。
2. `testAll` 在 `CheckURL` 非空时通过统一 `probe` 函数（与 subscribe 共享）完成测速。
3. 新增 URL 参数 `probe_url` / env `FORWARD_BALANCER_PROBE_URL`。
4. `internal/subscribe/connect_test_node.go` 的 `testNodeBestLatency` 改为调用同一 probe 函数，行为保持与之前一致。
5. `go test ./internal/chain/... ./internal/subscribe/...` 全绿。

---

## T-12 UDP 批量收发 `recvmmsg` / `sendmmsg` 可行性原型（对应 design §12）

**类别**：chore + feat（仅原型）

**涉及文件**：
- `internal/listener/udp/batch_linux.go`（新增，`//go:build linux`）
- `internal/listener/udp/batch_other.go`（新增，非 linux 平台空实现）
- `internal/listener/udp/listener.go`（在 `listenLoop` 中根据 `l.md.udpBatch` 与平台判断分发）
- `internal/listener/udp/listener_test.go`

**预估规模**：L

**依赖**：T-10（共享 `parseMetadata` 变更）

**验证方式**：
- `go test ./internal/listener/udp/...`（默认 `udp_batch=false`，不改变现有行为）
- 人工（仅 Linux）：`udp_batch=true` 启动，`iperf3 -u -b 1G -l 1200` 对比 PPS；`perf stat -e 'syscalls:sys_enter_recvfrom,syscalls:sys_enter_recvmmsg'` 观察 syscall 分布。
- Linux 不支持时自动降级路径必须走 `ReadFrom`，有单测断言。

**风险**：
- 内核 / glibc 兼容性差异大；
- 回退开关：默认 `udp_batch=false`；开启失败自动降级。

**验收清单**：
1. 新增 `batch_linux.go` / `batch_other.go` 结构完整，跨平台编译通过。
2. `Listener.listenLoop` 在 `udp_batch=true` 且 `runtime.GOOS == "linux"` 时调用批量接口，失败降级。
3. URL 参数 `udp_batch=true` 可显式启用。
4. Linux 平台单测覆盖"启用批量后收包顺序保持"、"降级路径仍然工作" 两类用例；非 Linux 平台不新增测试。
5. `go test ./internal/listener/udp/...` 在 darwin / linux 两个平台 CI 中均全绿（实施阶段）。
6. 提交说明中明确标注"原型 / opt-in"，未来如进入默认启用需单独 RFC。

---

## 全量验证建议

本批任务合并前建议在实施环境（可联网、能 `go mod download`）执行：

1. `go vet ./...`
2. `gofmt -l ./` 应无输出
3. `go build ./...`
4. `go test ./...`
5. `go test -race ./base/... ./internal/...`
6. Bench 抽样：`go test -bench . -benchmem -run '^$' ./base/io/net/ ./base/transport/pht/ ./internal/hysteria2/ ./internal/listener/udp/`
7. e2e：`go test ./tests/...`，重点跑 `proxy_e2e_test.go`、`hysteria2_e2e_test.go`、`reverse_e2e_test.go`、`reality_e2e_test.go`、`listener_h3_pht_server_test.go`。
8. 文档：每个任务若涉及用户可见参数，必须在 `README.md` 的"新增可选参数"章节添加一行说明，保持参数名、默认值、回退开关三项齐全。
