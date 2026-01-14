最高优先级问题（P0）：可被利用/导致崩溃/数据泄露（给出复现条件与修复建议）
P0-1：敏感信息被日志泄漏（VLESS UUID 分享链接、REALITY 私钥/敏感 Query）→ 直接导致未授权使用/密钥暴露

触发点/复现：

启动 VLESS+REALITY 监听：
-L "vless+reality://<uuid>@:443?dest=...&sni=...&sid=...&pbk=..."
源码 internal/listener/vless/listener.go 在 Run() 里 以 Info 级别直接打印完整 Shadowrocket URL（包含 UUID、pbk、sid、sni 等）。UUID 本质就是认证密钥——日志一旦被采集（容器 stdout、systemd journal、ELK），等同“把钥匙贴在门上”。

REALITY 私钥泄漏路径：

internal/listener/vless/register.go 从 URL Query 读取 key（注意：这里的 key 是 REALITY 私钥字符串，不是文件路径，见 internal/utils/crypto/x25519.go 的 Base64 解码逻辑）。

internal/endpoint/endpoint.go 的 Endpoint.String() 会把 RawQuery 原样拼回去（只打码 password，不打码 query）。

internal/app/app.go 中监听器异常时会 Logger.Error("Listener %s stopped", c.Listen.String(), ...) ——一旦监听启动失败（端口占用、权限不足、证书错误等），就会把 key=... 原样打进日志。

影响：

数据泄露级别：P0。泄漏 UUID/私钥意味着攻击者可直接连接你的 VLESS 服务；泄漏 REALITY 私钥更严重（等于服务端身份密钥泄漏）。

这类泄漏通常难以追回（日志已被集中系统收集/备份）。

根因定位：

internal/listener/vless/listener.go: Info("...Shadowrocket URL: %s", l.shadowrocketURL)

internal/endpoint/endpoint.go: String() 拼接 RawQuery 不做脱敏

internal/app/app.go: 监听器错误日志打印 Listen.String()

修复建议（务必默认安全）：

保留 Info 日志输出任何“可直接用于连接的分享链接/凭据”。

为 Endpoint 增加 RedactedString()（或让 String() 默认脱敏），对 query 做白名单或黑名单脱敏，例如：

黑名单键：key, private_key, pbk, sid, uuid, token, psk, password, secret, ca（看你策略）；

app.go 的错误日志不要打印 Listen.String()，改为只打印 scheme://host:port（Address()），必要时加 NodeName 方便定位。

P0-2：VLESS 入口可被“慢速握手/连接洪泛”DoS，且存在潜在 nil/unsafe 崩溃点

触发点/复现：

慢速握手 DoS（Slowloris 类）
VLESS listener 使用 internet.ListenTCP(... callback ...)，每个连接都会 go l.handleConn(ctx, conn)（internal/listener/vless/listener.go）。
handleConn() 里 readRequest() 从 conn 读取首包，但没有任何 read deadline（对比 SOCKS5/Reverse 都设置了 DefaultHandshakeTimeout）。
攻击方式：攻击者大量建立 TCP 连接，每条只发极少字节/缓慢发字节 → 连接与 goroutine 长时间占用，导致 FD/goroutine 耗尽。

潜在崩溃点（unsafe 取 xtls buffer）
internal/handler/vless/handler.go 的 xtlsBuffers() 用 reflect + unsafe.Pointer 访问非导出字段 input/rawInput，但不像 dialer 侧那样检查是否为 nil（dialer 侧有 if input==nil || rawInput==nil 的保护；handler 侧没有）。
如果底层连接类型/布局变化、或字段未初始化，可能引发 panic 或传入 nil 导致后续崩溃。

配置导致启动即 panic
internal/listener/vless/register.go：user := listen.User; username := user.Username()
当 listen URL 未包含 userinfo（比如 vless+reality://:443?... 或忘写 UUID），listen.User == nil 会 直接 panic，属于“配置错误导致进程崩溃”的 P0 稳定性问题。

影响：

公网暴露时非常现实：远程无需认证即可 DoS（连接层就能压死）。

unsafe 反射在依赖升级时可能触发生产崩溃（尤其你依赖 xray-core 这种内部结构变化风险较高的项目）。

根因定位：

internal/listener/vless/listener.go: 无连接并发限制；每连接 goroutine

internal/handler/vless/handler.go: 握手读取无 deadline；unsafe buffer 取值缺少 nil 防护

internal/listener/vless/register.go: listen.User nil 未处理

修复建议：

统一握手超时：在 VLESS handleConn 一开始 conn.SetReadDeadline(now+HandshakeTimeout)，握手成功后清理 deadline。

连接并发上限：给 VLESS listener 加 semaphore（类似 TCP/UDP listener 用的 DefaultMaxConnections），超过直接拒绝/延迟 accept。

修正 nil panic：listen.User == nil 时生成 UUID 或返回可读错误（不要 panic）。

unsafe 防护与降级策略：

handler 的 xtlsBuffers() 做 nil 检查，不满足则降级为普通 reader；

明确版本兼容策略：锁定 xray-core 版本 + CI 编译/集成测试；或尽量使用上游公开 API（避免读私有字段）。

P0-3：UDP 相关功能可被用于 UDP 反射/放大、端口扫描、以及无上限会话导致资源耗尽

这一条包含三个“可被远程滥用”的高危面：

3.1 SOCKS5 UDP ASSOCIATE：未校验 UDP 数据报来源 IP + 目标地址由报文头指定 → 可被滥用为开放 UDP 代理/反射器

复现思路：

部署 forward -L socks5://0.0.0.0:1080（无认证或弱认证）。

攻击者建立 TCP SOCKS5 会话并请求 UDP ASSOCIATE，拿到服务端 UDP relay 端口。

攻击者向该 relay 端口发送 UDP 报文（SOCKS5 UDP 格式），在 UDP 头里指定任意 dst host:port。

因为服务端 handleUDP() 不校验 UDP packet 的 src.IP 是否等于 TCP conn.RemoteAddr 的 IP，攻击者可以从别处（或伪造源 IP）注入报文，诱导服务端对任意目标发包，回包再转发给伪造源 → 反射/扫描。

根因定位：

internal/handler/socks5/handler.go 的 UDP relay：没有绑定/校验“关联 TCP 连接的对端 IP”，src 直接来自 ReadFromUDP。

修复建议：

SOCKS5 UDP relay 必做：只接受 src.IP == TCP 关联连接的 Remote IP（很多实现就是这样防滥用）。必要时也可绑定端口。

对 UDP ASSOCIATE 增加 session token/cookie（可选）进一步防注入。

3.3 UDP Session 数量无上限（SOCKS5 UDP、UDP forward）→ 轻松打爆 FD/goroutine/内存

复现：

SOCKS5 UDP：不断用不同 (src addr, dest) 组合发送报文；

UDP forward：不断伪造不同 src 触发 getOrCreateSession；
两者都会无限增长 map + goroutine（尤其 SOCKS5 peerSession 每个都有 go readUpstream()）。

根因定位：

internal/handler/socks5/handler.go: peerSessions map 无上限（虽然有 idle 清理，但可被持续制造新 key 绕过）

internal/handler/udp/handler.go: sessions map 无上限；config.DefaultMaxUDPSessions 常量存在但未使用

修复建议：

实现硬上限：全局、每监听器、每源 IP、每 TCP 会话（SOCKS5 UDP）分别限制。

淘汰策略：LRU + idle；超过上限直接 drop（并打采样日志）。

为 UDP 上游 dial 加限速/失败缓存，避免被用来“拨号洪泛”。

P0-4：Reverse Server（bind=true）缺少强制安全闸门：可远程让服务器对外任意开端口，工具化为“远程端口暴露/扫描平台”

复现：

公网启动：forward -L "tls://0.0.0.0:443?bind=true"（无 user:pass）。

任何人连接后按 reverse 协议发起 SOCKS5 BIND/UDP ASSOCIATE，服务端会 net.Listen("tcp", host:port) 或 net.ListenUDP 去绑定端口（internal/handler/reverse/server.go）。

这允许攻击者在你的公网机器上：

开任意对外端口（22/3389/3306/…），引入合规与入侵面；

作为端口扫描/反连跳板；

结合 UDP 绑定成为反射器。

根因定位：

internal/handler/reverse/server.go: 对 bind host/port 无 allowlist；listener 层也无“公网绑定必须认证”的硬限制

修复建议：

bind=true 强制要求认证（没有凭据就拒绝启动）。

增加 bind 约束：

Reverse listener 增加连接并发限制与握手超时（它有超时，但没有并发限制）。

中优先级问题（P1）：稳定性/兼容性/可维护性问题

P1-2：TLS 上游 HTTP CONNECT Dialer 的 ALPN 配置可能协商出 h2，导致你对上游发 HTTP/1.1 CONNECT 失败（协议不匹配）

位置： internal/dialer/http/http.go
当 forward scheme 为 https/tls 时，dialer 用 tls.Client 并设置 NextProtos: []string{"h2","http/1.1"}，但随后发送的是明文 HTTP/1.1 CONNECT。
若上游（尤其是另一个 forward 实例的 HTTPS 监听）支持 h2，ALPN 很可能协商为 h2，上游进入 HTTP/2 模式后会把你的 CONNECT ... 当垃圾流量 → 连接失败/不可用。

修复：

实现真正的 HTTP/2 CONNECT（复杂度更高）。

P1-3：hop-by-hop 头处理不完整：把 Trailer 写成了 Trailers，且会直接移除 Upgrade 导致 WebSocket 等协议不可用

位置： internal/handler/http/handler.go

hopByHop map 包含 "Trailers" 而不是标准头 "Trailer"

同时删除 Upgrade/Connection 等，会让 websocket、部分长连接升级协议无法代理

修复：

修正为 RFC 7230 的标准 hop-by-hop 列表（至少改对 Trailer）。

如果希望支持 Upgrade（WebSocket）：需要专门实现 upgrade tunnel（通常使用 Hijack/双向拷贝）。

P1-4：MMDB 自动下载无超时/无大小限制/允许跟随重定向 → 启动卡死/磁盘写爆/供应链风险

位置： internal/route/route.go ensureMMDB()

http.Get 默认无 timeout，可能无限挂住

ReadFrom(resp.Body) 无大小限制，可能写爆磁盘

虽然检查 link 前缀必须 https://，但默认 client 会跟随 redirect，可能被引到非 https（或引到巨大文件）

修复：

改用 http.Client{Timeout: ...}，并传入 context

限制最大下载大小（50MB）

禁止跨 scheme redirect，或校验最终 URL 仍为 https + allowlist 域名

P1-5：inet.Bidirectional 的半关闭逻辑对不支持 CloseWrite() 的 net.Conn 可能导致“提前全关闭”→ 数据截断/协议异常

位置： internal/io/net/copy.go
closeWrite(dst)：若 dst 不支持 CloseWrite，会直接 Close()。
这在 yamux stream、QUIC stream wrapper 等实现上可能导致：一侧 copy 完成后把另一侧整条连接关掉，另一方向的 copy 还没传完就被切断。

修复：

CloseWrite 不可用时应 no-op（不做半关闭），让双向 copy 自然结束后统一 Close；或用更细粒度的关闭策略。

P1-6：HTTP/HTTP3 监听的超时/MaxHeaderBytes 写死常量，配置项 ReadHeaderTimeout/MaxHeaderBytes 实际未生效

位置： internal/listener/http/listener.go、internal/listener/http3/listener.go

server 使用 config.DefaultReadHeaderTimeout/DefaultMaxHeaderBytes，忽略 cfg 中的可配置字段。
修复： 用 cfg.ReadHeaderTimeout/cfg.MaxHeaderBytes（defaults 已在 ApplyDefaults 设置）。

P1-7：端口转发“支持代理链”的文档描述与实现不一致（PortForward 模式下 Dialer 被强制 direct）

位置： internal/dialer/dialer.go
只要 cfg.Mode == ModePortForward，dialer.New 直接返回 direct，忽略 cfg.Forward 代理链。
如果你的产品目标确实要“TCP/UDP 端口转发支持代理链”，需要重新梳理：

明确文档：端口转发仅 direct；代理链仅用于 HTTP/SOCKS5 代理模式/反向模式。

P1-8：QUIC Reverse Listener 只 AcceptStream 一次，若对端恶意创建大量 stream 可能导致资源占用

位置： internal/listener/reverse/listener.go handleQUICConn()
只接收一个 stream，不处理其他 stream。
修复： 明确协议：只允许 1 stream，其余立即拒绝/读掉并关闭；或循环 accept 并限制数量。（需要确认只接受一个 stream 后会不会影响多个客户端同时连接 reverse server，如果影响，不做这个修复）

低优先级建议（P2）：风格、结构、可测试性
P2-1：统一错误处理与错误分类（避免 strings.Contains(err.Error(), "...")）

多处用字符串判断 “use of closed network connection”。建议用：

errors.Is(err, net.ErrClosed) / context.Canceled / os.ErrDeadlineExceeded 等；

自定义 sentinel error 包装。

P2-2：上下文与超时策略统一化

目前 SOCKS5/Reverse 有握手超时，VLESS 没有；MMDB 下载没有；TLS dial（reverse client）不响应 ctx cancel。建议：

定义 cfg.HandshakeTimeout / cfg.IOIdleTimeout / cfg.DNSResolveTimeout；

所有入口协议统一用同一套策略。

P2-3：可观测性

建议增加（至少 debug/metrics 可选）：

当前连接数、每协议连接数、每 IP 连接数；

UDP session 数、被 drop 的原因统计（超限/非法源/非法目的）；

route 命中统计（规则命中、DIRECT/PROXY/REJECT 分布）；

reverse tunnel 状态、yamux stream 数。

P2-4：依赖注入/接口边界

目前 handler 里直接 new http.Client、route store 直接下载 mmdb。建议：

把 HTTPClient、MMDBDownloader 抽成接口，便于单测与离线部署；

dialer/route 的缓存与更新策略可单独封装。

P2-5：Endpoint 表达与安全默认

Endpoint.String() 建议只用于 debug（且默认脱敏），另提供 Endpoint.SafeString() 用于日志；避免未来新增 query 参数（token/key）再次泄漏。
