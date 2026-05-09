package config

import (
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC 默认窗口与超时。quic-go 原生默认值对高 BDP 链路（跨国 + 高带宽）
// 严重欠跑：默认 InitialStreamReceiveWindow=512KB、MaxStreamReceiveWindow=6MB、
// InitialConnectionReceiveWindow=512KB、MaxConnectionReceiveWindow=15MB。
//
// 这里统一拉到 client/server 都一致的更大窗口，作为工厂基线；调用方可以
// 在基线之上再根据 metadata override（仅非零值覆盖，保持向后兼容）。
const (
	quicInitialStreamReceiveWindow     = 2 << 20  // 2 MB
	quicMaxStreamReceiveWindow         = 16 << 20 // 16 MB
	quicInitialConnectionReceiveWindow = 4 << 20  // 4 MB
	quicMaxConnectionReceiveWindow     = 64 << 20 // 64 MB
	quicKeepAlivePeriod                = 15 * time.Second
	quicMaxIdleTimeout                 = 30 * time.Second
)

// NewClientQUICConfig 返回一个带窗口/超时基线的客户端 QUIC Config。
//
// 客户端主动发 PING（KeepAlivePeriod），让 NAT 不至于超时闭掉 UDP 映射。
//
// 注意：quic-go 原生默认 KeepAlivePeriod=0（不发 PING），本项目基线是
// 15s；调用方的 metadata override 使用 `> 0` 门槛，因此 metadata 传
// 0（或未设）都会保留本基线 15s——即**无法通过 metadata 显式关闭 PING**。
// 对绝大多数跨 NAT 场景这是改进；如果未来有用户反馈需要完全关闭 PING，
// 应通过引入 sentinel 值或专门的配置项来暴露该能力（而非把基线改回 0，
// 那会让多数现有部署退化）。MaxIdleTimeout=30s 与 quic-go 原默认一致，
// 不构成语义变化。
func NewClientQUICConfig() *quic.Config {
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1},
		InitialStreamReceiveWindow:     quicInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicInitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     quicMaxConnectionReceiveWindow,
		KeepAlivePeriod:                quicKeepAlivePeriod,
		MaxIdleTimeout:                 quicMaxIdleTimeout,
	}
}

// NewServerQUICConfig 返回一个带窗口基线的服务端 QUIC Config。
//
// 服务端不设 KeepAlivePeriod（quic-go 默认会在收到 client 的 PING 后
// 回发 PING，手动再主动探活反而浪费带宽）。同时启用 Allow0RTT：客户端
// 如果缓存了 session ticket 可以直接带应用数据上来，省一个 RTT。
func NewServerQUICConfig() *quic.Config {
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1},
		InitialStreamReceiveWindow:     quicInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicInitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     quicMaxConnectionReceiveWindow,
		MaxIdleTimeout:                 quicMaxIdleTimeout,
		Allow0RTT:                      true,
	}
}
