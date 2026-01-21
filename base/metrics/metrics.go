// Package metrics 提供可观测性指标收集能力
// 可后续集成 prometheus、expvar 或其他指标系统
package metrics

import (
	"sync/atomic"
	"time"
)

// Metrics 全局指标收集器
type Metrics struct {
	activeConnections   int64
	totalConnections    int64
	rejectedConnections int64

	// UDP 会话指标
	activeUDPSessions int64
	totalUDPSessions  int64

	// 认证指标
	authFailCount    int64
	authSuccessCount int64

	// 延迟指标（纳秒）
	dialLatencyNs      int64
	handshakeLatencyNs int64

	// PHT 隧道指标
	phtActiveStreams int64
}

// 全局实例
var Global = &Metrics{}

// IncActiveConnections 增加活跃连接数
func (m *Metrics) IncActiveConnections() {
	atomic.AddInt64(&m.activeConnections, 1)
	atomic.AddInt64(&m.totalConnections, 1)
}

// DecActiveConnections 减少活跃连接数
func (m *Metrics) DecActiveConnections() {
	atomic.AddInt64(&m.activeConnections, -1)
}

// ActiveConnections 返回当前活跃连接数
func (m *Metrics) ActiveConnections() int64 {
	return atomic.LoadInt64(&m.activeConnections)
}

// TotalConnections 返回总连接数
func (m *Metrics) TotalConnections() int64 {
	return atomic.LoadInt64(&m.totalConnections)
}

// IncRejectedConnections 增加拒绝连接数
func (m *Metrics) IncRejectedConnections() {
	atomic.AddInt64(&m.rejectedConnections, 1)
}

// RejectedConnections 返回拒绝连接数
func (m *Metrics) RejectedConnections() int64 {
	return atomic.LoadInt64(&m.rejectedConnections)
}

// IncActiveUDPSessions 增加活跃 UDP 会话数
func (m *Metrics) IncActiveUDPSessions() {
	atomic.AddInt64(&m.activeUDPSessions, 1)
	atomic.AddInt64(&m.totalUDPSessions, 1)
}

// DecActiveUDPSessions 减少活跃 UDP 会话数
func (m *Metrics) DecActiveUDPSessions() {
	atomic.AddInt64(&m.activeUDPSessions, -1)
}

// ActiveUDPSessions 返回当前活跃 UDP 会话数
func (m *Metrics) ActiveUDPSessions() int64 {
	return atomic.LoadInt64(&m.activeUDPSessions)
}

// IncAuthFail 增加认证失败次数
func (m *Metrics) IncAuthFail() {
	atomic.AddInt64(&m.authFailCount, 1)
}

// AuthFailCount 返回认证失败次数
func (m *Metrics) AuthFailCount() int64 {
	return atomic.LoadInt64(&m.authFailCount)
}

// IncAuthSuccess 增加认证成功次数
func (m *Metrics) IncAuthSuccess() {
	atomic.AddInt64(&m.authSuccessCount, 1)
}

// RecordDialLatency 记录拨号延迟
func (m *Metrics) RecordDialLatency(d time.Duration) {
	atomic.StoreInt64(&m.dialLatencyNs, d.Nanoseconds())
}

// DialLatency 返回最近一次拨号延迟
func (m *Metrics) DialLatency() time.Duration {
	return time.Duration(atomic.LoadInt64(&m.dialLatencyNs))
}

// Snapshot 返回当前指标快照
func (m *Metrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"active_connections":   m.ActiveConnections(),
		"total_connections":    m.TotalConnections(),
		"rejected_connections": m.RejectedConnections(),
		"active_udp_sessions":  m.ActiveUDPSessions(),
		"auth_fail_count":      m.AuthFailCount(),
		"dial_latency_ns":      atomic.LoadInt64(&m.dialLatencyNs),
		"handshake_latency_ns": atomic.LoadInt64(&m.handshakeLatencyNs),
	}
}
