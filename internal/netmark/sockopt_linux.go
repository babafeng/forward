//go:build linux

package netmark

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// 目标接收/发送缓冲区大小。高 BDP 链路（跨国 + 千兆级）默认 TCP 窗口
// 需要 MB 级才能跑满带宽；Linux 一般 tcp_rmem/tcp_wmem max 给到 6 MB，
// net.core.rmem_max 视发行版而异（Ubuntu 默认 208 KB）。这里是 best
// effort：SO_RCVBUF/SO_SNDBUF 受 rmem_max/wmem_max 限制，失败静默忽略。
const desiredSocketBuf = 4 << 20 // 4 MB

func tuneFD(fd int) {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, desiredSocketBuf)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, desiredSocketBuf)
}

// TuneTCPConn 在 Linux 上把给定 TCP 连接的收发缓冲区拉到 desiredSocketBuf。
// 任何失败都静默忽略（不影响业务）。
func TuneTCPConn(c *net.TCPConn) {
	if c == nil {
		return
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) { tuneFD(int(fd)) })
}

// TuneUDPConn 在 Linux 上把给定 UDP PacketConn 的收发缓冲区拉到
// desiredSocketBuf。接受任意 net.PacketConn（需要实现 syscall.Conn），
// 失败静默忽略。
func TuneUDPConn(c net.PacketConn) {
	if c == nil {
		return
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) { tuneFD(int(fd)) })
}
