package proto

import (
	"bufio"
	"fmt"
	"io"
	"net"

	socks5util "forward/base/utils/socks5"
)

const (
	socksVer5 = 0x05

	socksMethodNoAuth   = 0x00
	socksMethodUserPass = 0x02

	socksCmdBind         = 0x02
	socksCmdUDPAssociate = 0x03
)

func Socks5ClientBind(conn net.Conn, user, pass, bindHost string, bindPort int, udp bool) error {
	bw := bufio.NewWriter(conn)
	br := bufio.NewReader(conn)

	methods := []byte{socksVer5, 1, socksMethodNoAuth}
	if user != "" || pass != "" {
		methods = []byte{socksVer5, 2, socksMethodNoAuth, socksMethodUserPass}
	}
	if _, err := bw.Write(methods); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != socksVer5 {
		return fmt.Errorf("socks5: bad version %d", ver)
	}
	method, err := br.ReadByte()
	if err != nil {
		return err
	}
	if method == socksMethodUserPass {
		if err := writeUserPassAuth(bw, br, user, pass); err != nil {
			return err
		}
	} else if method == 0xFF {
		return fmt.Errorf("socks5: no acceptable auth methods")
	}

	addr, err := socks5util.EncodeAddr(bindHost, bindPort)
	if err != nil {
		return err
	}

	cmd := byte(socksCmdBind)
	if udp {
		cmd = socksCmdUDPAssociate
	}

	req := make([]byte, 0, 3+len(addr))
	req = append(req, socksVer5, cmd, 0x00)
	req = append(req, addr...)
	if _, err := bw.Write(req); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return err
	}
	if header[0] != socksVer5 {
		return fmt.Errorf("socks5: bad reply version %d", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks5: bind failed rep=0x%02x", header[1])
	}

	_, _, err = socks5util.ReadAddr(br, header[3])
	return err
}

func Socks5ServerBind(br *bufio.Reader, bw *bufio.Writer, userPassCheck func(u, p string) bool) (bindHost string, bindPort int, isUDP bool, err error) {
	head := make([]byte, 2)
	if _, err = io.ReadFull(br, head); err != nil {
		return "", 0, false, err
	}
	if head[0] != socksVer5 {
		return "", 0, false, fmt.Errorf("socks5: bad version %d", head[0])
	}
	nmethods := int(head[1])
	methods := make([]byte, nmethods)
	if _, err = io.ReadFull(br, methods); err != nil {
		return "", 0, false, err
	}

	wantAuth := userPassCheck != nil
	var method byte = socksMethodNoAuth
	if wantAuth {
		method = socksMethodUserPass
	}
	if !socks5util.Contains(methods, method) {
		if _, err := bw.Write([]byte{socksVer5, 0xFF}); err != nil {
			return "", 0, false, fmt.Errorf("write reject: %w", err)
		}
		if err := bw.Flush(); err != nil {
			return "", 0, false, fmt.Errorf("flush reject: %w", err)
		}
		return "", 0, false, fmt.Errorf("socks5: required auth method not offered")
	}
	if _, err := bw.Write([]byte{socksVer5, method}); err != nil {
		return "", 0, false, fmt.Errorf("write method: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return "", 0, false, fmt.Errorf("flush method: %w", err)
	}

	if method == socksMethodUserPass {
		if err = readUserPassAuth(br, bw, userPassCheck); err != nil {
			return "", 0, false, err
		}
	}

	reqHead := make([]byte, 4)
	if _, err = io.ReadFull(br, reqHead); err != nil {
		return "", 0, false, err
	}

	cmd := reqHead[1]
	if cmd != socksCmdBind && cmd != socksCmdUDPAssociate {
		return "", 0, false, fmt.Errorf("socks5: unsupported cmd 0x%02x", cmd)
	}
	isUDP = (cmd == socksCmdUDPAssociate)

	host, port, err := socks5util.ReadAddr(br, reqHead[3])
	if err != nil {
		return "", 0, false, err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if port == 0 {
		return "", 0, false, fmt.Errorf("socks5: invalid bind port 0")
	}
	return host, port, isUDP, nil
}

func WriteBindSuccess(bw *bufio.Writer, host string, port int) error {
	addr, err := socks5util.EncodeAddr(host, port)
	if err != nil {
		return err
	}
	reply := make([]byte, 0, 3+len(addr))
	reply = append(reply, socksVer5, 0x00, 0x00)
	reply = append(reply, addr...)
	if _, err := bw.Write(reply); err != nil {
		return err
	}
	return bw.Flush()
}

func writeUserPassAuth(bw *bufio.Writer, br *bufio.Reader, user, pass string) error {
	req := []byte{0x01, byte(len(user))}
	req = append(req, []byte(user)...)
	req = append(req, byte(len(pass)))
	req = append(req, []byte(pass)...)
	if _, err := bw.Write(req); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(br, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5: auth failed")
	}
	return nil
}

func readUserPassAuth(br *bufio.Reader, bw *bufio.Writer, check func(u, p string) bool) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return err
	}
	if head[0] != 0x01 {
		return fmt.Errorf("socks5: bad auth version %d", head[0])
	}
	ulen := int(head[1])
	ub := make([]byte, ulen)
	if _, err := io.ReadFull(br, ub); err != nil {
		return err
	}
	plen, err := br.ReadByte()
	if err != nil {
		return err
	}
	pb := make([]byte, int(plen))
	if _, err := io.ReadFull(br, pb); err != nil {
		return err
	}

	user := string(ub)
	pass := string(pb)
	status := byte(0x00)
	if !check(user, pass) {
		status = 0x01
	}
	if _, err := bw.Write([]byte{0x01, status}); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if status != 0x00 {
		return fmt.Errorf("socks5: auth failed")
	}
	return nil
}
