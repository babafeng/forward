package utils

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func ConfuseSSH(channel ssh.Channel, requests <-chan *ssh.Request, conn net.Conn) {
	defer channel.Close()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell", "pty-req", "env":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	remoteAddr := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remoteAddr)
	now := time.Now().UTC()
	timeStr1 := now.Format("Mon Jan 02 15:04:05 MST 2006")
	timeStr2 := now.Format("Mon Jan 02 15:04:05 2006")

	msg := confuseSSHString(timeStr1, timeStr2, host)

	channel.Write([]byte(strings.ReplaceAll(msg, "\n", "\r\n")))
	time.Sleep(time.Second)
}

func confuseSSHString(timeStr1, timeStr2, host string) string {
	msg := fmt.Sprintf(`Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.14.0-1016-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of %s

  System load:  3.03                Temperature:           -273.1 C
  Usage of /:   65.3%% of 192.69GB   Processes:             188
  Memory usage: 46%%                 Users logged in:       0
  Swap usage:   0%%                  IPv4 address for ens5: 172.30.20.10

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

79 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


*** System restart required ***
Last login: %s from %s
-bash: warning: setlocale: LC_ALL: cannot change locale (zh_CN.UTF-8)
`, timeStr1, timeStr2, host)
	return msg
}
