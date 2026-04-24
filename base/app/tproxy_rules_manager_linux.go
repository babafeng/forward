//go:build linux

package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"forward/base/logging"
	"forward/internal/config"
	"forward/internal/netmark"
)

const (
	managedTProxyRulesServiceName = "forward-tproxy-rules.service"
	managedTProxyRulesUnitPath    = "/etc/systemd/system/" + managedTProxyRulesServiceName
)

type linuxDistroKind string

const (
	linuxDistroOther   linuxDistroKind = "other"
	linuxDistroOpenWRT linuxDistroKind = "openwrt"
	linuxDistroDebian  linuxDistroKind = "debian"
)

type ownerMatchMode string

const (
	ownerMatchUID ownerMatchMode = "uid"
	ownerMatchGID ownerMatchMode = "gid"
)

type ownerMatch struct {
	Mode  ownerMatchMode
	Value string
}

func (o ownerMatch) IPTablesArg() string {
	switch o.Mode {
	case ownerMatchGID:
		return "--gid-owner " + o.Value
	default:
		return "--uid-owner " + o.Value
	}
}

func (o ownerMatch) String() string {
	return string(o.Mode) + ":" + o.Value
}

func (o ownerMatch) Enabled() bool {
	return o.Mode == ownerMatchGID && strings.TrimSpace(o.Value) != ""
}

type osReleaseInfo struct {
	ID     string
	IDLike []string
	Name   string
}

type commandRunner func(name string, args ...string) error

type fileWriter func(name string, data []byte, perm os.FileMode) error

type fileRemover func(name string) error

type tproxyRulesManager struct {
	logger      *logging.Logger
	serviceName string
	unitPath    string
	tproxyPort  int
	ownerMatch  ownerMatch
	run         commandRunner
	writeFile   fileWriter
	removeFile  fileRemover
}

func setupManagedTProxyRulesPlatform(cfg config.Config) (func(), error) {
	netmark.EnableSelfBypassMark()
	disableNetmark := func() {
		netmark.DisableSelfBypassMark()
	}

	distro, info, err := detectLinuxDistro(os.ReadFile, os.Stat)
	if err != nil {
		disableNetmark()
		return nil, err
	}

	switch distro {
	case linuxDistroOpenWRT:
		if cfg.Logger != nil {
			cfg.Logger.Info("Skip managed tproxy rules on OpenWrt")
		}
		return disableNetmark, nil
	case linuxDistroDebian:
		owner, err := resolveOwnerMatch()
		if err != nil {
			disableNetmark()
			return nil, err
		}
		mgr := tproxyRulesManager{
			logger:      cfg.Logger,
			serviceName: managedTProxyRulesServiceName,
			unitPath:    managedTProxyRulesUnitPath,
			tproxyPort:  cfg.TProxy.Port,
			ownerMatch:  owner,
			run:         runSystemCommand,
			writeFile:   os.WriteFile,
			removeFile:  os.Remove,
		}
		if err := mgr.Setup(); err != nil {
			disableNetmark()
			return nil, err
		}
		if cfg.Logger != nil {
			cfg.Logger.Info("Managed tproxy rules enabled via %s (distro=%s, owner=%s)", managedTProxyRulesServiceName, distroLabel(info), owner.String())
		}
		return func() {
			defer disableNetmark()
			if err := mgr.Cleanup(); err != nil && cfg.Logger != nil {
				cfg.Logger.Warn("Managed tproxy rules cleanup failed: %v", err)
			}
		}, nil
	default:
		if cfg.Logger != nil {
			cfg.Logger.Info("Skip managed tproxy rules on unsupported Linux distro: %s", distroLabel(info))
		}
		return disableNetmark, nil
	}
}

func (m tproxyRulesManager) Setup() error {
	if m.tproxyPort <= 0 {
		return fmt.Errorf("managed tproxy rules requires a positive tproxy port")
	}
	if m.logger != nil {
		m.logger.Info("Registering %s for transparent proxy rules (port=%d, owner=%s)", m.serviceName, m.tproxyPort, m.ownerMatch.String())
	}
	if err := m.resetExistingUnit(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.unitPath), 0o755); err != nil {
		return fmt.Errorf("create systemd unit dir: %w", err)
	}
	if m.logger != nil {
		m.logger.Info("Writing systemd unit %s", m.unitPath)
	}
	if err := m.writeFile(m.unitPath, []byte(renderTProxyRulesUnit(m.tproxyPort, m.ownerMatch)), 0o644); err != nil {
		return fmt.Errorf("write systemd unit %s: %w", m.unitPath, err)
	}
	if err := m.systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("systemd daemon-reload: %w", err)
	}
	if err := m.systemctl("reset-failed", m.serviceName); err != nil && !shouldIgnoreSystemctlNotLoaded(err) && m.logger != nil {
		m.logger.Warn("systemctl reset-failed %s: %v", m.serviceName, err)
	}
	if m.logger != nil {
		m.logger.Info("Starting %s", m.serviceName)
	}
	if err := m.systemctl("start", m.serviceName); err != nil {
		return fmt.Errorf("systemctl start %s: %w", m.serviceName, err)
	}
	if m.logger != nil {
		m.logger.Info("%s started", m.serviceName)
	}
	return nil
}

func (m tproxyRulesManager) Cleanup() error {
	var errs []error
	if m.logger != nil {
		m.logger.Info("Removing %s", m.serviceName)
	}
	if err := m.systemctl("stop", m.serviceName); err != nil {
		errs = append(errs, fmt.Errorf("systemctl stop %s: %w", m.serviceName, err))
	}
	if err := m.systemctl("disable", m.serviceName); err != nil && m.logger != nil {
		m.logger.Warn("systemctl disable %s: %v", m.serviceName, err)
	}
	if err := m.removeFile(m.unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove unit %s: %w", m.unitPath, err))
	}
	if err := m.systemctl("daemon-reload"); err != nil {
		errs = append(errs, fmt.Errorf("systemd daemon-reload: %w", err))
	}
	if err := m.systemctl("reset-failed", m.serviceName); err != nil && !shouldIgnoreSystemctlNotLoaded(err) && m.logger != nil {
		m.logger.Warn("systemctl reset-failed %s: %v", m.serviceName, err)
	}
	if len(errs) == 0 && m.logger != nil {
		m.logger.Info("%s removed", m.serviceName)
	}
	return errors.Join(errs...)
}

func (m tproxyRulesManager) resetExistingUnit() error {
	if _, err := os.Stat(m.unitPath); err == nil && m.logger != nil {
		m.logger.Info("Existing %s found, recreating it", m.serviceName)
	}
	if err := m.systemctl("stop", m.serviceName); err != nil && m.logger != nil {
		m.logger.Debug("systemctl stop %s before recreate: %v", m.serviceName, err)
	}
	if err := m.systemctl("disable", m.serviceName); err != nil && m.logger != nil {
		m.logger.Debug("systemctl disable %s before recreate: %v", m.serviceName, err)
	}
	if err := m.removeFile(m.unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale unit %s: %w", m.unitPath, err)
	}
	if err := m.systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("systemd daemon-reload: %w", err)
	}
	if err := m.systemctl("reset-failed", m.serviceName); err != nil && !shouldIgnoreSystemctlNotLoaded(err) && m.logger != nil {
		m.logger.Debug("systemctl reset-failed %s before recreate: %v", m.serviceName, err)
	}
	return nil
}

func (m tproxyRulesManager) systemctl(args ...string) error {
	if m.run == nil {
		return fmt.Errorf("systemctl runner is not configured")
	}
	return m.run("systemctl", args...)
}

func renderTProxyRulesUnit(port int, owner ownerMatch) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=forward tproxy rules service\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=oneshot\n")
	b.WriteString("RemainAfterExit=yes\n")
	writeUnitExecs(&b, "ExecStart", port, owner)
	writeUnitExecs(&b, "ExecStop", port, owner)
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

func writeUnitExecs(b *strings.Builder, key string, port int, owner ownerMatch) {
	quotedPort := strconv.Itoa(port)
	lines := []string{
		"/bin/sh -c 'iptables -t mangle -D OUTPUT -j GO_MARK 2>/dev/null || true'",
		"/bin/sh -c 'iptables -t mangle -F GO_MARK 2>/dev/null || true'",
		"/bin/sh -c 'iptables -t mangle -X GO_MARK 2>/dev/null || true'",
		"/bin/sh -c 'iptables -t mangle -D PREROUTING -j GO_TPROXY 2>/dev/null || true'",
		"/bin/sh -c 'iptables -t mangle -F GO_TPROXY 2>/dev/null || true'",
		"/bin/sh -c 'iptables -t mangle -X GO_TPROXY 2>/dev/null || true'",
		"/bin/sh -c 'ip rule del fwmark 1 lookup 100 2>/dev/null || true'",
		"/bin/sh -c 'ip route flush table 100 2>/dev/null || true'",
	}
	if key == "ExecStart" {
		lines = append(lines,
			"/sbin/ip rule add fwmark 1 lookup 100",
			"/sbin/ip route add local 0.0.0.0/0 dev lo table 100",
			"/sbin/iptables -t mangle -N GO_MARK",
			"/sbin/iptables -t mangle -A GO_MARK -m mark --mark "+strconv.Itoa(netmark.SelfBypassMark)+" -j RETURN",
			"/sbin/iptables -t mangle -A GO_MARK -d 127.0.0.0/8 -j RETURN",
			"/sbin/iptables -t mangle -A GO_MARK -d 255.255.255.255/32 -j RETURN",
			"/sbin/iptables -t mangle -A GO_MARK -d 192.168.0.0/16 -j RETURN",
			"/sbin/iptables -t mangle -A GO_MARK -d 10.0.0.0/8 -j RETURN",
			"/sbin/iptables -t mangle -A GO_MARK -d 172.16.0.0/12 -j RETURN",
			"/sbin/iptables -t mangle -A GO_MARK -p tcp -j MARK --set-mark 1",
			"/sbin/iptables -t mangle -A GO_MARK -p udp -j MARK --set-mark 1",
			"/sbin/iptables -t mangle -A OUTPUT -j GO_MARK",
			"/sbin/iptables -t mangle -N GO_TPROXY",
			"/sbin/iptables -t mangle -A GO_TPROXY -m mark --mark 1 -p tcp -j TPROXY --on-port "+quotedPort+" --tproxy-mark 1",
			"/sbin/iptables -t mangle -A GO_TPROXY -m mark --mark 1 -p udp -j TPROXY --on-port "+quotedPort+" --tproxy-mark 1",
			"/sbin/iptables -t mangle -A PREROUTING -j GO_TPROXY",
		)
		if owner.Enabled() {
			lines = insertAfterGO_MARKCreate(lines, "/sbin/iptables -t mangle -A GO_MARK -m owner "+owner.IPTablesArg()+" -j RETURN")
		}
	}
	for _, line := range lines {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(line)
		b.WriteString("\n")
	}
}

func insertAfterGO_MARKCreate(lines []string, line string) []string {
	for i, existing := range lines {
		if strings.Contains(existing, "-N GO_MARK") {
			return append(lines[:i+1], append([]string{line}, lines[i+1:]...)...)
		}
	}
	return append(lines, line)
}

func detectLinuxDistro(readFile func(string) ([]byte, error), stat func(string) (os.FileInfo, error)) (linuxDistroKind, osReleaseInfo, error) {
	if stat != nil {
		if _, err := stat("/etc/openwrt_release"); err == nil {
			return linuxDistroOpenWRT, osReleaseInfo{ID: "openwrt", Name: "OpenWrt"}, nil
		}
	}
	data, err := readFile("/etc/os-release")
	if err != nil {
		return linuxDistroOther, osReleaseInfo{}, fmt.Errorf("read /etc/os-release: %w", err)
	}
	info := parseOSRelease(data)
	if info.ID == "openwrt" || containsToken(info.IDLike, "openwrt") {
		return linuxDistroOpenWRT, info, nil
	}
	if info.ID == "debian" || info.ID == "ubuntu" || info.ID == "kali" || containsToken(info.IDLike, "debian") {
		return linuxDistroDebian, info, nil
	}
	return linuxDistroOther, info, nil
}

func parseOSRelease(data []byte) osReleaseInfo {
	info := osReleaseInfo{}
	for _, rawLine := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSpace(string(rawLine))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToUpper(key))
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		switch key {
		case "ID":
			info.ID = strings.ToLower(value)
		case "ID_LIKE":
			info.IDLike = splitReleaseTokens(value)
		case "NAME":
			info.Name = value
		}
	}
	return info
}

func splitReleaseTokens(raw string) []string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(raw)))
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func containsToken(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}

func distroLabel(info osReleaseInfo) string {
	if strings.TrimSpace(info.Name) != "" {
		return info.Name
	}
	if strings.TrimSpace(info.ID) != "" {
		return info.ID
	}
	return "linux"
}

func resolveOwnerMatch() (ownerMatch, error) {
	if grp, err := user.LookupGroupId(strconv.Itoa(os.Getegid())); err == nil && grp != nil {
		if strings.EqualFold(strings.TrimSpace(grp.Name), "go-proxy") {
			return ownerMatch{Mode: ownerMatchGID, Value: "go-proxy"}, nil
		}
	}
	return ownerMatch{Mode: ownerMatchUID, Value: strconv.Itoa(os.Geteuid())}, nil
}

func runSystemCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
}

func shouldIgnoreSystemctlNotLoaded(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not loaded")
}
