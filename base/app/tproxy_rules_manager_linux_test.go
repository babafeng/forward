//go:build linux

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDetectLinuxDistro(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		statOK  bool
		release string
		want    linuxDistroKind
	}{
		{
			name:   "openwrt via release file",
			statOK: true,
			want:   linuxDistroOpenWRT,
		},
		{
			name: "debian family via id like",
			release: `
ID=kali
ID_LIKE="debian"
NAME="Kali GNU/Linux"
`,
			want: linuxDistroDebian,
		},
		{
			name: "other distro",
			release: `
ID=fedora
ID_LIKE="rhel fedora"
NAME=Fedora
`,
			want: linuxDistroOther,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			readFile := func(path string) ([]byte, error) {
				if path != "/etc/os-release" {
					t.Fatalf("unexpected read path: %s", path)
				}
				return []byte(tt.release), nil
			}
			stat := func(path string) (os.FileInfo, error) {
				if path != "/etc/openwrt_release" {
					t.Fatalf("unexpected stat path: %s", path)
				}
				if tt.statOK {
					return fakeFileInfo{name: "openwrt_release"}, nil
				}
				return nil, os.ErrNotExist
			}

			got, _, err := detectLinuxDistro(readFile, stat)
			if err != nil {
				t.Fatalf("detectLinuxDistro error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("detectLinuxDistro = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRenderTProxyRulesUnit(t *testing.T) {
	t.Parallel()

	unit := renderTProxyRulesUnit(12345, ownerMatch{Mode: ownerMatchUID, Value: "0"})
	checks := []string{
		"Description=forward tproxy rules service",
		"RemainAfterExit=yes",
		"--uid-owner 0",
		"TPROXY --on-port 12345 --tproxy-mark 1",
		"ExecStop=/bin/sh -c 'ip route flush table 100 2>/dev/null || true'",
	}
	for _, check := range checks {
		if !strings.Contains(unit, check) {
			t.Fatalf("renderTProxyRulesUnit missing %q\n%s", check, unit)
		}
	}
}

func TestTProxyRulesManagerSetupAndCleanup(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	unitPath := filepath.Join(tmpDir, managedTProxyRulesServiceName)
	if err := os.WriteFile(unitPath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale unit: %v", err)
	}

	var calls []string
	runner := func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}

	mgr := tproxyRulesManager{
		serviceName: managedTProxyRulesServiceName,
		unitPath:    unitPath,
		tproxyPort:  12345,
		ownerMatch:  ownerMatch{Mode: ownerMatchGID, Value: "go-proxy"},
		run:         runner,
		writeFile:   os.WriteFile,
		removeFile:  os.Remove,
	}

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup error: %v", err)
	}

	content, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("read generated unit: %v", err)
	}
	if !strings.Contains(string(content), "--gid-owner go-proxy") {
		t.Fatalf("generated unit missing gid owner rule:\n%s", string(content))
	}

	wantSetupCalls := []string{
		"systemctl stop " + managedTProxyRulesServiceName,
		"systemctl disable " + managedTProxyRulesServiceName,
		"systemctl daemon-reload",
		"systemctl daemon-reload",
		"systemctl reset-failed " + managedTProxyRulesServiceName,
		"systemctl start " + managedTProxyRulesServiceName,
	}
	if diff := diffCalls(wantSetupCalls, calls); diff != "" {
		t.Fatalf("setup calls mismatch:\n%s", diff)
	}

	calls = nil
	if err := mgr.Cleanup(); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("unit file should be removed, stat err = %v", err)
	}

	wantCleanupCalls := []string{
		"systemctl stop " + managedTProxyRulesServiceName,
		"systemctl disable " + managedTProxyRulesServiceName,
		"systemctl daemon-reload",
		"systemctl reset-failed " + managedTProxyRulesServiceName,
	}
	if diff := diffCalls(wantCleanupCalls, calls); diff != "" {
		t.Fatalf("cleanup calls mismatch:\n%s", diff)
	}
}

func diffCalls(want, got []string) string {
	if len(want) != len(got) {
		return "different call count:\nwant: " + strings.Join(want, "\n") + "\ngot: " + strings.Join(got, "\n")
	}
	for i := range want {
		if want[i] != got[i] {
			return "call mismatch at index " + fmt.Sprint(i) + ":\nwant: " + strings.Join(want, "\n") + "\ngot: " + strings.Join(got, "\n")
		}
	}
	return ""
}

type fakeFileInfo struct {
	name string
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }
