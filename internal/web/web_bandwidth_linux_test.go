package web

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
)

type bandwidthProcFixture struct {
	fstest.MapFS
	failedPath string
	readError  error
}

func (proc bandwidthProcFixture) ReadLink(name string) (string, error) {
	if proc.failedPath == name {
		return "", proc.readError
	}
	return proc.MapFS.ReadLink(name)
}

func (proc bandwidthProcFixture) ReadFile(name string) ([]byte, error) {
	if proc.failedPath == name {
		return nil, proc.readError
	}
	return proc.MapFS.ReadFile(name)
}

func TestBandwidthStockProcessPreflight(t *testing.T) {
	install := t.TempDir()
	bin := filepath.Join(install, "bin")
	xrayBinary := filepath.Join(bin, "xray-linux-amd64")
	mtgBinary := filepath.Join(bin, "mtg-linux-amd64")
	paths := bandwidthStockPaths{
		xrayBinary:     xrayBinary,
		xrayExecutable: xrayBinary,
		xrayConfig:     filepath.Join(bin, "config.json"),
		mtgBinary:      mtgBinary,
		mtgExecutable:  mtgBinary,
		mtgConfigs:     filepath.Join(bin, "mtproto"),
		xrayName:       bandwidthProcessName("xray-linux-amd64"),
		mtgName:        bandwidthProcessName("mtg-linux-amd64"),
	}
	if err := os.MkdirAll(paths.mtgConfigs, 0o700); err != nil {
		t.Fatal(err)
	}
	otherInstall := t.TempDir()
	alias := filepath.Join(install, "linked-bin")
	linkErr := os.Symlink(bin, alias)
	if linkErr != nil && runtime.GOOS != "windows" {
		t.Fatal(linkErr)
	}
	// The scanner sees these paths after resolving the current stable binary
	// links. They simulate a move from v1 to v2 without a host symlink privilege.
	linkedPaths := paths
	linkedPaths.xrayExecutable = filepath.Join(bin, "versions", "v2", "xray")
	linkedPaths.mtgExecutable = filepath.Join(bin, "versions", "v2", "mtg")
	oldXray := filepath.Join(bin, "versions", "v1", "xray")
	oldMTG := filepath.Join(bin, "versions", "v1", "mtg")
	otherMTG := filepath.Join(otherInstall, "bin", "mtg-linux-amd64")
	const owner = "1000"
	const ownedStatus = "Name:\txray-linux-amd6\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n"
	const xrayArgs = "bin/xray-linux-amd64\x00-c\x00bin/config.json\x00"
	const mtgArgs = "bin/mtg-linux-amd64\x00run\x00bin/mtproto/mtg-42.toml\x00"
	for _, test := range []struct {
		name, exe, cwd, command, status string
		failedPath                      string
		readError                       error
		kind                            string
		wantError                       bool
		retargeted                      bool
	}{
		{name: "relative Xray", exe: paths.xrayBinary, cwd: install, command: xrayArgs, kind: "Xray"},
		{name: "linked replaced Xray", exe: paths.xrayBinary + " (deleted)", cwd: install, command: strings.ReplaceAll(xrayArgs, "bin/", "linked-bin/"), kind: "Xray"},
		{name: "absolute Xray", exe: paths.xrayBinary, cwd: otherInstall, command: paths.xrayBinary + "\x00-c\x00" + paths.xrayConfig + "\x00", kind: "Xray"},
		{name: "replaced MTProto", exe: paths.mtgBinary + " (deleted)", cwd: install, command: mtgArgs, kind: "MTProto"},
		{name: "same basename elsewhere", exe: otherMTG, cwd: install, command: otherMTG + "\x00run\x00bin/mtproto/mtg-42.toml\x00"},
		{name: "relative paths in another install", exe: paths.xrayBinary, cwd: otherInstall, command: xrayArgs},
		{name: "different effective user", exe: paths.xrayBinary, cwd: install, command: xrayArgs, status: "Uid:\t1000\t1001\t1000\t1000\n"},
		{name: "non-panel Xray config", exe: paths.xrayBinary, cwd: install, command: strings.Replace(xrayArgs, "config.json", "other.json", 1)},
		{name: "non-panel MTProto config", exe: paths.mtgBinary, cwd: install, command: strings.Replace(mtgArgs, "mtg-42.toml", "test.toml", 1)},
		{name: "managed MTProto", exe: paths.mtgBinary, cwd: install, command: strings.Replace(mtgArgs, "run\x00", "run\x00--vanilla-bandwidth\x00", 1)},
		{name: "malformed cmdline", exe: paths.mtgBinary, cwd: install, command: strings.TrimSuffix(mtgArgs, "\x00")},
		{name: "known executable inaccessible cwd", exe: paths.xrayBinary, cwd: install, command: xrayArgs, failedPath: "cwd", readError: fs.ErrPermission, wantError: true},
		{name: "known executable inaccessible cmdline", exe: paths.xrayBinary, cwd: install, command: xrayArgs, failedPath: "cmdline", readError: fs.ErrPermission, wantError: true},
		{name: "known executable inaccessible status", exe: paths.xrayBinary, cwd: install, command: xrayArgs, failedPath: "status", readError: fs.ErrPermission, wantError: true},
		{name: "known executable exited", exe: paths.xrayBinary, cwd: install, command: xrayArgs, failedPath: "cmdline", readError: fs.ErrNotExist},
		{name: "exe inaccessible with exact command", cwd: install, command: xrayArgs, failedPath: "exe", readError: fs.ErrPermission, wantError: true},
		{name: "exe inaccessible in another install", cwd: otherInstall, command: xrayArgs, failedPath: "exe", readError: fs.ErrPermission},
		{name: "exe inaccessible for different user", cwd: install, command: xrayArgs, status: "Name:\txray-linux-amd6\nUid:\t1001\t1001\t1001\t1001\n", failedPath: "exe", readError: fs.ErrPermission},
		{name: "missing zombie executable", cwd: install, command: xrayArgs, status: strings.Replace(ownedStatus, "S (sleeping)", "Z (zombie)", 1), failedPath: "exe", readError: fs.ErrNotExist},
		{name: "retargeted Xray", exe: oldXray, cwd: install, command: xrayArgs, kind: "Xray", retargeted: true},
		{name: "retargeted MTProto with deleted executable", exe: oldMTG + " (deleted)", cwd: install, command: mtgArgs, kind: "MTProto", retargeted: true},
		{name: "current Xray symlink target", exe: linkedPaths.xrayExecutable, cwd: install, command: xrayArgs, kind: "Xray", retargeted: true},
		{name: "retargeted Xray other installation", exe: filepath.Join(otherInstall, "versions", "v1", "xray"), cwd: otherInstall, command: xrayArgs, retargeted: true},
		{name: "retargeted Xray other user", exe: oldXray, cwd: install, command: xrayArgs, status: "Uid:\t1000\t1001\t1000\t1000\n", retargeted: true},
		{name: "retargeted Xray other configuration", exe: oldXray, cwd: install, command: strings.Replace(xrayArgs, "config.json", "other.json", 1), retargeted: true},
		{name: "retargeted Xray direct invocation", exe: oldXray, cwd: install, command: oldXray + "\x00-c\x00" + paths.xrayConfig + "\x00", retargeted: true},
		{name: "Xray symlink replaced by regular file", exe: oldXray, cwd: install, command: xrayArgs, kind: "Xray"},
		{name: "MTProto symlink replaced by regular file", exe: oldMTG + " (deleted)", cwd: install, command: mtgArgs, kind: "MTProto"},
		{name: "old Xray direct invocation with regular install binary", exe: oldXray, cwd: install, command: oldXray + "\x00-c\x00" + paths.xrayConfig + "\x00"},
		{name: "unrelated process inaccessible cmdline", exe: otherMTG, cwd: otherInstall, command: mtgArgs, failedPath: "cmdline", readError: fs.ErrPermission},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "linked replaced Xray" && linkErr != nil {
				t.Skip(linkErr)
			}
			status := test.status
			if status == "" {
				status = ownedStatus
			}
			proc := bandwidthProcFixture{
				MapFS: fstest.MapFS{
					"exe":     {Mode: fs.ModeSymlink, Data: []byte(test.exe)},
					"cwd":     {Mode: fs.ModeSymlink, Data: []byte(test.cwd)},
					"cmdline": {Data: []byte(test.command)},
					"status":  {Data: []byte(status)},
				},
				failedPath: test.failedPath,
				readError:  test.readError,
			}
			candidatePaths := paths
			if test.retargeted {
				candidatePaths = linkedPaths
			}
			kind, err := candidatePaths.stockProcess(proc, owner)
			if kind != test.kind || (err != nil) != test.wantError || (test.wantError && !errors.Is(err, test.readError)) {
				t.Fatalf("stockProcess = %q, %v; want %q, error %v", kind, err, test.kind, test.wantError)
			}
		})
	}
	if err := paths.check(filepath.Join(install, "missing-proc"), owner); err == nil {
		t.Fatal("managed node accepted an unreadable process inventory")
	}
}
