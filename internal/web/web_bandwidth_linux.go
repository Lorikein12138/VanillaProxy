package web

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/mhsanaei/3x-ui/v3/internal/mtproto"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func checkBandwidthStockChildren() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve bandwidth node working directory: %w", err)
	}
	xrayBinary := bandwidthCommandPath(cwd, xray.GetBinaryPath())
	mtgBinary := bandwidthCommandPath(cwd, mtproto.GetBinaryPath())
	paths := bandwidthStockPaths{
		xrayBinary:     xrayBinary,
		xrayExecutable: bandwidthAbsolutePath(cwd, xrayBinary),
		xrayConfig:     bandwidthCommandPath(cwd, xray.GetConfigPath()),
		mtgBinary:      mtgBinary,
		mtgExecutable:  bandwidthAbsolutePath(cwd, mtgBinary),
		mtgConfigs:     bandwidthAbsolutePath(cwd, filepath.Join(filepath.Dir(mtgBinary), "mtproto")),
		xrayName:       bandwidthProcessName(xray.GetBinaryName()),
		mtgName:        bandwidthProcessName(mtproto.GetBinaryName()),
	}
	return paths.check("/proc", strconv.Itoa(os.Geteuid()))
}

type bandwidthStockPaths struct {
	xrayBinary     string
	xrayExecutable string
	xrayConfig     string
	mtgBinary      string
	mtgExecutable  string
	mtgConfigs     string
	xrayName       string
	mtgName        string
}

func (paths bandwidthStockPaths) check(procDir, uid string) error {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return fmt.Errorf("inspect Linux processes before enabling bandwidth management: %w", err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		// A directory handle keeps observations tied to one process even if it
		// exits and Linux reuses its PID before the scan finishes.
		proc, err := os.OpenRoot(filepath.Join(procDir, entry.Name()))
		if err != nil {
			continue
		}
		kind, err := paths.stockProcess(proc.FS(), uid)
		_ = proc.Close()
		if err != nil {
			return fmt.Errorf("inspect existing bandwidth node process (PID %d): %w", pid, err)
		}
		if kind != "" {
			return fmt.Errorf("stop the existing stock %s process (PID %d) before enabling bandwidth management", kind, pid)
		}
	}
	return nil
}

func (paths bandwidthStockPaths) stockProcess(proc fs.FS, uid string) (string, error) {
	exe, exeErr := fs.ReadLink(proc, "exe")
	// The service can atomically replace a binary while a child still runs
	// from the old inode. Procfs appends this suffix to that inode's path.
	exe = strings.TrimSuffix(exe, " (deleted)")
	knownExe := exeErr == nil && (exe == paths.xrayBinary || exe == paths.xrayExecutable ||
		exe == paths.mtgBinary || exe == paths.mtgExecutable)
	status, err := fs.ReadFile(proc, "status")
	if err != nil {
		return "", bandwidthProcessReadError(knownExe, err)
	}
	name, owner, dead := bandwidthProcessStatus(status)
	if dead || (owner != "" && owner != uid) {
		return "", nil
	}
	if owner == "" {
		return "", bandwidthProcessReadError(knownExe, errors.New("cannot determine process owner"))
	}
	if exeErr != nil && name != paths.xrayName && name != paths.mtgName {
		return "", nil
	}
	cmdline, err := fs.ReadFile(proc, "cmdline")
	if err != nil {
		return "", bandwidthProcessReadError(knownExe, err)
	}
	line, terminated := strings.CutSuffix(string(cmdline), "\x00")
	args := strings.Split(line, "\x00")
	if !terminated || len(args) != 3 || args[0] == "" || args[2] == "" {
		return "", nil
	}
	var stockBinary, executable, stockName string
	switch args[1] {
	case "-c":
		stockBinary, executable, stockName = paths.xrayBinary, paths.xrayExecutable, paths.xrayName
	case "run":
		stockBinary, executable, stockName = paths.mtgBinary, paths.mtgExecutable, paths.mtgName
	default:
		return "", nil
	}
	if exeErr != nil && name != stockName {
		return "", nil
	}
	// A child launched through a symlink keeps the old target after the link
	// moves or is replaced by a regular file. Its launch and config paths
	// establish ownership even if its executable differs from today's.
	if knownExe && exe != stockBinary && exe != executable {
		return "", nil
	}
	cwd, err := fs.ReadLink(proc, "cwd")
	relativeArgs := !filepath.IsAbs(args[0]) || !filepath.IsAbs(args[2])
	if err != nil && (knownExe || relativeArgs) {
		return "", bandwidthProcessReadError(knownExe, err)
	}
	if !filepath.IsAbs(cwd) && relativeArgs {
		return "", bandwidthProcessReadError(knownExe, errors.New("cannot resolve process working directory"))
	}
	if bandwidthCommandPath(cwd, args[0]) != stockBinary {
		return "", nil
	}
	kind := paths.matchStockConfig(stockBinary, bandwidthCommandPath(cwd, args[2]))
	if kind != "" && exeErr != nil {
		return "", fmt.Errorf("cannot verify candidate stock %s executable: %w", kind, exeErr)
	}
	return kind, nil
}

func (paths bandwidthStockPaths) matchStockConfig(binary, configPath string) string {
	if binary == paths.xrayBinary && configPath == paths.xrayConfig {
		return "Xray"
	}
	if binary == paths.mtgBinary && filepath.Dir(configPath) == paths.mtgConfigs {
		name, prefix := strings.CutPrefix(filepath.Base(configPath), "mtg-")
		idText, suffix := strings.CutSuffix(name, ".toml")
		id, err := strconv.Atoi(idText)
		if prefix && suffix && err == nil && id > 0 && strconv.Itoa(id) == idText {
			return "MTProto"
		}
	}
	return ""
}

func bandwidthProcessStatus(status []byte) (name, uid string, dead bool) {
	for line := range strings.SplitSeq(string(status), "\n") {
		key, value, _ := strings.Cut(line, ":")
		switch key {
		case "Name":
			name = strings.TrimSpace(value)
		case "Uid":
			fields := strings.Fields(value)
			if len(fields) == 4 {
				uid = fields[1]
			}
		case "State":
			state := strings.TrimSpace(value)
			dead = strings.HasPrefix(state, "Z ") || strings.HasPrefix(state, "X ")
		}
	}
	return name, uid, dead
}

func bandwidthProcessReadError(knownExe bool, err error) error {
	// An executable we could not associate with this installation must not
	// block it on the strength of a matching name alone.
	if !knownExe || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func bandwidthProcessName(name string) string {
	// Linux comm includes up to 15 bytes of the executable name.
	return name[:min(len(name), 15)]
}

func bandwidthCommandPath(cwd, filename string) string {
	// Preserve the filename the panel passed to exec. A symlink in a parent
	// directory identifies the same installation, but a symlink at the binary
	// path can change independently of a running child.
	return filepath.Join(bandwidthAbsolutePath(cwd, filepath.Dir(filename)), filepath.Base(filename))
}

func bandwidthAbsolutePath(cwd, filename string) string {
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(cwd, filename)
	}
	filename = filepath.Clean(filename)
	if resolved, err := filepath.EvalSymlinks(filename); err == nil {
		return resolved
	}
	// A child's binary or configuration may have been removed since startup.
	if dir, err := filepath.EvalSymlinks(filepath.Dir(filename)); err == nil {
		return filepath.Join(dir, filepath.Base(filename))
	}
	return filename
}
