//go:build !windows

package bandwidthruntime

import "os"

func protectNodePolicyFile(_ *os.File, _ string) error { return nil }

func replaceNodePolicyFile(dir *os.Root, from, to string) error {
	return dir.Rename(from, to)
}

func syncNodePolicyDirectory(dir *os.Root) error {
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
