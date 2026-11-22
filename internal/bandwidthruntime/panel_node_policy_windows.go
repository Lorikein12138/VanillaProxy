package bandwidthruntime

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func protectNodePolicyFile(file *os.File, path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	verify, err := os.Open(path)
	if err != nil {
		return err
	}
	defer verify.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	verified, err := verify.Stat()
	if err != nil || !os.SameFile(info, verified) || !isPrivatePanelTokenFile(verify, verified) {
		return errors.New("cannot make automatic bandwidth policy private")
	}
	return nil
}

func replaceNodePolicyFile(dir *os.Root, from, to string) error {
	source, err := windows.UTF16PtrFromString(filepath.Join(dir.Name(), from))
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(filepath.Join(dir.Name(), to))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// The Windows replacement already requested a write-through move.
func syncNodePolicyDirectory(_ *os.Root) error { return nil }
