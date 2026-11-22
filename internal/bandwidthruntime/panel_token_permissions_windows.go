package bandwidthruntime

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isPrivatePanelTokenFile(file *os.File, _ os.FileInfo) bool {
	conn, err := file.SyscallConn()
	if err != nil {
		return false
	}
	private := false
	err = conn.Control(func(handle uintptr) {
		descriptor, err := windows.GetSecurityInfo(windows.Handle(handle), windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return
		}
		private = isPrivatePanelTokenDescriptor(descriptor)
	})
	return err == nil && private
}

func isPrivatePanelTokenDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) bool {
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil ||
			uintptr(ace.Header.AceSize) < unsafe.Sizeof(ace.Header) {
			return false
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// Conditional and object-specific entries can have a different layout.
		// Require a conventional private file ACL before interpreting any allow.
		const sidOffset = unsafe.Offsetof(ace.SidStart)
		const minSIDSize = 8
		size := uintptr(ace.Header.AceSize)
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || size < sidOffset+minSIDSize {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if uintptr(sid.Len()) > size-sidOffset || !sid.IsValid() {
			return false
		}
		if isTrustedPanelTokenSID(sid, owner, user.User.Sid) {
			continue
		}
		// A synchronization-only ACE does not permit reading or modifying
		// the token, its metadata or its security descriptor.
		if ace.Mask&^windows.SYNCHRONIZE != 0 {
			return false
		}
	}
	return true
}

func isTrustedPanelTokenSID(sid, owner, currentUser *windows.SID) bool {
	return sid.Equals(owner) || sid.Equals(currentUser) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}
