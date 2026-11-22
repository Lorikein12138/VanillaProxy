package bandwidthruntime

import (
	"testing"

	"golang.org/x/sys/windows"
)

func privatePanelTokenTestDACL(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)"
}

func setTestPanelTokenDACL(t *testing.T, path string, dacl *windows.ACL) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func panelTokenTestACL(t *testing.T, sddl string) *windows.ACL {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("test descriptor DACL: %v", err)
	}
	return dacl
}

func protectTestPanelToken(t *testing.T, path string) {
	t.Helper()
	setTestPanelTokenDACL(t, path, panelTokenTestACL(t, privatePanelTokenTestDACL(t)))
}

func TestPanelTokenWindowsDACL(t *testing.T) {
	path, tokenPath := writePanelTestConfig(t, `{"node":`+testPanelNode+`}`, testPanelToken)
	if cfg, err := LoadPanelConfig(path); err != nil || cfg == nil {
		t.Fatalf("private token rejected: %v", err)
	}
	for _, tt := range []struct {
		name string
		dacl *windows.ACL
	}{
		{"Everyone read", panelTokenTestACL(t, privatePanelTokenTestDACL(t)+"(A;;FR;;;WD)")},
		{"Everyone write", panelTokenTestACL(t, privatePanelTokenTestDACL(t)+"(A;;FW;;;WD)")},
		{"Everyone change ACL", panelTokenTestACL(t, privatePanelTokenTestDACL(t)+"(A;;WD;;;WD)")},
		{"NULL DACL", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setTestPanelTokenDACL(t, tokenPath, tt.dacl)
			defer protectTestPanelToken(t, tokenPath)
			if cfg, err := LoadPanelConfig(path); err == nil || cfg != nil {
				t.Fatal("insecure token accepted")
			}
		})
	}
}

func TestPanelTokenWindowsACEInheritance(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := "O:" + user.User.Sid.String()
	private := privatePanelTokenTestDACL(t)
	for _, tt := range []struct {
		name       string
		descriptor string
		private    bool
	}{
		{"distinct file owner", "O:LSD:P(A;;FA;;;LS)(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"inherit-only allow", owner + private + "(A;OIIO;FR;;;WD)", true},
		{"inherited effective allow", owner + private + "(A;ID;FR;;;WD)", false},
		{"ordinary deny", owner + "D:P(D;;FR;;;BU)" + private[3:], true},
		{"no DACL", owner, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tt.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if private := isPrivatePanelTokenDescriptor(descriptor); private != tt.private {
				t.Fatalf("private DACL = %t, want %t", private, tt.private)
			}
		})
	}
}
