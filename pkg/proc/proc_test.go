package proc

import (
	"os"
	"runtime"
	"testing"
)

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// --- NewHostsManager ---

func TestNewHostsManager_NotNil(t *testing.T) {
	h := NewHostsManager()
	if h == nil {
		t.Fatal("NewHostsManager should return non-nil")
	}
}

func TestNewHostsManager_ResolvedIPsInitialized(t *testing.T) {
	h := NewHostsManager()
	if h.ResolvedIPs == nil {
		t.Error("ResolvedIPs should be initialized (non-nil map)")
	}
}

func TestNewHostsManager_ResolvedIPsEmpty(t *testing.T) {
	h := NewHostsManager()
	if len(h.ResolvedIPs) != 0 {
		t.Errorf("ResolvedIPs should be empty initially, got %d entries", len(h.ResolvedIPs))
	}
}

// --- HostsManager Admin-Required Tests ---

func TestHostsManager_RedirectDomains_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (writes to hosts file)")
	}
	h := NewHostsManager()
	err := h.RedirectDomains([]string{"test-domain-netkit.example.com"})
	if err != nil {
		t.Errorf("RedirectDomains failed: %v", err)
	}
	// Cleanup
	h.Restore()
}

func TestHostsManager_Restore_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (writes to hosts file)")
	}
	h := NewHostsManager()
	// Must redirect first so there's something to restore
	h.RedirectDomains([]string{"test-restore-netkit.example.com"})
	err := h.Restore()
	if err != nil {
		t.Errorf("Restore failed: %v", err)
	}
}

// --- NewLauncher ---

func TestNewLauncher_FileNotFound(t *testing.T) {
	_, err := NewLauncher("C:\\non\\existent\\app.exe")
	if err == nil {
		t.Error("NewLauncher should fail for non-existent file")
	}
}

func TestNewLauncher_NonExistentDeep(t *testing.T) {
	_, err := NewLauncher("Z:\\this_drive_does_not_exist_9999\\no\\such\\app.exe")
	if err == nil {
		t.Error("NewLauncher should fail for non-existent deep path")
	}
}

// --- Launcher.Wait ---

func TestLauncher_Wait_NotStarted(t *testing.T) {
	l := &Launcher{Path: "dummy.exe"}
	err := l.Wait()
	if err == nil {
		t.Error("Wait should return error if application not started")
	}
}

// --- Launcher.Stop ---

func TestLauncher_Stop_NilCmd(t *testing.T) {
	l := &Launcher{Path: "dummy.exe"}
	err := l.Stop()
	if err != nil {
		t.Errorf("Stop should not error when cmd is nil: %v", err)
	}
}

// --- isBrowserProcess ---

func TestIsBrowserProcess_Chrome(t *testing.T) {
	if !isBrowserProcess("chrome.exe") {
		t.Error("chrome.exe should be recognized as a browser")
	}
}

func TestIsBrowserProcess_Edge(t *testing.T) {
	if !isBrowserProcess("msedge.exe") {
		t.Error("msedge.exe should be recognized as a browser")
	}
}

func TestIsBrowserProcess_Firefox(t *testing.T) {
	if !isBrowserProcess("firefox.exe") {
		t.Error("firefox.exe should be recognized as a browser")
	}
}

func TestIsBrowserProcess_Brave(t *testing.T) {
	if !isBrowserProcess("brave.exe") {
		t.Error("brave.exe should be recognized as a browser")
	}
}

func TestIsBrowserProcess_Opera(t *testing.T) {
	if !isBrowserProcess("opera.exe") {
		t.Error("opera.exe should be recognized as a browser")
	}
}

func TestIsBrowserProcess_Notepad(t *testing.T) {
	if isBrowserProcess("notepad.exe") {
		t.Error("notepad.exe should NOT be recognized as a browser")
	}
}

func TestIsBrowserProcess_Empty(t *testing.T) {
	if isBrowserProcess("") {
		t.Error("Empty string should NOT be recognized as a browser")
	}
}

func TestIsBrowserProcess_CaseSensitive(t *testing.T) {
	// The function does exact match — uppercase should NOT match
	if isBrowserProcess("Chrome.exe") {
		t.Error("Browser detection is case-sensitive, 'Chrome.exe' should NOT match")
	}
}

// --- GetPortsByPID ---

func TestGetPortsByPID_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (Windows API)")
	}
	ports, err := GetPortsByPID(os.Getpid())
	if err != nil {
		t.Errorf("GetPortsByPID failed: %v", err)
	}
	// Current process may or may not have ports
	_ = ports
}

// --- GetSystemConnections ---

func TestGetSystemConnections_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (Windows API)")
	}
	tcp, udp, err := GetSystemConnections()
	if err != nil {
		t.Errorf("GetSystemConnections failed: %v", err)
	}
	if tcp == nil {
		t.Error("TCP map should not be nil")
	}
	if udp == nil {
		t.Error("UDP map should not be nil")
	}
}

// --- GetAllPortPIDMappings ---

func TestGetAllPortPIDMappings_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (Windows API)")
	}
	tcp, udp, err := GetAllPortPIDMappings()
	if err != nil {
		t.Errorf("GetAllPortPIDMappings failed: %v", err)
	}
	if tcp == nil {
		t.Error("TCP map should not be nil")
	}
	if udp == nil {
		t.Error("UDP map should not be nil")
	}
}

// --- GetProcessName ---

func TestGetProcessName_SystemPID(t *testing.T) {
	name := GetProcessName(0)
	if name != "System" {
		t.Errorf("Expected 'System' for PID 0, got '%s'", name)
	}
}

func TestGetProcessName_CurrentProcess_SkipAdmin(t *testing.T) {
	if !isAdmin() {
		t.Skip("Skipping: requires administrator privileges (Windows API)")
	}
	pid := uint32(os.Getpid())
	name := GetProcessName(pid)
	if name == "" || name == "unknown" {
		t.Errorf("Expected valid process name for current PID %d, got '%s'", pid, name)
	}
}

// --- GetBrowserPIDs ---

func TestGetBrowserPIDs_NoError(t *testing.T) {
	pids, err := GetBrowserPIDs()
	if err != nil {
		t.Errorf("GetBrowserPIDs should not error: %v", err)
	}
	// May be empty if no browser is running, that's OK
	_ = pids
}

func TestGetBrowserPIDs_ReturnType(t *testing.T) {
	pids, _ := GetBrowserPIDs()
	// Even if empty, should be a valid slice (not nil after successful call, but can be nil)
	for _, pid := range pids {
		if pid <= 0 {
			t.Errorf("Browser PID should be positive, got %d", pid)
		}
	}
}

// --- WarmProcessCache ---

func TestWarmProcessCache_SystemPID(t *testing.T) {
	// Should not panic
	WarmProcessCache([]uint32{0})
	name := GetProcessName(0)
	if name != "System" {
		t.Errorf("Expected 'System', got '%s'", name)
	}
}

func TestWarmProcessCache_Empty(t *testing.T) {
	// Should not panic with empty slice
	WarmProcessCache([]uint32{})
}
