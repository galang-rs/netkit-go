package proc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostsReal_RedirectAndRestore(t *testing.T) {
	// 1. Setup temporary hosts file
	tmpDir := t.TempDir()
	tmpHosts := filepath.Join(tmpDir, "hosts")
	initialContent := "127.0.0.1 localhost\n::1 localhost\n"
	err := os.WriteFile(tmpHosts, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp hosts: %v", err)
	}

	// 2. Override global path
	oldPath := HostsPath
	HostsPath = tmpHosts
	defer func() { HostsPath = oldPath }()

	// 3. Initialize Manager and Redirect
	h := NewHostsManager()
	domains := []string{"example.com", "test.local"}

	// We use a small hack here: RedirectDomains will fail DNS resolution if offline,
	// but it should still write the 127.0.0.1 redirection to the file even if resolution fails?
	// Actually, RedirectDomains returns error only if it can't open/write the file.
	err = h.RedirectDomains(domains)
	if err != nil {
		t.Fatalf("RedirectDomains failed: %v", err)
	}

	// 4. Verify file content
	content, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("Failed to read temp hosts: %v", err)
	}
	sContent := string(content)

	for _, d := range domains {
		if !strings.Contains(sContent, "127.0.0.1 "+d) {
			t.Errorf("Expected redirection for %s not found in hosts", d)
		}
		if !strings.Contains(sContent, Marker) {
			t.Errorf("Marker not found in hosts")
		}
	}

	// 5. Restore
	err = h.Restore()
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// 6. Verify restored content (should match initial)
	restoredContent, err := os.ReadFile(tmpHosts)
	if err != nil {
		t.Fatalf("Failed to read restored hosts: %v", err)
	}

	// Note: RedirectDomains might change \n to \r\n or add trailing newline.
	// We check if it contains the original lines and DOES NOT contain the redirects.
	sRestored := string(restoredContent)
	if !strings.Contains(sRestored, "127.0.0.1 localhost") {
		t.Errorf("Original content lost after restore")
	}
	for _, d := range domains {
		if strings.Contains(sRestored, "127.0.0.1 "+d) {
			t.Errorf("Redirection for %s still exists after restore", d)
		}
	}
}
