package proc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bacot120211/netkit-go/pkg/logger"
)

// Launcher handles starting an external application and tracking its PID
type Launcher struct {
	Path string
	Args []string
	PID  int
	cmd  *exec.Cmd
}

func NewLauncher(appPath string, args ...string) (*Launcher, error) {
	absPath, err := filepath.Abs(appPath)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("application not found: %s", absPath)
	}

	ext := strings.ToLower(filepath.Ext(absPath))
	logger.Infof("[Launcher] Initial path: %s (Ext: %s)\n", absPath, ext)

	// Resolve shortcut if it's a .lnk file
	if ext == ".lnk" {
		logger.Infof("[Launcher] Resolving Windows shortcut...\n")
		target, err := resolveShortcut(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve shortcut: %v", err)
		}
		if target == "" {
			return nil, fmt.Errorf("shortcut resolved to empty path")
		}
		logger.Infof("[Launcher] Resolved target: %s\n", target)
		absPath = target
	}

	return &Launcher{
		Path: absPath,
		Args: args,
	}, nil
}

func resolveShortcut(path string) (string, error) {
	// Use PowerShell to resolve the shortcut TargetPath
	// We use double quotes inside PS script and escape backslashes
	escapedPath := strings.ReplaceAll(path, "\\", "\\\\")
	psCmd := fmt.Sprintf("$s = (New-Object -ComObject WScript.Shell).CreateShortcut('%s'); $s.TargetPath", escapedPath)
	out, err := exec.Command("powershell", "-Command", psCmd).Output()
	if err != nil {
		return "", err
	}
	res := strings.TrimSpace(string(out))
	// Remove surrounding quotes if any
	res = strings.Trim(res, "\"'")
	return res, nil
}

// Start launches the application and returns its PID
func (l *Launcher) Start() (int, error) {
	l.cmd = exec.Command(l.Path, l.Args...)
	l.cmd.Stdout = os.Stdout
	l.cmd.Stderr = os.Stderr

	if err := l.cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start application: %v", err)
	}

	l.PID = l.cmd.Process.Pid
	return l.PID, nil
}

// Wait waits for the application to exit
func (l *Launcher) Wait() error {
	if l.cmd == nil {
		return fmt.Errorf("application not started")
	}
	return l.cmd.Wait()
}

// Stop terminates the application
func (l *Launcher) Stop() error {
	if l.cmd != nil && l.cmd.Process != nil {
		return l.cmd.Process.Kill()
	}
	return nil
}
