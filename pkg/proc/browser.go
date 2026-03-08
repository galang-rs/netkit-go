package proc

import (
	"os/exec"
	"strconv"
	"strings"
)

// knownBrowsers is the list of browser process names to scan for.
var knownBrowsers = []string{
	"chrome.exe",
	"msedge.exe",
	"firefox.exe",
	"brave.exe",
	"opera.exe",
}

// GetBrowserPIDs returns the PIDs of all running browser processes.
// Uses `tasklist /FO CSV /NH` which works on all Windows versions without Admin.
func GetBrowserPIDs() ([]int, error) {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// CSV format: "chrome.exe","12345","Console","1","100,888 K"
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		name := strings.Trim(parts[0], "\"")
		pidStr := strings.Trim(parts[1], "\"")

		if isBrowserProcess(strings.ToLower(name)) {
			pid, err := strconv.Atoi(pidStr)
			if err == nil && pid > 0 {
				pids = append(pids, pid)
			}
		}
	}
	return pids, nil
}

func isBrowserProcess(name string) bool {
	for _, b := range knownBrowsers {
		if name == b {
			return true
		}
	}
	return false
}
