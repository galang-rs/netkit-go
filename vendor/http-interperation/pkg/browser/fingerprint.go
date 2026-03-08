package browser

import (
	"fmt"
	"math/rand"
	"runtime"
	"time"
)

// OSFingerprint represents system environment fingerprint
type OSFingerprint struct {
	OS          string
	OSVersion   string
	Arch        string
	Kernel      string
	Hostname    string
	Username    string
	HomeDir     string
	TempDir     string
	Shell       string
	CPUCores    int
	MemoryTotal string
	Locale      string
	Timezone    string
	ProcessID   int
}

// BrowserFingerprint represents browser environment
type BrowserFingerprint struct {
	UserAgent           string
	Platform            string
	Language            string
	Languages           []string
	Vendor              string
	VendorSub           string
	ProductSub          string
	AppCodeName         string
	AppName             string
	AppVersion          string
	ScreenWidth         int
	ScreenHeight        int
	ColorDepth          int
	PixelRatio          float64
	HardwareConcurrency int
	DeviceMemory        int
	MaxTouchPoints      int
	DoNotTrack          string
}

var (
	// OS options
	osOptions = []string{
		"Windows NT 10.0", "Windows NT 11.0",
		"Macintosh; Intel Mac OS X 10_15_7", "Macintosh; Intel Mac OS X 11_6_0",
		"X11; Linux x86_64", "X11; Ubuntu; Linux x86_64",
	}

	// Browser versions
	chromeVersions  = []string{"120.0.0.0", "119.0.0.0", "118.0.0.0", "121.0.0.0"}
	firefoxVersions = []string{"120.0", "119.0", "118.0", "121.0"}
	safariVersions  = []string{"17.1", "17.0", "16.6"}

	// Screen resolutions
	screenResolutions = [][2]int{
		{1920, 1080}, {1366, 768}, {1440, 900}, {1536, 864},
		{2560, 1440}, {1920, 1200}, {1680, 1050}, {3840, 2160},
	}

	// Timezones
	timezones = []string{
		"America/New_York", "America/Los_Angeles", "America/Chicago",
		"Europe/London", "Europe/Paris", "Asia/Tokyo", "Asia/Singapore",
		"America/Toronto", "Europe/Berlin", "Asia/Shanghai",
	}

	// Languages
	languageSets = [][]string{
		{"en-US", "en"},
		{"en-GB", "en"},
		{"fr-FR", "fr", "en"},
		{"de-DE", "de", "en"},
		{"ja-JP", "ja", "en"},
		{"zh-CN", "zh", "en"},
	}

	// Hostnames patterns
	hostnamePatterns = []string{
		"DESKTOP-%s", "LAPTOP-%s", "PC-%s", "WORKSTATION-%s",
		"MacBook-%s", "iMac-%s",
	}

	// Usernames
	usernamePatterns = []string{
		"user", "admin", "developer", "john", "jane", "alex", "chris",
	}
)

// GenerateRandomOSFingerprint creates random OS environment
func GenerateRandomOSFingerprint() *OSFingerprint {
	rand.Seed(time.Now().UnixNano())

	// Random OS
	osType := osOptions[rand.Intn(len(osOptions))]

	// Determine arch and other details based on OS
	arch := "x86_64"
	if rand.Float32() < 0.3 {
		arch = "amd64"
	}

	// Random hostname
	hostnamePattern := hostnamePatterns[rand.Intn(len(hostnamePatterns))]
	hostname := fmt.Sprintf(hostnamePattern, randomString(6))

	// Random username
	username := usernamePatterns[rand.Intn(len(usernamePatterns))]
	if rand.Float32() < 0.5 {
		username = fmt.Sprintf("%s%d", username, rand.Intn(100))
	}

	// Random specs
	cpuCores := []int{2, 4, 6, 8, 12, 16}[rand.Intn(6)]
	memoryOptions := []string{"8GB", "16GB", "32GB", "64GB"}
	memory := memoryOptions[rand.Intn(len(memoryOptions))]

	return &OSFingerprint{
		OS:          osType,
		OSVersion:   randomVersion(),
		Arch:        arch,
		Kernel:      randomKernelVersion(osType),
		Hostname:    hostname,
		Username:    username,
		HomeDir:     fmt.Sprintf("/home/%s", username),
		TempDir:     "/tmp",
		Shell:       "/bin/bash",
		CPUCores:    cpuCores,
		MemoryTotal: memory,
		Locale:      "en_US.UTF-8",
		Timezone:    timezones[rand.Intn(len(timezones))],
		ProcessID:   rand.Intn(99999) + 1000,
	}
}

// GenerateRandomBrowserFingerprint creates random browser environment
func GenerateRandomBrowserFingerprint() *BrowserFingerprint {
	rand.Seed(time.Now().UnixNano())

	browserType := rand.Intn(3) // 0=Chrome, 1=Firefox, 2=Safari

	var userAgent, platform, vendor, appName, appVersion string
	var chromeVersion, firefoxVersion, safariVersion string

	screen := screenResolutions[rand.Intn(len(screenResolutions))]
	langSet := languageSets[rand.Intn(len(languageSets))]

	switch browserType {
	case 0: // Chrome
		chromeVersion = chromeVersions[rand.Intn(len(chromeVersions))]
		platform = "Win32"
		if rand.Float32() < 0.3 {
			platform = "MacIntel"
		}
		vendor = "Google Inc."
		appName = "Netscape"
		appVersion = fmt.Sprintf("5.0 (%s)", platform)
		userAgent = fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
			platform, chromeVersion)

	case 1: // Firefox
		firefoxVersion = firefoxVersions[rand.Intn(len(firefoxVersions))]
		platform = "Win32"
		if rand.Float32() < 0.3 {
			platform = "MacIntel"
		}
		vendor = ""
		appName = "Netscape"
		appVersion = "5.0"
		userAgent = fmt.Sprintf("Mozilla/5.0 (%s; rv:%s) Gecko/20100101 Firefox/%s",
			platform, firefoxVersion, firefoxVersion)

	case 2: // Safari
		safariVersion = safariVersions[rand.Intn(len(safariVersions))]
		platform = "MacIntel"
		vendor = "Apple Computer, Inc."
		appName = "Netscape"
		appVersion = "5.0 (Macintosh)"
		userAgent = fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15",
			safariVersion)
	}

	colorDepths := []int{24, 30, 32}
	pixelRatios := []float64{1.0, 1.25, 1.5, 2.0, 2.5}
	hardwareConcurrency := []int{2, 4, 6, 8, 12, 16}
	deviceMemory := []int{4, 8, 16, 32}

	return &BrowserFingerprint{
		UserAgent:           userAgent,
		Platform:            platform,
		Language:            langSet[0],
		Languages:           langSet,
		Vendor:              vendor,
		VendorSub:           "",
		ProductSub:          "20030107",
		AppCodeName:         "Mozilla",
		AppName:             appName,
		AppVersion:          appVersion,
		ScreenWidth:         screen[0],
		ScreenHeight:        screen[1],
		ColorDepth:          colorDepths[rand.Intn(len(colorDepths))],
		PixelRatio:          pixelRatios[rand.Intn(len(pixelRatios))],
		HardwareConcurrency: hardwareConcurrency[rand.Intn(len(hardwareConcurrency))],
		DeviceMemory:        deviceMemory[rand.Intn(len(deviceMemory))],
		MaxTouchPoints:      0,
		DoNotTrack:          []string{"1", "0", "null"}[rand.Intn(3)],
	}
}

// ToEnvMap converts fingerprint to environment variables map
func (f *OSFingerprint) ToEnvMap() map[string]string {
	return map[string]string{
		"OS":           f.OS,
		"OS_VERSION":   f.OSVersion,
		"ARCH":         f.Arch,
		"KERNEL":       f.Kernel,
		"HOSTNAME":     f.Hostname,
		"USER":         f.Username,
		"USERNAME":     f.Username,
		"HOME":         f.HomeDir,
		"TMPDIR":       f.TempDir,
		"TEMP":         f.TempDir,
		"SHELL":        f.Shell,
		"CPU_CORES":    fmt.Sprintf("%d", f.CPUCores),
		"MEMORY_TOTAL": f.MemoryTotal,
		"LANG":         f.Locale,
		"TZ":           f.Timezone,
		"PID":          fmt.Sprintf("%d", f.ProcessID),
	}
}

// ToEnvMap converts browser fingerprint to environment variables
func (f *BrowserFingerprint) ToEnvMap() map[string]string {
	return map[string]string{
		"USER_AGENT":           f.UserAgent,
		"PLATFORM":             f.Platform,
		"LANGUAGE":             f.Language,
		"VENDOR":               f.Vendor,
		"APP_NAME":             f.AppName,
		"APP_VERSION":          f.AppVersion,
		"SCREEN_WIDTH":         fmt.Sprintf("%d", f.ScreenWidth),
		"SCREEN_HEIGHT":        fmt.Sprintf("%d", f.ScreenHeight),
		"COLOR_DEPTH":          fmt.Sprintf("%d", f.ColorDepth),
		"PIXEL_RATIO":          fmt.Sprintf("%.2f", f.PixelRatio),
		"HARDWARE_CONCURRENCY": fmt.Sprintf("%d", f.HardwareConcurrency),
		"DEVICE_MEMORY":        fmt.Sprintf("%d", f.DeviceMemory),
		"DNT":                  f.DoNotTrack,
	}
}

// CombineEnvMaps combines multiple env maps
func CombineEnvMaps(maps ...map[string]string) map[string]string {
	combined := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			combined[k] = v
		}
	}
	return combined
}

// Helper functions
func randomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randomVersion() string {
	major := rand.Intn(5) + 10
	minor := rand.Intn(10)
	patch := rand.Intn(20)
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func randomKernelVersion(osType string) string {
	if strContains(osType, "Windows") {
		return fmt.Sprintf("10.0.%d", rand.Intn(5000)+19000)
	} else if strContains(osType, "Mac") {
		return fmt.Sprintf("21.%d.%d", rand.Intn(7), rand.Intn(10))
	}
	return fmt.Sprintf("5.%d.%d", rand.Intn(20), rand.Intn(100))
}

func strContains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func init() {
	// Seed random at package init
	rand.Seed(time.Now().UnixNano())

	// Force use of runtime to avoid unused import
	_ = runtime.GOOS
}
