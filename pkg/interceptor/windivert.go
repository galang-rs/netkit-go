package interceptor

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/bacot120211/netkit-go/pkg/engine"
	"github.com/bacot120211/netkit-go/pkg/logger"
)

// TransparentInterceptor implements the "WinDivert concept" without using the actual WinDivert driver.
// It uses native Windows tools like 'netsh' for TCP redirection and Raw Sockets for UDP observation.
type TransparentInterceptor struct {
	engine    engine.Engine
	activeTCP []string // List of redirected ports to cleanup
}

func NewTransparentInterceptor(e engine.Engine) *TransparentInterceptor {
	return &TransparentInterceptor{
		engine: e,
	}
}

func (t *TransparentInterceptor) Name() string {
	return "Driverless Transparent Interceptor"
}

func (t *TransparentInterceptor) Start() error {
	logger.Printf("[Transparent] Starting driverless interception mode...\n")

	// Ensure cleanup on exit
	t.Cleanup()

	return nil
}

// RedirectTCP uses 'netsh interface portproxy' to redirect outbound traffic.
// Note: This requires administrator privileges.
func (t *TransparentInterceptor) RedirectTCP(listenAddr string, listenPort uint16, connectAddr string, connectPort uint16) error {
	cmdStr := fmt.Sprintf("interface portproxy add v4tov4 listenaddress=%s listenport=%d connectaddress=%s connectport=%d",
		listenAddr, listenPort, connectAddr, connectPort)

	logger.Printf("[Transparent] [TCP] Executing: netsh %s\n", cmdStr)
	cmd := exec.Command("netsh", strings.Split(cmdStr, " ")...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute netsh: %w (ensure you are running as Admin)", err)
	}

	id := fmt.Sprintf("%s:%d", listenAddr, listenPort)
	t.activeTCP = append(t.activeTCP, id)
	return nil
}

func (t *TransparentInterceptor) Cleanup() {
	if len(t.activeTCP) == 0 {
		return
	}

	logger.Printf("[Transparent] Cleaning up netsh redirection rules...\n")
	for _, id := range t.activeTCP {
		parts := strings.Split(id, ":")
		if len(parts) != 2 {
			continue
		}
		addr := parts[0]
		port := parts[1]
		cmdStr := fmt.Sprintf("interface portproxy delete v4tov4 listenaddress=%s listenport=%s", addr, port)
		_ = exec.Command("netsh", strings.Split(cmdStr, " ")...).Run()
	}
	t.activeTCP = nil
}

func (t *TransparentInterceptor) OnConnect(conn *engine.ConnInfo) *engine.TunnelConfig {
	return nil
}

func (t *TransparentInterceptor) OnPacket(ctx *engine.PacketContext) error {
	// For driverless mode, we tag the packet so the JS hook knows it was
	// captured via transparent redirection or raw socket sniffing.
	if ctx.Packet.Metadata == nil {
		ctx.Packet.Metadata = make(map[string]interface{})
	}
	ctx.Packet.Metadata["Transparent"] = true

	// Returning nil allows it to flow to the next interceptor (like JSInterceptor).
	return nil
}
