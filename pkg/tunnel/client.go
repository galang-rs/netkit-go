package tunnel

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHTransportConfig holds SSH transport configuration for NK-Tunnel client.
type SSHTransportConfig struct {
	Host       string
	Port       int
	User       string
	Pass       string
	PrivateKey string // Path to private key file or raw PEM content
}

type NKTunnelClient struct {
	ServerAddr      string
	User            string
	Pass            string
	LocalAddr       string
	RemotePortRange string
	Protocol        string
	SSHConfig       *SSHTransportConfig // Optional: SSH transport
	ControlConn     net.Conn
	sshClient       *ssh.Client // SSH client for cleanup
	streams         map[uint32]net.Conn
	pending         map[uint32]chan []byte // Buffer for initial frames during Dial
	udpConns        map[uint32]net.PacketConn
	streamMu        sync.RWMutex
	writeMu         sync.Mutex // protects concurrent writes to ControlConn
	stopCh          chan struct{}
	assignedStart   int
	assignedEnd     int
	serverPublicIP4 string
	serverPublicIP6 string
	connected       bool
}

func NewNKTunnelClient(server, user, pass, local string, remotePortRange string, proto string) *NKTunnelClient {
	return &NKTunnelClient{
		ServerAddr:      server,
		User:            user,
		Pass:            pass,
		LocalAddr:       local,
		RemotePortRange: remotePortRange,
		Protocol:        proto,
		streams:         make(map[uint32]net.Conn),
		pending:         make(map[uint32]chan []byte),
		udpConns:        make(map[uint32]net.PacketConn),
		stopCh:          make(chan struct{}),
	}
}

func (c *NKTunnelClient) Start() error {
	var conn net.Conn
	var err error

	if c.SSHConfig != nil {
		conn, err = c.dialViaSSH()
		if err != nil {
			return fmt.Errorf("ssh transport error: %w", err)
		}
		fmt.Printf("[NK-Tunnel] Connected to %s via SSH (%s:%d)\n", c.ServerAddr, c.SSHConfig.Host, c.SSHConfig.Port)
	} else {
		conn, err = net.Dial("tcp", c.ServerAddr)
		if err != nil {
			return err
		}
		fmt.Printf("[NK-Tunnel] Connected to %s\n", c.ServerAddr)
	}
	c.ControlConn = conn

	// 1. Auth
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "%s %s %s\n", CmdAuth, c.User, c.Pass)
	resp := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(resp)
	if err != nil || !strings.Contains(string(resp[:n]), CmdOk) {
		return fmt.Errorf("auth failed: %s", string(resp[:n]))
	}

	// 2. Req
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "%s %s %s\n", CmdReq, c.Protocol, c.RemotePortRange)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = conn.Read(resp)
	if err != nil || !strings.Contains(string(resp[:n]), CmdRes) {
		return fmt.Errorf("request failed: %s", string(resp[:n]))
	}

	// Parse response: "RES <start> <end> <publicIP>"
	respStr := strings.TrimSpace(string(resp[:n]))
	parts := strings.Fields(respStr)
	if len(parts) >= 3 {
		fmt.Sscanf(parts[1], "%d", &c.assignedStart)
		fmt.Sscanf(parts[2], "%d", &c.assignedEnd)
	}
	if len(parts) >= 4 {
		ip := parts[3]
		if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil {
			c.serverPublicIP4 = ip
		} else {
			c.serverPublicIP6 = ip
		}
	}

	c.connected = true
	conn.SetDeadline(time.Time{}) // Clear deadlines before starting loops

	fmt.Printf("[NK-Tunnel] Tunnel established: ports %d-%d on %s (v4), %s (v6)\n",
		c.assignedStart, c.assignedEnd, c.serverPublicIP4, c.serverPublicIP6)

	// 3. Process Frames
	go c.runFrameLoop()

	// 4. Start keep-alive (PING every 25s)
	go c.keepAlive()

	return nil
}

// Stop gracefully shuts down the tunnel client.
func (c *NKTunnelClient) Stop() {
	c.connected = false
	select {
	case <-c.stopCh:
		// Already closed
	default:
		close(c.stopCh)
	}
	if c.ControlConn != nil {
		c.ControlConn.Close()
	}
	if c.sshClient != nil {
		c.sshClient.Close()
	}
}

// dialViaSSH connects to the NK-Tunnel server through an SSH tunnel.
// It first dials the SSH server, then creates a forwarded channel to the tunnel server address.
func (c *NKTunnelClient) dialViaSSH() (net.Conn, error) {
	cfg := c.SSHConfig
	if cfg.Port == 0 {
		cfg.Port = 22
	}

	sshAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	// Build auth methods
	var authMethods []ssh.AuthMethod
	if cfg.Pass != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Pass))
	}
	if cfg.PrivateKey != "" {
		var keyData []byte
		var err error
		// Check if it's a file path or raw PEM
		if _, statErr := os.Stat(cfg.PrivateKey); statErr == nil {
			keyData, err = os.ReadFile(cfg.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("read SSH key file: %w", err)
			}
		} else {
			keyData = []byte(cfg.PrivateKey)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("SSH config requires either password or private key")
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	fmt.Printf("[NK-Tunnel] 🔑 Dialing SSH %s@%s ...\n", cfg.User, sshAddr)

	// Connect to SSH server
	sshClient, err := ssh.Dial("tcp", sshAddr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("SSH dial error: %w", err)
	}
	c.sshClient = sshClient

	fmt.Printf("[NK-Tunnel] 🔑 SSH connected, tunneling to %s ...\n", c.ServerAddr)

	// Create forwarded TCP connection to the tunnel server through SSH
	conn, err := sshClient.Dial("tcp", c.ServerAddr)
	if err != nil {
		sshClient.Close()
		c.sshClient = nil
		return nil, fmt.Errorf("SSH tunnel to %s error: %w", c.ServerAddr, err)
	}

	return conn, nil
}

// GetAssignedPorts returns the port range assigned by the server.
func (c *NKTunnelClient) GetAssignedPorts() (start, end int) {
	return c.assignedStart, c.assignedEnd
}

// GetServerPublicIP returns the public IPv4 of the tunnel server.
func (c *NKTunnelClient) GetServerPublicIP() string {
	return c.serverPublicIP4
}

// GetServerPublicIPs returns both public IPs of the tunnel server.
func (c *NKTunnelClient) GetServerPublicIPs() (string, string) {
	return c.serverPublicIP4, c.serverPublicIP6
}

// GetPublicEndpoints returns all public endpoints that external clients can connect to.
func (c *NKTunnelClient) GetPublicEndpoints() []string {
	if (c.serverPublicIP4 == "" && c.serverPublicIP6 == "") || c.assignedStart == 0 {
		return nil
	}
	var endpoints []string
	for p := c.assignedStart; p <= c.assignedEnd; p++ {
		if c.serverPublicIP4 != "" {
			endpoints = append(endpoints, fmt.Sprintf("%s:%d", c.serverPublicIP4, p))
		}
		if c.serverPublicIP6 != "" {
			endpoints = append(endpoints, fmt.Sprintf("[%s]:%d", c.serverPublicIP6, p))
		}
	}
	return endpoints
}

// IsConnected returns whether the tunnel is active.
func (c *NKTunnelClient) IsConnected() bool {
	return c.connected
}

// keepAlive sends periodic PING frames to keep the tunnel alive.
func (c *NKTunnelClient) keepAlive() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if !c.connected {
				return
			}
			err := c.writeFrame(c.ControlConn, StreamIDPing, []byte("PING"))
			if err != nil {
				fmt.Printf("[NK-Tunnel] Keep-alive failed: %v\n", err)
				c.connected = false
				return
			}
		}
	}
}

func (c *NKTunnelClient) runFrameLoop() {
	defer func() {
		c.connected = false
		c.ControlConn.Close()
	}()
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		frame, err := c.readFrame(c.ControlConn)
		if err != nil {
			break
		}

		// Handle PING/PONG keep-alive (StreamID 0 is reserved)
		if frame.StreamID == StreamIDPing {
			// PONG response from server — just ignore
			continue
		}

		c.streamMu.RLock()
		stream, ok := c.streams[frame.StreamID]
		udpConn, udpOk := c.udpConns[frame.StreamID]
		pendingCh, isPending := c.pending[frame.StreamID]
		c.streamMu.RUnlock()

		if ok {
			if len(frame.Payload) == 0 {
				stream.Close()
				c.streamMu.Lock()
				delete(c.streams, frame.StreamID)
				c.streamMu.Unlock()
			} else {
				stream.Write(frame.Payload)
			}
			continue
		}

		if udpOk {
			addr, _ := net.ResolveUDPAddr("udp", c.LocalAddr)
			udpConn.WriteTo(frame.Payload, addr)
			continue
		}

		if isPending {
			// Buffer data while Dialing
			select {
			case pendingCh <- frame.Payload:
			default:
				// Buffer full? Drop to avoid blocking the loop
			}
			continue
		}

		// New stream?
		payload := string(frame.Payload)
		if strings.HasPrefix(payload, "OPEN") {
			ch := make(chan []byte, 100)
			c.streamMu.Lock()
			c.pending[frame.StreamID] = ch
			c.streamMu.Unlock()
			go c.handleNewStream(frame.StreamID, payload, ch)
		} else if c.Protocol == ProtoUDP {
			go c.handleNewUDPStream(frame.StreamID, frame.Payload)
		}
	}
}

func (c *NKTunnelClient) handleNewUDPStream(streamID uint32, firstPayload []byte) {
	conn, err := net.ListenPacket("udp", ":0") // ephemeral local port
	if err != nil {
		return
	}
	defer conn.Close()

	c.streamMu.Lock()
	c.udpConns[streamID] = conn
	c.streamMu.Unlock()
	defer func() {
		c.streamMu.Lock()
		delete(c.udpConns, streamID)
		c.streamMu.Unlock()
	}()

	addr, _ := net.ResolveUDPAddr("udp", c.LocalAddr)
	conn.WriteTo(firstPayload, addr)

	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFrom(buf)
		if n > 0 {
			if err := c.writeFrame(c.ControlConn, streamID, buf[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
}

func (c *NKTunnelClient) handleNewStream(streamID uint32, openPayload string, dataCh chan []byte) {
	localAddr := c.LocalAddr
	// If the OPEN payload contains a port (OPEN:port), we can potentially calculate a local port offset
	if strings.Contains(openPayload, ":") {
		parts := strings.Split(openPayload, ":")
		if len(parts) >= 2 {
			var remotePort int
			fmt.Sscanf(parts[1], "%d", &remotePort)

			// Simple offset mapping if RemotePortRange is a range
			if strings.Contains(c.RemotePortRange, "-") {
				var start, end int
				fmt.Sscanf(c.RemotePortRange, "%d-%d", &start, &end)
				offset := remotePort - start

				host, portStr, _ := net.SplitHostPort(c.LocalAddr)
				var localStart int
				fmt.Sscanf(portStr, "%d", &localStart)
				localAddr = fmt.Sprintf("%s:%d", host, localStart+offset)
			}
		}
	}

	local, err := net.Dial("tcp", localAddr)
	if err != nil {
		fmt.Printf("[NK-Tunnel] ❌ Failed to dial local %s for stream %d: %v\n", localAddr, streamID, err)
		c.streamMu.Lock()
		delete(c.pending, streamID)
		c.streamMu.Unlock()
		return
	}
	defer local.Close()
	fmt.Printf("[NK-Tunnel] 🔗 Forwarding stream %d to local %s\n", streamID, localAddr)

	c.streamMu.Lock()
	c.streams[streamID] = local
	delete(c.pending, streamID) // Switch from pending to active
	c.streamMu.Unlock()

	// Drain what was queued during Dial
drain:
	for {
		select {
		case data := <-dataCh:
			if len(data) > 0 {
				local.Write(data)
			}
		default:
			break drain
		}
	}

	// Relay local to control
	buf := make([]byte, 32*1024)
	for {
		n, err := local.Read(buf)
		if n > 0 {
			if writeErr := c.writeFrame(c.ControlConn, streamID, buf[:n]); writeErr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	// Send EOF frame (writeFrame handles its own mutex)
	c.writeFrame(c.ControlConn, streamID, nil)
	c.streamMu.Lock()
	delete(c.streams, streamID)
	c.streamMu.Unlock()
}

func (c *NKTunnelClient) readFrame(conn net.Conn) (*Frame, error) {
	header := make([]byte, 8)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	streamID := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	length := uint32(header[4])<<24 | uint32(header[5])<<16 | uint32(header[6])<<8 | uint32(header[7])

	payload := make([]byte, length)
	if length > 0 {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
	}
	return &Frame{StreamID: streamID, Payload: payload}, nil
}

func (c *NKTunnelClient) writeFrame(conn net.Conn, streamID uint32, payload []byte) error {
	length := uint32(len(payload))
	header := []byte{
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
		byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length),
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if length > 0 {
		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		_, err := conn.Write(payload)
		return err
	}
	return nil
}

// ============================================================
// SSH Reverse Port Forwarding (ssh -R equivalent)
// ============================================================

// SSHReverseTunnel exposes a local service on a remote SSH server's IP.
// Equivalent to: ssh -R remote_port:local_addr user@ssh_host
type SSHReverseTunnel struct {
	SSH        *SSHTransportConfig
	LocalAddr  string // e.g. "127.0.0.1:5500"
	RemoteBind string // e.g. "0.0.0.0:80" (bind on SSH server)
	sshClient  *ssh.Client
	listener   net.Listener
	stopCh     chan struct{}
	connected  bool
}

// NewSSHReverseTunnel creates a new SSH reverse tunnel.
func NewSSHReverseTunnel(sshCfg *SSHTransportConfig, localAddr, remoteBind string) *SSHReverseTunnel {
	return &SSHReverseTunnel{
		SSH:        sshCfg,
		LocalAddr:  localAddr,
		RemoteBind: remoteBind,
		stopCh:     make(chan struct{}),
	}
}

// Start connects to the SSH server and begins reverse forwarding.
func (t *SSHReverseTunnel) Start() error {
	cfg := t.SSH
	if cfg.Port == 0 {
		cfg.Port = 22
	}

	sshAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	// Build auth methods
	var authMethods []ssh.AuthMethod
	if cfg.Pass != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Pass))
	}
	if cfg.PrivateKey != "" {
		var keyData []byte
		var err error
		if _, statErr := os.Stat(cfg.PrivateKey); statErr == nil {
			keyData, err = os.ReadFile(cfg.PrivateKey)
			if err != nil {
				return fmt.Errorf("read SSH key: %w", err)
			}
		} else {
			keyData = []byte(cfg.PrivateKey)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return fmt.Errorf("parse SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("SSH requires password or private key")
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	fmt.Printf("[SSH-Reverse] 🔑 Connecting to %s@%s ...\n", cfg.User, sshAddr)

	client, err := ssh.Dial("tcp", sshAddr, sshConfig)
	if err != nil {
		return fmt.Errorf("SSH dial error: %w", err)
	}
	t.sshClient = client

	// Request the SSH server to listen on the remote address
	listener, err := client.Listen("tcp", t.RemoteBind)
	if err != nil {
		client.Close()
		return fmt.Errorf("SSH remote listen on %s failed: %w", t.RemoteBind, err)
	}
	t.listener = listener
	t.connected = true

	fmt.Printf("[SSH-Reverse] ✅ Bound %s on %s → forwarding to local %s\n", t.RemoteBind, cfg.Host, t.LocalAddr)

	// Accept loop
	go t.acceptLoop()

	// Keep-alive
	go t.keepAlive()

	return nil
}

// Stop shuts down the SSH reverse tunnel.
func (t *SSHReverseTunnel) Stop() {
	t.connected = false
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	if t.listener != nil {
		t.listener.Close()
	}
	if t.sshClient != nil {
		t.sshClient.Close()
	}
}

// IsConnected returns whether the tunnel is active.
func (t *SSHReverseTunnel) IsConnected() bool {
	return t.connected
}

func (t *SSHReverseTunnel) acceptLoop() {
	defer func() {
		t.connected = false
	}()

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		remoteConn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			default:
			}
			fmt.Printf("[SSH-Reverse] ❌ Accept error: %v\n", err)
			continue
		}

		go t.handleConn(remoteConn)
	}
}

func (t *SSHReverseTunnel) handleConn(remote net.Conn) {
	defer remote.Close()

	local, err := net.DialTimeout("tcp", t.LocalAddr, 5*time.Second)
	if err != nil {
		fmt.Printf("[SSH-Reverse] ❌ Failed to connect to local %s: %v\n", t.LocalAddr, err)
		return
	}
	defer local.Close()

	fmt.Printf("[SSH-Reverse] 🔗 %s → %s\n", remote.RemoteAddr(), t.LocalAddr)

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(local, remote)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(remote, local)
		done <- struct{}{}
	}()
	<-done
}

func (t *SSHReverseTunnel) keepAlive() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			if !t.connected || t.sshClient == nil {
				return
			}
			_, _, err := t.sshClient.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				fmt.Printf("[SSH-Reverse] ❌ Keep-alive failed: %v\n", err)
				t.connected = false
				return
			}
		}
	}
}
