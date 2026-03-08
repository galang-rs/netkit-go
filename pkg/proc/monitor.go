package proc

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

var (
	modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")

	modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess               = modKernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle               = modKernel32.NewProc("CloseHandle")
)

var Verbose = false

const (
	TCP_TABLE_OWNER_PID_ALL           = 5
	AF_INET                           = 2
	AF_INET6                          = 23
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

// MIB_TCPROW_OWNER_PID represents a single row in the TCP table
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID represents a single row in the UDP table
type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// MIB_TCP6ROW_OWNER_PID represents a single row in the TCP6 table
type MIB_TCP6ROW_OWNER_PID struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

// MIB_UDP6ROW_OWNER_PID represents a single row in the UDP6 table
type MIB_UDP6ROW_OWNER_PID struct {
	LocalAddr    [16]byte
	LocalScopeId uint32
	LocalPort    uint32
	OwningPid    uint32
}

// GetPortsByPID returns a list of local ports currently owned by the given PID
func GetPortsByPID(pid int) ([]uint16, error) {
	var size uint32
	// Initial size check
	ret, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	// ERROR_INSUFFICIENT_BUFFER = 122
	// If ret is 0, it means it somehow succeeded with 0 size, which is unlikely but possible
	if ret != 122 && ret != 0 {
		return nil, fmt.Errorf("initial GetExtendedTcpTable call failed: %d", ret)
	}

	var buf []byte
	// Retry up to 3 times if size changes between calls
	for i := 0; i < 3; i++ {
		if size == 0 {
			break
		}
		buf = make([]byte, size)
		ret, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			AF_INET,
			TCP_TABLE_OWNER_PID_ALL,
			0,
		)
		if ret == 0 {
			break
		}
		if ret != 122 {
			return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
		}
		// size was updated, loop again
	}

	if len(buf) < 4 {
		return nil, nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})

	var ports []uint16
	for i := uint32(0); i < numEntries; i++ {
		// Calculate offset safely: offset starts at byte 4
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
		if row.OwningPid == uint32(pid) {
			port := syscall.Ntohs(uint16(row.LocalPort))
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// ConnectionInfo holds details about a system-level connection
type ConnectionInfo struct {
	PID        uint32
	RemoteIP   string
	RemotePort uint16
}

// GetSystemConnections returns mappings from local ports to connection details for both TCP and UDP.
// This is used to proactively seed the sniffer's connection map.
func GetSystemConnections() (tcp map[uint16]ConnectionInfo, udp map[uint16]ConnectionInfo, err error) {
	tcp = make(map[uint16]ConnectionInfo)
	udp = make(map[uint16]ConnectionInfo)

	// --- TCP IPv4 ---
	var tcpSize uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&tcpSize)), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

	var tcpBuf []byte
	for i := 0; i < 3; i++ {
		if tcpSize == 0 {
			break
		}
		tcpBuf = make([]byte, tcpSize)
		ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&tcpBuf[0])), uintptr(unsafe.Pointer(&tcpSize)), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
		if ret == 0 {
			break
		}
		if ret != 122 {
			break // unexpected error
		}
	}

	if len(tcpBuf) >= 4 {
		numEntries := binary.LittleEndian.Uint32(tcpBuf[0:4])
		rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})
		for i := uint32(0); i < numEntries; i++ {
			offset := 4 + uintptr(i)*rowSize
			if offset+rowSize > uintptr(len(tcpBuf)) {
				break
			}
			row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&tcpBuf[offset]))
			localPort := syscall.Ntohs(uint16(row.LocalPort))
			remoteIP := net.IPv4(byte(row.RemoteAddr), byte(row.RemoteAddr>>8), byte(row.RemoteAddr>>16), byte(row.RemoteAddr>>24)).String()
			remotePort := syscall.Ntohs(uint16(row.RemotePort))

			// Only track real external connections
			if remoteIP != "0.0.0.0" && remoteIP != "127.0.0.1" {
				tcp[localPort] = ConnectionInfo{
					PID:        row.OwningPid,
					RemoteIP:   remoteIP,
					RemotePort: remotePort,
				}
			}
		}
	}

	// --- UDP IPv4 ---
	var udpSize uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&udpSize)), 0, AF_INET, 1, 0)

	var udpBuf []byte
	for i := 0; i < 3; i++ {
		if udpSize == 0 {
			break
		}
		udpBuf = make([]byte, udpSize)
		ret, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&udpBuf[0])), uintptr(unsafe.Pointer(&udpSize)), 0, AF_INET, 1, 0)
		if ret == 0 {
			break
		}
		if ret != 122 {
			break
		}
	}

	if len(udpBuf) >= 4 {
		numEntries := binary.LittleEndian.Uint32(udpBuf[0:4])
		rowSize := unsafe.Sizeof(MIB_UDPROW_OWNER_PID{})
		for i := uint32(0); i < numEntries; i++ {
			offset := 4 + uintptr(i)*rowSize
			if offset+rowSize > uintptr(len(udpBuf)) {
				break
			}
			row := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&udpBuf[offset]))
			localPort := syscall.Ntohs(uint16(row.LocalPort))
			udp[localPort] = ConnectionInfo{
				PID: row.OwningPid,
			}
		}
	}

	return tcp, udp, nil
}

// GetAllPortPIDMappings exists for backward compatibility, now uses GetSystemConnections
func GetAllPortPIDMappings() (tcp map[uint16]uint32, udp map[uint16]uint32, err error) {
	tConns, uConns, err := GetSystemConnections()
	if err != nil {
		return nil, nil, err
	}
	tcp = make(map[uint16]uint32)
	udp = make(map[uint16]uint32)
	for p, info := range tConns {
		tcp[p] = info.PID
	}
	for p, info := range uConns {
		udp[p] = info.PID
	}
	return tcp, udp, nil
}

var (
	nameCache = make(map[uint32]string)
	nameMu    sync.RWMutex
)

// WarmProcessCache pre-populates the name cache for a list of PIDs
func WarmProcessCache(pids []uint32) {
	// For now, we just rely on GetProcessName being called.
	// In a future optimization, we could use a single 'tasklist' or 'wmic' call for all PIDs.
	for _, pid := range pids {
		GetProcessName(pid)
	}
}

// GetProcessName returns the executable name for a given PID.
// It uses a cache and performs lazy lookup via native Windows API if needed.
func GetProcessName(pid uint32) string {
	if pid == 0 {
		return "System"
	}

	nameMu.RLock()
	if name, ok := nameCache[pid]; ok {
		nameMu.RUnlock()
		return name
	}
	nameMu.RUnlock()

	// High-performance path: Native Windows API
	name := "unknown"
	handle, _, _ := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)

	if handle != 0 {
		defer procCloseHandle.Call(handle)
		var buf [syscall.MAX_PATH]uint16
		size := uint32(len(buf))
		ret, _, _ := procQueryFullProcessImageName.Call(
			handle,
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if ret != 0 {
			fullPath := syscall.UTF16ToString(buf[:size])
			name = filepath.Base(fullPath)
		}
	}

	nameMu.Lock()
	nameCache[pid] = name
	nameMu.Unlock()

	return name
}
