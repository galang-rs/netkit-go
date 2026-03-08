package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/bacot120211/netkit-go/pkg/capture"
)

type ServiceDiscovery struct {
	Verbose bool
	Sniffer *capture.Sniffer
}

func NewServiceDiscovery(sniffer *capture.Sniffer) *ServiceDiscovery {
	return &ServiceDiscovery{
		Sniffer: sniffer,
	}
}

func (s *ServiceDiscovery) Start(ctx context.Context) error {
	fmt.Println("[Discovery] Starting mDNS, SSDP, and NBNS listeners...")

	go s.listenMDNS(ctx)
	go s.listenSSDP(ctx)
	go s.listenNBNS(ctx)

	return nil
}

func (s *ServiceDiscovery) listenMDNS(ctx context.Context) {
	// mDNS: 224.0.0.251:5353
	addr, _ := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		fmt.Printf("[Discovery] mDNS Listen failed: %v\n", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if s.Verbose {
				fmt.Printf("[Discovery] [mDNS] %s -> %d bytes\n", src, n)
			}
		}
	}
}

func (s *ServiceDiscovery) listenSSDP(ctx context.Context) {
	// SSDP: 239.255.255.250:1900
	addr, _ := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		fmt.Printf("[Discovery] SSDP Listen failed: %v\n", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			payload := string(buf[:n])
			if strings.Contains(payload, "NOTIFY") || strings.Contains(payload, "M-SEARCH") {
				if s.Verbose {
					fmt.Printf("[Discovery] [SSDP] %s -> %s\n", src, payload)
				}
			}
		}
	}
}

func (s *ServiceDiscovery) listenNBNS(ctx context.Context) {
	// NBNS/NetBIOS: UDP 137
	addr, _ := net.ResolveUDPAddr("udp4", ":137")
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		fmt.Printf("[Discovery] NBNS Listen failed: %v\n", err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if n > 12 {
				// Simple NBNS name extract (first name in question section)
				// NBNS names are encoded: 32 bytes of 'A'+half-byte
				if n >= 45 {
					nameEnc := buf[13:45]
					var nameDec []byte
					for i := 0; i < len(nameEnc); i += 2 {
						c := ((nameEnc[i]-'A')<<4 | (nameEnc[i+1] - 'A'))
						if c > 0 && c != 0x20 { // 0x20 is space in NetBIOS encoding sometimes
							nameDec = append(nameDec, c)
						}
					}
					hostname := strings.TrimSpace(string(nameDec))
					if hostname != "" && s.Sniffer != nil {
						s.Sniffer.AddDomainMapping(src.IP.String(), hostname)
						if s.Verbose {
							fmt.Printf("[Discovery] [NBNS] Learned: %s -> %s\n", src.IP, hostname)
						}
					}
				}
			}
		}
	}
}
