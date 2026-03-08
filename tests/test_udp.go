package tests

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestUDP(t *testing.T) {
	proxy := "127.0.0.1:1111"

	// 1. Establish TCP Control Connection
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		fmt.Printf("Dial proxy failed: %v\n", err)
		return
	}
	defer conn.Close()

	// Negotiation
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(conn, buf)
	fmt.Println("Negotiated SOCKS5")

	// 2. UDP ASSOCIATE Request
	req := []byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	conn.Write(req)

	resp := make([]byte, 10)
	io.ReadFull(conn, resp)
	if resp[1] != 0x00 {
		fmt.Printf("UDP ASSOCIATE failed: %02x\n", resp[1])
		return
	}

	relayPort := int(resp[8])<<8 | int(resp[9])
	relayIP := net.IP(resp[4:8]).String()
	fmt.Printf("UDP ASSOCIATE SUCCESS! Relay at %s:%d\n", relayIP, relayPort)

	// 3. Setup a local UDP server to receive the forwarded packet
	targetL, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3333})
	defer targetL.Close()

	go func() {
		buf := make([]byte, 1024)
		n, addr, _ := targetL.ReadFromUDP(buf)
		fmt.Printf("TARGET RECEIVED: %s from %s\n", string(buf[:n]), addr)
		// Echo back
		targetL.WriteToUDP([]byte("ECHO: "+string(buf[:n])), addr)
	}()

	// 4. Send encapsulated UDP packet to relay
	udpConn, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(relayIP), Port: relayPort})
	defer udpConn.Close()

	// Header: RSV=0, FRG=0, ATYP=1, IP=127.0.0.1, Port=3333
	header := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(3333 >> 8), byte(3333 & 0xFF)}
	payload := []byte("HELLO UDP")
	udpConn.Write(append(header, payload...))

	// 5. Read response from relay
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 1024)
	rn, _, err := udpConn.ReadFromUDP(respBuf)
	if err != nil {
		fmt.Printf("UDP Read error: %v\n", err)
	} else {
		fmt.Printf("RECEIVED FROM RELAY: %s\n", string(respBuf[:rn]))
	}
}
