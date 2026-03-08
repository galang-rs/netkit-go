package tests

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestBind(t *testing.T) {
	proxy := "127.0.0.1:1111"

	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		fmt.Printf("Dial proxy failed: %v\n", err)
		return
	}
	defer conn.Close()

	// 1. Negotiation (No Auth)
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(conn, buf)
	if buf[1] != 0x00 {
		fmt.Printf("Negotiation failed: %02x\n", buf[1])
		return
	}

	// 2. BIND Request
	// CMD=0x02, ATYP=0x01 (IPv4), Addr=127.0.0.1, Port=2222
	req := []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	conn.Write(req)

	// 3. First Success Response (Bind Addr)
	resp := make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		fmt.Printf("Read first response failed: %v\n", err)
		return
	}
	if resp[1] != 0x00 {
		fmt.Printf("BIND request failed: %02x\n", resp[1])
		return
	}

	bindPort := int(resp[8])<<8 | int(resp[9])
	fmt.Printf("BIND SUCCESS! Listening on port: %d\n", bindPort)

	// 4. Connect to the bind port from a second goroutine (simulating target)
	go func() {
		time.Sleep(1 * time.Second)
		fmt.Printf("Simulating target connection to port %d...\n", bindPort)
		targetConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort))
		if err != nil {
			fmt.Printf("Target connection failed: %v\n", err)
			return
		}
		targetConn.Write([]byte("HELLO FROM TARGET"))
		// Keep targetConn open for a moment to ensure read succeeds
		time.Sleep(1 * time.Second)
		targetConn.Close()
	}()

	// 5. Wait for Second Success Response (Confirming connection)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		fmt.Printf("Read second response failed: %v\n", err)
		return
	}
	if resp[1] != 0x00 {
		fmt.Printf("BIND confirm failed: %02x\n", resp[1])
		return
	}
	fmt.Println("BIND CONFIRMED! Target connected.")

	// 6. Read data from target via proxy
	data := make([]byte, 100)
	n, err := conn.Read(data)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}
	fmt.Printf("RECEIVED: %s\n", string(data[:n]))
}
