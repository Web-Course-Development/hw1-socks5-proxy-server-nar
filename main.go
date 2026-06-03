package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1. Read client greeting and negotiate authentication method
	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation failed: %v", err)
		return
	}

	// 2. Perform authentication if required (when PROXY_USER env var is set)
	if method == 0x02 {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("authentication failed: %v", err)
			return
		}
	}

	// 3-5. Read the CONNECT request, dial the target, and send the reply.
	target, err := handleConnect(conn)
	if err != nil {
		log.Printf("connect failed: %v", err)
		return
	}
	defer target.Close()

	// 6. Relay data bidirectionally between client and target until both
	// directions close.
	relay(conn, target)
}

// relay copies data bidirectionally between the client and target connections,
// returning only after both directions have finished. When one direction's copy
// completes, it half-closes (CloseWrite) the destination so the peer observes
// EOF, allowing the other direction to drain and finish cleanly.
func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> target.
	go func() {
		defer wg.Done()
		io.Copy(target, client)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target -> client.
	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if cc, ok := client.(*net.TCPConn); ok {
			cc.CloseWrite()
		}
	}()

	wg.Wait()
}

// negotiateAuth reads the client greeting [VER, NMETHODS, METHODS...] and
// selects an authentication method based on the environment. If PROXY_USER is
// set, method 0x02 (username/password) is required; otherwise method 0x00
// (no auth) is accepted. On success it replies [0x05, method] and returns the
// selected method. If the client did not offer the required method, it replies
// [0x05, 0xFF] and returns an error.
func negotiateAuth(conn net.Conn) (byte, error) {
	// Read VER and NMETHODS.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("reading greeting header: %w", err)
	}
	if header[0] != 0x05 {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	// Read the advertised methods.
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, fmt.Errorf("reading methods: %w", err)
	}

	// Decide which method we require.
	var required byte = 0x00
	if os.Getenv("PROXY_USER") != "" {
		required = 0x02
	}

	// Check whether the client offered the required method.
	offered := false
	for _, m := range methods {
		if m == required {
			offered = true
			break
		}
	}

	if !offered {
		// No acceptable methods.
		if _, err := conn.Write([]byte{0x05, 0xFF}); err != nil {
			return 0, fmt.Errorf("writing no-acceptable-methods reply: %w", err)
		}
		return 0, fmt.Errorf("client did not offer required auth method 0x%02x", required)
	}

	if _, err := conn.Write([]byte{0x05, required}); err != nil {
		return 0, fmt.Errorf("writing method selection: %w", err)
	}
	return required, nil
}

// authenticateUserPass performs the RFC 1929 username/password sub-negotiation.
// The sub-negotiation version byte is 0x01 (NOT 0x05). It reads
// [VER, ULEN, USERNAME, PLEN, PASSWORD] and compares against PROXY_USER /
// PROXY_PASS. On success it replies [0x01, 0x00]; on mismatch it replies
// [0x01, 0x01] and returns an error.
func authenticateUserPass(conn net.Conn) error {
	// Read VER and ULEN.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("reading auth header: %w", err)
	}
	if header[0] != 0x01 {
		return fmt.Errorf("unsupported auth sub-negotiation version: %d", header[0])
	}

	// Read the username.
	ulen := int(header[1])
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("reading username: %w", err)
	}

	// Read PLEN.
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return fmt.Errorf("reading password length: %w", err)
	}

	// Read the password.
	plen := int(plenBuf[0])
	password := make([]byte, plen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	// Compare against the configured credentials.
	if string(username) == os.Getenv("PROXY_USER") && string(password) == os.Getenv("PROXY_PASS") {
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return fmt.Errorf("writing auth success reply: %w", err)
		}
		return nil
	}

	if _, err := conn.Write([]byte{0x01, 0x01}); err != nil {
		return fmt.Errorf("writing auth failure reply: %w", err)
	}
	return errors.New("invalid username or password")
}

// sendReply writes a SOCKS5 reply with the given REP code. The bound
// address/port fields are always [0x01, 0,0,0,0, 0,0] (IPv4 0.0.0.0:0), which
// is acceptable for a CONNECT response per RFC 1928.
func sendReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// handleConnect parses the SOCKS5 CONNECT request, dials the requested target,
// and sends the corresponding reply. Only the CONNECT command (0x01) and the
// IPv4 (0x01) and domain-name (0x03) address types are supported. On success it
// returns the dialed target connection; on any failure it sends an error reply
// and returns an error.
func handleConnect(conn net.Conn) (net.Conn, error) {
	// Read VER, CMD, RSV, ATYP.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading request header: %w", err)
	}
	ver, cmd, atyp := header[0], header[1], header[3]
	if ver != 0x05 {
		return nil, fmt.Errorf("unsupported SOCKS version in request: %d", ver)
	}

	// Only CONNECT is supported.
	if cmd != 0x01 {
		sendReply(conn, 0x07) // command not supported
		return nil, fmt.Errorf("unsupported command: 0x%02x", cmd)
	}

	// Parse the destination address based on ATYP.
	var host string
	switch atyp {
	case 0x01: // IPv4: exactly 4 bytes
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("reading IPv4 address: %w", err)
		}
		host = net.IP(addr).String()
	case 0x03: // Domain name: 1 length byte followed by the name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, fmt.Errorf("reading domain length: %w", err)
		}
		name := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return nil, fmt.Errorf("reading domain name: %w", err)
		}
		host = string(name)
	default:
		sendReply(conn, 0x08) // address type not supported
		return nil, fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}

	// Read the 2-byte big-endian port.
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("reading port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Dial the target.
	addr := fmt.Sprintf("%s:%d", host, port)
	target, err := net.Dial("tcp", addr)
	if err != nil {
		sendReply(conn, 0x05) // connection refused
		return nil, fmt.Errorf("dialing target %s: %w", addr, err)
	}

	// Success.
	if err := sendReply(conn, 0x00); err != nil {
		target.Close()
		return nil, fmt.Errorf("writing success reply: %w", err)
	}
	return target, nil
}
