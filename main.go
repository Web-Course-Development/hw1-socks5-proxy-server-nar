package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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

	// Phase 1 complete: authentication handshake done.
	// TODO Phase 2:
	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target
	return
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
