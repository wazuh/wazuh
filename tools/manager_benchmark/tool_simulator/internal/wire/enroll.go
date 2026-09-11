package wire

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Identity is a registered agent: its manager-issued id and the 64-hex secret its
// bearer tokens are signed with (see jwt.go).
type Identity struct {
	ID   string
	Name string
	Key  string // 64 lowercase hex chars, as it appears in client.keys
	// ReenrollSecret is the second 64-hex secret POST /enroll answers with (authd
	// stores it in global.db alone, never in client.keys). Kept with the key the way
	// a real agent keeps it, and never sent: it is what makes a token-bootstrapped
	// identity re-enrollable. Empty for an identity from Enroll below -- port 1515
	// issues none.
	ReenrollSecret string
}

// Enroll registers one agent against authd over TLS (plain-text protocol):
//
//	→  OSSEC A:'<name>'\n
//	←  OSSEC K:'<id> <name> <ip> <key>'\n
//
// The manager's certificate is accepted without verification (test managers
// are self-signed). A password-protected authd is intentionally unsupported:
// this is the LEGACY bootstrap (--bootstrap 1515), kept for comparison against
// the enrollment-token one, and it needs a manager opened with
// `prepare_manager.sh --open-1515` (<use_password>no</use_password>).
func Enroll(host string, port int, name string, timeout time.Duration) (Identity, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return Identity{}, fmt.Errorf("authd dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := fmt.Fprintf(conn, "OSSEC A:'%s'\n", name); err != nil {
		return Identity{}, fmt.Errorf("authd write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return Identity{}, fmt.Errorf("authd read: %w", err)
	}
	resp := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(resp, "ERROR") {
		return Identity{}, fmt.Errorf("authd refused %q: %s", name, resp)
	}

	// "OSSEC K:'<id> <name> <ip> <key>'"
	open := strings.IndexByte(resp, '\'')
	closeIdx := strings.LastIndexByte(resp, '\'')
	if open < 0 || closeIdx <= open {
		return Identity{}, fmt.Errorf("authd: unexpected response %q", resp)
	}
	fields := strings.Fields(resp[open+1 : closeIdx])
	if len(fields) < 4 {
		return Identity{}, fmt.Errorf("authd: short key body %q", resp)
	}
	return Identity{ID: fields[0], Name: name, Key: fields[3]}, nil
}
