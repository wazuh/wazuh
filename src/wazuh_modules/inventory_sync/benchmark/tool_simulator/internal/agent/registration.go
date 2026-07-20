// Package agent implements per-simulated-agent state: registration
// against authd (TLS+plain text), the TCP connection to remoted, the send
// mutex, the StartAck FIFO and the read goroutine that demuxes inbound
// frames to per-session inboxes. See docu/04-agent-state-machine.md and
// docu/05-wire-protocol.md.
package agent

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Identity is the registered agent's (id, name, manager-issued key).
type Identity struct {
	ID         string
	Name       string
	ManagerKey string
}

// Register opens a TLS connection to wazuh-authd, sends OSSEC A:'<name>'
// and parses the OSSEC K:'<id> <name> <ip> <key>' response. Mirrors
// benchmark_sender.py BenchmarkAgent.register.
func Register(host string, port int, name string, timeout time.Duration) (Identity, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // matches Python's CERT_NONE
	})
	if err != nil {
		return Identity{}, fmt.Errorf("authd dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("OSSEC A:'%s'\n", name)
	if _, err := conn.Write([]byte(req)); err != nil {
		return Identity{}, fmt.Errorf("authd write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return Identity{}, fmt.Errorf("authd read: %w", err)
	}
	resp := string(buf[:n])
	// "OSSEC K:'<id> <name> <ip> <key>'\n"
	parts := strings.Split(resp, "'")
	if len(parts) < 2 {
		return Identity{}, fmt.Errorf("authd: unexpected response %q", resp)
	}
	body := parts[1]
	fields := strings.Fields(body)
	if len(fields) < 4 {
		return Identity{}, fmt.Errorf("authd: short body %q", body)
	}
	return Identity{ID: fields[0], Name: name, ManagerKey: fields[3]}, nil
}
