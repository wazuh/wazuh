package wire

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

// ProtocolVersion is the value of the `protocol-version` header the manager's
// auth gateway expects (authTypes.hpp: supportedProtocolVersion "1").
const ProtocolVersion = "1"

// CanonicalString assembles the exact byte sequence the manager signs, per
// docu/04-wire-protocol.md. It MUST match authMiddleware.cpp byte for byte:
//
//	"WAZUH-REQUEST\n" version "\n" METHOD "\n" target "\n" agentID "\n" ts "\n" body
//
// with the body appended raw and no trailing newline. agentID and ts are the
// exact strings that go into the Authorization header.
func CanonicalString(protocolVersion, method, target, agentID, timestamp string, body []byte) []byte {
	head := "WAZUH-REQUEST\n" +
		protocolVersion + "\n" +
		method + "\n" +
		target + "\n" +
		agentID + "\n" +
		timestamp + "\n"
	out := make([]byte, 0, len(head)+len(body))
	out = append(out, head...)
	out = append(out, body...)
	return out
}

// Sign returns the lowercase-hex AES-CMAC of the canonical string, exactly 32
// characters. keyHex is the agent's enrollment key as it appears in
// client.keys (hex); it decodes to a 16/24/32-byte AES key.
func Sign(keyHex, method, target, agentID, timestamp string, body []byte) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("agent key is not valid hex: %w", err)
	}
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return "", fmt.Errorf("agent key must decode to 16, 24 or 32 bytes, got %d", l)
	}
	mac, err := AESCMAC(key, CanonicalString(ProtocolVersion, method, target, agentID, timestamp, body))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(mac), nil
}

// AuthHeaders returns the two headers every authenticated request carries.
func AuthHeaders(keyHex, method, target, agentID string, unixTimestamp int64, body []byte) (map[string]string, error) {
	ts := strconv.FormatInt(unixTimestamp, 10)
	mac, err := Sign(keyHex, method, target, agentID, ts, body)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"protocol-version": ProtocolVersion,
		"Authorization":    fmt.Sprintf("Wazuh %s:%s:%s", agentID, ts, mac),
	}, nil
}
