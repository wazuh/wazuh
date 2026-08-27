// Package wire speaks the bytes the manager expects: authd enrollment, the
// wazuh-agent+jwt bearer token every HTTPS request carries, and the HTTPS and
// Unix-socket transports. It knows nothing about scenarios (see
// docu/04-wire-protocol.md).
package wire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// ProtocolVersion is the value of the `protocol-version` header the manager's
// auth gateway expects (authTypes.hpp: kSupportedProtocolVersion "1").
const ProtocolVersion = "1"

// The closed `wazuh-agent+jwt` profile (src/shared_modules/utils/jwt/jwtProfileV1.hpp).
// Nothing here is negotiable: the manager rejects any deviation as an invalid token.
const (
	TokenType      = "wazuh-agent+jwt"
	tokenAlgorithm = "HS256"
	issuerPrefix   = "wazuh-agent/"
	// TokenLifetime is the declared lifetime of every token (exp - iat), a profile
	// constant. The manager may accept a token for less time (remoted.jwt_max_age),
	// never more.
	TokenLifetime int64 = 60
	agentKeyBytes       = 32
	jtiBytes            = 16
)

// jwtHeader and jwtClaims are serialised with encoding/json, whose output is compact
// and follows struct field order. The fields are declared alphabetically so the text
// is byte-identical to what the manager's own signer (and a nlohmann-backed jwt-cpp
// builder) emits -- which is what lets jwt_test.go reproduce the frozen vector exactly.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Iss string `json:"iss"`
	Jti string `json:"jti"`
	Nbf int64  `json:"nbf"`
	Sub string `json:"sub"`
}

var b64 = base64.RawURLEncoding

// DecodeAgentKey turns the client.keys secret (exactly 64 lowercase hex chars) into
// the 32-byte HS256 key. Anything else is refused: the manager's keystore applies the
// same rule, and signing with the ASCII text instead of the decoded bytes is the classic
// interoperability mistake (the frozen vectors pin it as a negative case).
func DecodeAgentKey(keyHex string) ([]byte, error) {
	if len(keyHex) != 2*agentKeyBytes {
		return nil, fmt.Errorf("agent key must be %d hex chars, got %d", 2*agentKeyBytes, len(keyHex))
	}
	for _, c := range keyHex {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, fmt.Errorf("agent key must be lowercase hex, got %q", c)
		}
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("agent key is not valid hex: %w", err)
	}
	return key, nil
}

// CanonicalAgentID returns the agent id as client.keys spells it -- decimal, zero-padded
// to at least three digits ("1" -> "001") -- which is the only spelling the manager
// accepts in kid/sub/iss. authd already answers in this form; this exists for callers
// that build an Identity by hand.
func CanonicalAgentID(id string) (string, error) {
	n, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return "", fmt.Errorf("agent id %q is not a decimal number: %w", id, err)
	}
	return fmt.Sprintf("%03d", n), nil
}

// NewJTI returns a fresh token id: 16 CSPRNG bytes as 22 unpadded base64url chars.
func NewJTI() (string, error) {
	var raw [jtiBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("jti: %w", err)
	}
	return b64.EncodeToString(raw[:]), nil
}

// Sign mints one wazuh-agent+jwt token for agentID with the client.keys secret keyHex,
// as of now (unix seconds). jti is normally "" (a fresh random id); tests pass a fixed
// one to reproduce the frozen vectors. The result is the compact JWS the Authorization
// header carries after "Bearer ".
func Sign(keyHex, agentID string, now int64, jti string) (string, error) {
	key, err := DecodeAgentKey(keyHex)
	if err != nil {
		return "", err
	}
	kid, err := CanonicalAgentID(agentID)
	if err != nil {
		return "", err
	}
	if now < 0 {
		return "", fmt.Errorf("clock before the epoch: %d", now)
	}
	if jti == "" {
		if jti, err = NewJTI(); err != nil {
			return "", err
		}
	}

	header, err := json.Marshal(jwtHeader{Alg: tokenAlgorithm, Kid: kid, Typ: TokenType})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(jwtClaims{
		Exp: now + TokenLifetime,
		Iat: now,
		Iss: issuerPrefix + kid,
		Jti: jti,
		Nbf: now,
		Sub: kid,
	})
	if err != nil {
		return "", err
	}

	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil)), nil
}

// AuthHeaders returns the two headers every authenticated request carries. Called once
// per attempt -- retries included -- so every request on the wire has a fresh token
// (new jti, new iat). The token binds the agent's identity only: not the method, not
// the target, not the body (TLS protects the channel).
func AuthHeaders(keyHex, agentID string, now int64) (map[string]string, error) {
	token, err := Sign(keyHex, agentID, now, "")
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"protocol-version": ProtocolVersion,
		"Authorization":    "Bearer " + token,
	}, nil
}
