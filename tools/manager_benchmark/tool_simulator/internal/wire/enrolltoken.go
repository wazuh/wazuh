package wire

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// EnrollTokenType is the `typ` of the enrollment bearer (jwtEnrollProfileV1.hpp): the sibling of
// TokenType for an agent that has no identity yet. Same HS256 core, same compact grammar, same
// 60 s lifetime; no `iss`/`sub`, since there is nothing to name.
const EnrollTokenType = "wazuh-enroll+jwt"

// The enrollment token's key material (jwtEnrollProfileV1.hpp / src/shared/include/enrollment_token.h):
// the token's `key` field is id || secret, 32 bytes; the first 16 name the token (the bearer's
// `kid`, 22 canonical base64url chars), the last 16 are the secret its HS256 key is derived from.
const (
	enrollTokenIDBytes     = 16
	enrollTokenSecretBytes = 16
	// HKDF-SHA256 parameters of jwt/enrollKeyDerivation.hpp's deriveEnrollTokenKey(): a zero salt of
	// HashLen bytes and `info` = this label followed by the single version byte 0x01.
	hkdfSaltBytes      = 32
	hkdfTokenInfoLabel = "WAZUH-ENROLL-TOKEN-KEY"
	hkdfInfoVersion    = 0x01
)

// EnrollmentToken is the token an operator mints with `wazuh-manager-authd
// --create-enrollment-token` and pastes into an agent (issue #38993), decoded: the text is
// base64url (unpadded) of the compact JSON {"ver":1,"adr":"host[:port][/prefix]","pin"|"ca":...
// [,"key":...]}. `adr` says where the manager is and `pin`/`ca` how to trust it; neither is used
// here (the sender targets --manager/--port and skips TLS verification like every other route,
// docu/04). What the sender needs is `key`: without it the token carries no credential and cannot
// authenticate an enrollment, so ParseEnrollmentToken refuses it up front.
type EnrollmentToken struct {
	Address string // adr, verbatim (informational)
	ID      string // the 16 id bytes as 22 canonical base64url chars: the bearer's `kid`
	secret  []byte // 16 bytes; never printed
}

// enrollTokenJSON is the compact document inside the token. Unknown members are refused: the C
// codec that mints it (src/shared/src/enrollment_token.c) writes exactly these, so anything else
// is not a token this sender understands.
type enrollTokenJSON struct {
	Ver int     `json:"ver"`
	Adr string  `json:"adr"`
	Pin *string `json:"pin"`
	CA  *string `json:"ca"`
	Key *string `json:"key"`
}

// ParseEnrollmentToken decodes the pasted token text (surrounding whitespace tolerated).
func ParseEnrollmentToken(text string) (*EnrollmentToken, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("enrollment token: empty")
	}
	raw, err := b64.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("enrollment token: not unpadded base64url: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc enrollTokenJSON
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("enrollment token: not the expected JSON: %w", err)
	}
	if doc.Ver != 1 {
		return nil, fmt.Errorf("enrollment token: unsupported version %d (want 1)", doc.Ver)
	}
	if doc.Adr == "" {
		return nil, errors.New("enrollment token: missing adr")
	}
	if (doc.Pin == nil) == (doc.CA == nil) {
		return nil, errors.New("enrollment token: exactly one of pin/ca is required")
	}
	if doc.Key == nil {
		return nil, errors.New("enrollment token: carries no credential (no key field): it can pin the " +
			"manager's CA but cannot authenticate an enrollment -- mint one without --no-credential")
	}
	keyRaw, err := b64.DecodeString(*doc.Key)
	if err != nil || len(keyRaw) != enrollTokenIDBytes+enrollTokenSecretBytes {
		return nil, errors.New("enrollment token: key is not base64url of 32 bytes")
	}
	tok := &EnrollmentToken{
		Address: doc.Adr,
		ID:      b64.EncodeToString(keyRaw[:enrollTokenIDBytes]),
		secret:  append([]byte(nil), keyRaw[enrollTokenIDBytes:]...),
	}
	return tok, nil
}

// Key derives the token's HS256 key: HKDF-SHA256(IKM = secret, salt = 32 x 0x00,
// info = "WAZUH-ENROLL-TOKEN-KEY" || 0x01, L = 32) -- jwt/enrollKeyDerivation.hpp, which authd
// replicates in C and remoted's TokenKeySource runs over the store. The frozen vector
// (testdata/jwt_vectors.json, "enroll_token".hkdf_token) pins all three against this one.
func (t *EnrollmentToken) Key() []byte { return DeriveEnrollTokenKey(t.secret) }

// DeriveEnrollTokenKey is Key() over an explicit 16-byte secret (the vector test feeds it directly).
func DeriveEnrollTokenKey(secret []byte) []byte {
	salt := make([]byte, hkdfSaltBytes)
	info := append([]byte(hkdfTokenInfoLabel), hkdfInfoVersion)
	return hkdfSHA256(secret, salt, info, agentKeyBytes)
}

// hkdfSHA256 is RFC 5869 for L <= HashLen: extract (PRK = HMAC(salt, IKM)), then a single expand
// block (T(1) = HMAC(PRK, info || 0x01)). The standard library has no HKDF package and these two
// HMAC calls are the whole construction for a 32-byte output; the vector test pins them against
// the manager's OpenSSL EVP_KDF result, so a slip here fails loudly rather than mis-signing.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)[:length]
}

// enrollHeader / enrollClaims: fields declared alphabetically so encoding/json's output is
// byte-identical to jwtEnrollTokenSigner.hpp's hand-serialised header and payload (which is what
// lets enrolltoken_test.go reproduce the frozen vector exactly).
type enrollHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type enrollClaims struct {
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	Nbf int64  `json:"nbf"`
}

// SignEnrollWithKid mints the `wazuh-enroll+jwt` bearer of an enrollment token
// (jwtEnrollTokenSigner.hpp's signWithKid): header exactly {alg, kid, typ} with kid = the token
// id, claims exactly {exp, iat, jti, nbf} -- no iss/sub, there is no identity yet -- signed HS256
// with the token key. jti is normally "" (a fresh random id); tests pass a fixed one to reproduce
// the frozen vector.
func SignEnrollWithKid(key []byte, kid string, now int64, jti string) (string, error) {
	if len(key) != agentKeyBytes {
		return "", fmt.Errorf("enroll token key must be %d bytes, got %d", agentKeyBytes, len(key))
	}
	if kid == "" {
		return "", errors.New("enroll token kid must not be empty")
	}
	if now < 0 {
		return "", fmt.Errorf("clock before the epoch: %d", now)
	}
	var err error
	if jti == "" {
		if jti, err = NewJTI(); err != nil {
			return "", err
		}
	}

	header, err := json.Marshal(enrollHeader{Alg: tokenAlgorithm, Kid: kid, Typ: EnrollTokenType})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(enrollClaims{Exp: now + TokenLifetime, Iat: now, Jti: jti, Nbf: now})
	if err != nil {
		return "", err
	}

	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil)), nil
}

// EnrollTokenAuthHeaders returns the two headers a POST /enroll authenticated with an enrollment
// token carries. Called once per attempt, so every request on the wire has a fresh token.
func EnrollTokenAuthHeaders(key []byte, kid string, now int64) (map[string]string, error) {
	token, err := SignEnrollWithKid(key, kid, now, "")
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"protocol-version": ProtocolVersion,
		"Authorization":    "Bearer " + token,
	}, nil
}
