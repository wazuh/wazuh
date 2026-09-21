package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// enrollTokenVectors mirrors the "enroll_token" object of testdata/jwt_vectors.json (issue
// #38993): the frozen enrollment-token vectors shared with the manager's C++ library
// (src/shared_modules/utils/jwt/testVectors.hpp) and authd's C tests. Reproducing them byte for
// byte is the interoperability proof: the bearer this tool mints from a pasted token IS what
// remoted's TokenKeySource + verifyWithKid accept, and the key it derives IS the one authd derives.
type enrollTokenVectors struct {
	TokenIDHex          string `json:"token_id_hex"`
	TokenIDB64URL       string `json:"token_id_b64url"`
	TokenSecretHex      string `json:"token_secret_hex"`
	TokenKeyFieldB64URL string `json:"token_key_field_b64url"`
	HkdfToken           struct {
		KeyHex string `json:"key_hex"`
	} `json:"hkdf_token"`
	TokenKidJWT struct {
		Kid         string `json:"kid"`
		HeaderJSON  string `json:"header_json"`
		PayloadJSON string `json:"payload_json"`
		Token       string `json:"token"`
	} `json:"token_kid_jwt"`
	EnrollmentToken struct {
		Tokens []struct {
			JSON  string `json:"json"`
			Token string `json:"token"`
		} `json:"tokens"`
	} `json:"enrollment_token"`
}

func loadEnrollTokenVectors(t *testing.T) enrollTokenVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/jwt_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var all struct {
		EnrollToken enrollTokenVectors `json:"enroll_token"`
	}
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return all.EnrollToken
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestDeriveEnrollTokenKeyMatchesTheVector(t *testing.T) {
	v := loadEnrollTokenVectors(t)
	key := DeriveEnrollTokenKey(mustHex(t, v.TokenSecretHex))
	if got := hex.EncodeToString(key); got != v.HkdfToken.KeyHex {
		t.Fatalf("HKDF key = %s, want %s", got, v.HkdfToken.KeyHex)
	}
}

func TestSignEnrollWithKidReproducesTheVector(t *testing.T) {
	v := loadEnrollTokenVectors(t)
	key := mustHex(t, v.HkdfToken.KeyHex)

	// Same iat and jti as the vector (the payload's jti is the id bytes 00..0f as base64url).
	var claims struct {
		Iat int64  `json:"iat"`
		Jti string `json:"jti"`
	}
	if err := json.Unmarshal([]byte(v.TokenKidJWT.PayloadJSON), &claims); err != nil {
		t.Fatalf("vector payload: %v", err)
	}
	token, err := SignEnrollWithKid(key, v.TokenKidJWT.Kid, claims.Iat, claims.Jti)
	if err != nil {
		t.Fatalf("SignEnrollWithKid: %v", err)
	}
	if token != v.TokenKidJWT.Token {
		t.Fatalf("token differs from the vector:\n got  %s\n want %s", token, v.TokenKidJWT.Token)
	}

	// The header and payload segments are exactly the vector's canonical JSON texts.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	for i, want := range []string{v.TokenKidJWT.HeaderJSON, v.TokenKidJWT.PayloadJSON} {
		got, err := b64.DecodeString(parts[i])
		if err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
		if string(got) != want {
			t.Errorf("segment %d = %s, want %s", i, got, want)
		}
	}
}

func TestSignEnrollWithKidRefusesBadInputs(t *testing.T) {
	v := loadEnrollTokenVectors(t)
	key := mustHex(t, v.HkdfToken.KeyHex)
	if _, err := SignEnrollWithKid(key[:16], v.TokenKidJWT.Kid, 1700000000, ""); err == nil {
		t.Error("a 16-byte key must be refused")
	}
	if _, err := SignEnrollWithKid(key, "", 1700000000, ""); err == nil {
		t.Error("an empty kid must be refused")
	}
	if _, err := SignEnrollWithKid(key, v.TokenKidJWT.Kid, -1, ""); err == nil {
		t.Error("a pre-epoch clock must be refused")
	}
	// A fresh jti per call: two mints never collide.
	a, err := SignEnrollWithKid(key, v.TokenKidJWT.Kid, 1700000000, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignEnrollWithKid(key, v.TokenKidJWT.Kid, 1700000000, "")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two mints produced the same token: jti is not fresh")
	}
}

func TestParseEnrollmentTokenExtractsTheIdAndDerivesTheVectorKey(t *testing.T) {
	v := loadEnrollTokenVectors(t)
	// The vector's second token is the one that carries a credential (`key` present).
	var withKey string
	for _, tok := range v.EnrollmentToken.Tokens {
		if strings.Contains(tok.JSON, `"key"`) {
			withKey = tok.Token
		}
	}
	if withKey == "" {
		t.Fatal("no credential-bearing token in the vectors")
	}

	tok, err := ParseEnrollmentToken("  " + withKey + "\n")
	if err != nil {
		t.Fatalf("ParseEnrollmentToken: %v", err)
	}
	if tok.Address != "siem.example.local" {
		t.Errorf("Address = %q", tok.Address)
	}
	if tok.ID != v.TokenIDB64URL {
		t.Errorf("ID = %q, want %q", tok.ID, v.TokenIDB64URL)
	}
	if got := hex.EncodeToString(tok.Key()); got != v.HkdfToken.KeyHex {
		t.Errorf("Key() = %s, want %s", got, v.HkdfToken.KeyHex)
	}
	// And the bearer minted from the pasted token is the vector's, given its iat/jti.
	token, err := SignEnrollWithKid(tok.Key(), tok.ID, 1700000000, "AAECAwQFBgcICQoLDA0ODw")
	if err != nil {
		t.Fatal(err)
	}
	if token != v.TokenKidJWT.Token {
		t.Errorf("bearer from the pasted token differs from the vector")
	}
}

func TestParseEnrollmentTokenRefusesWhatCannotAuthenticate(t *testing.T) {
	v := loadEnrollTokenVectors(t)
	// The credential-less tokens (no `key`) are valid tokens for an agent's trust bootstrap, but
	// useless to this tool: refused up front, with a message that says why.
	for _, tok := range v.EnrollmentToken.Tokens {
		if strings.Contains(tok.JSON, `"key"`) {
			continue
		}
		_, err := ParseEnrollmentToken(tok.Token)
		if err == nil || !strings.Contains(err.Error(), "no credential") {
			t.Errorf("credential-less token %q: err = %v, want a 'no credential' refusal", tok.JSON, err)
		}
	}

	bad := map[string]string{
		"empty":          "",
		"not base64url":  "not*a*token",
		"padded base64":  b64.EncodeToString([]byte(`{"ver":1}`)) + "==",
		"not json":       b64.EncodeToString([]byte("hello")),
		"wrong version":  b64.EncodeToString([]byte(`{"ver":2,"adr":"m","pin":"p","key":"` + v.TokenKeyFieldB64URL + `"}`)),
		"no adr":         b64.EncodeToString([]byte(`{"ver":1,"pin":"p","key":"` + v.TokenKeyFieldB64URL + `"}`)),
		"pin and ca":     b64.EncodeToString([]byte(`{"ver":1,"adr":"m","pin":"p","ca":"c","key":"` + v.TokenKeyFieldB64URL + `"}`)),
		"short key":      b64.EncodeToString([]byte(`{"ver":1,"adr":"m","pin":"p","key":"AAECAwQFBgcICQoLDA0ODw"}`)),
		"unknown member": b64.EncodeToString([]byte(`{"ver":1,"adr":"m","pin":"p","key":"` + v.TokenKeyFieldB64URL + `","x":1}`)),
	}
	for name, text := range bad {
		if _, err := ParseEnrollmentToken(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnrollTokenAuthHeadersCarryTheProtocolVersionAndABearer(t *testing.T) {
	v := loadEnrollTokenVectors(t)
	headers, err := EnrollTokenAuthHeaders(mustHex(t, v.HkdfToken.KeyHex), v.TokenKidJWT.Kid, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if headers["protocol-version"] != ProtocolVersion {
		t.Errorf("protocol-version = %q", headers["protocol-version"])
	}
	if !strings.HasPrefix(headers["Authorization"], "Bearer ey") {
		t.Errorf("Authorization = %q", headers["Authorization"])
	}
}
