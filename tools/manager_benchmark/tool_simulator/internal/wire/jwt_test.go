package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// vectors mirrors testdata/jwt_vectors.json, the frozen wazuh-agent+jwt vectors shared with the
// manager's C++ library (src/shared_modules/utils/jwt/testVectors.hpp) and the Python tools. They
// were generated with an implementation independent of both (Python stdlib), so reproducing them
// byte for byte here is the interoperability proof: a token this tool mints IS what the manager
// verifies.
type vectors struct {
	Key struct {
		Hex      string `json:"hex"`
		BytesLen int    `json:"bytes_len"`
	} `json:"key"`
	AgentID         string `json:"agent_id"`
	Iat             int64  `json:"iat"`
	Exp             int64  `json:"exp"`
	JtiBytesHex     string `json:"jti_bytes_hex"`
	Jti             string `json:"jti"`
	HeaderJSON      string `json:"header_json"`
	PayloadJSON     string `json:"payload_json"`
	SigningInput    string `json:"signing_input"`
	SignatureB64URL string `json:"signature_b64url"`
	Token           string `json:"token"`
	Negative        struct {
		ASCIIKeyToken struct {
			Token string `json:"token"`
		} `json:"ascii_key_token"`
		AudPresentToken struct {
			Token string `json:"token"`
		} `json:"aud_present_token"`
	} `json:"negative"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/jwt_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func TestDecodeAgentKeyMatchesTheVector(t *testing.T) {
	v := loadVectors(t)
	key, err := DecodeAgentKey(v.Key.Hex)
	if err != nil {
		t.Fatalf("DecodeAgentKey: %v", err)
	}
	if len(key) != v.Key.BytesLen || len(key) != 32 {
		t.Fatalf("key is %d bytes, want 32", len(key))
	}
	// Binary key, not printable: the vector deliberately starts with 0x00 and ends with 0xff.
	if key[0] != 0x00 || key[31] != 0xff {
		t.Errorf("key bytes = %x, want 00...ff", key)
	}
}

func TestDecodeAgentKeyRejectsEverythingButSixtyFourLowercaseHex(t *testing.T) {
	v := loadVectors(t)
	bad := []string{
		"",
		"2b7e151628aed2a6abf7158809cf4f3c", // 16 bytes
		"2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6", // 24 bytes
		v.Key.Hex[:63],
		v.Key.Hex + "0",
		strings.ToUpper(v.Key.Hex),
		v.Key.Hex[:63] + "g",
	}
	for _, k := range bad {
		if _, err := DecodeAgentKey(k); err == nil {
			t.Errorf("DecodeAgentKey(%q) accepted, want error", k)
		}
	}
}

func TestSignReproducesTheFrozenVectorByteForByte(t *testing.T) {
	v := loadVectors(t)
	token, err := Sign(v.Key.Hex, v.AgentID, v.Iat, v.Jti)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if token != v.Token {
		t.Fatalf("token mismatch\n got %s\nwant %s", token, v.Token)
	}

	// The segments are exactly the vector's texts: header and claims serialised compactly and
	// alphabetically, the signature over "header.payload".
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	if parts[0]+"."+parts[1] != v.SigningInput {
		t.Errorf("signing input mismatch")
	}
	if parts[2] != v.SignatureB64URL {
		t.Errorf("signature mismatch: got %s want %s", parts[2], v.SignatureB64URL)
	}
	header, _ := b64.DecodeString(parts[0])
	claims, _ := b64.DecodeString(parts[1])
	if string(header) != v.HeaderJSON {
		t.Errorf("header = %s, want %s", header, v.HeaderJSON)
	}
	if string(claims) != v.PayloadJSON {
		t.Errorf("claims = %s, want %s", claims, v.PayloadJSON)
	}
	if v.Exp != v.Iat+TokenLifetime {
		t.Errorf("vector lifetime %d disagrees with the profile constant %d", v.Exp-v.Iat, TokenLifetime)
	}
	jtiRaw, _ := hex.DecodeString(v.JtiBytesHex)
	if b64.EncodeToString(jtiRaw) != v.Jti {
		t.Errorf("jti encoding mismatch")
	}
}

// Signing with the 64 ASCII chars of the key instead of the 32 decoded bytes is the negative
// vector: it must NOT reproduce the valid signature, and it must reproduce the frozen negative.
func TestASCIIKeyIsTheWrongKey(t *testing.T) {
	v := loadVectors(t)
	mac := hmac.New(sha256.New, []byte(v.Key.Hex))
	mac.Write([]byte(v.SigningInput))
	sig := b64.EncodeToString(mac.Sum(nil))
	if sig == v.SignatureB64URL {
		t.Fatal("the ASCII key produced the valid signature")
	}
	if got := v.SigningInput + "." + sig; got != v.Negative.ASCIIKeyToken.Token {
		t.Errorf("ascii-key token = %s, want the frozen negative %s", got, v.Negative.ASCIIKeyToken.Token)
	}
	// And DecodeAgentKey never hands the ASCII bytes back as a key.
	key, _ := DecodeAgentKey(v.Key.Hex)
	if string(key) == v.Key.Hex {
		t.Fatal("DecodeAgentKey returned the hex text")
	}
}

func TestTwoTokensInTheSameSecondDifferInJtiAndSignature(t *testing.T) {
	v := loadVectors(t)
	a, err := Sign(v.Key.Hex, v.AgentID, v.Iat, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(v.Key.Hex, v.AgentID, v.Iat, "")
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if pa[0] != pb[0] {
		t.Error("headers differ")
	}
	if pa[1] == pb[1] || pa[2] == pb[2] {
		t.Error("two tokens minted in the same second share claims/signature: jti is not fresh")
	}
}

func TestNewJTIIsCanonicalAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		jti, err := NewJTI()
		if err != nil {
			t.Fatal(err)
		}
		if len(jti) != 22 {
			t.Fatalf("jti %q has %d chars, want 22", jti, len(jti))
		}
		raw, err := b64.DecodeString(jti)
		if err != nil || len(raw) != 16 {
			t.Fatalf("jti %q does not decode to 16 bytes", jti)
		}
		if b64.EncodeToString(raw) != jti {
			t.Fatalf("jti %q is not canonical base64url", jti)
		}
		if seen[jti] {
			t.Fatalf("duplicate jti after %d draws", i)
		}
		seen[jti] = true
	}
}

func TestCanonicalAgentID(t *testing.T) {
	for in, want := range map[string]string{"1": "001", "01": "001", "001": "001", "42": "042", "12345": "12345"} {
		got, err := CanonicalAgentID(in)
		if err != nil || got != want {
			t.Errorf("CanonicalAgentID(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "a", "-1", "1.0", "4294967296", " 1"} {
		if _, err := CanonicalAgentID(bad); err == nil {
			t.Errorf("CanonicalAgentID(%q) accepted", bad)
		}
	}
}

func TestSignRefusesBadInputs(t *testing.T) {
	v := loadVectors(t)
	if _, err := Sign("2b7e151628aed2a6abf7158809cf4f3c", v.AgentID, v.Iat, ""); err == nil {
		t.Error("a 16-byte key was accepted")
	}
	if _, err := Sign(v.Key.Hex, "agent", v.Iat, ""); err == nil {
		t.Error("a non-numeric agent id was accepted")
	}
	if _, err := Sign(v.Key.Hex, v.AgentID, -1, ""); err == nil {
		t.Error("a clock before the epoch was accepted")
	}
}

func TestAuthHeadersCarryProtocolVersionAndABearer(t *testing.T) {
	v := loadVectors(t)
	h, err := AuthHeaders(v.Key.Hex, v.AgentID, v.Iat)
	if err != nil {
		t.Fatal(err)
	}
	if h["protocol-version"] != "1" {
		t.Errorf("protocol-version = %q", h["protocol-version"])
	}
	if !strings.HasPrefix(h["Authorization"], "Bearer ey") {
		t.Errorf("Authorization = %q, want a Bearer JWS", h["Authorization"])
	}
	if len(h) != 2 {
		t.Errorf("%d headers, want exactly 2", len(h))
	}
}
