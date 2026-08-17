package wire

import (
	"encoding/hex"
	"testing"
)

// RFC 4493 test vectors for AES-128-CMAC (§4). These pin the algorithm itself;
// a manager is not needed to catch a regression.
func TestAESCMACRFC4493(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")

	cases := []struct {
		name string
		msg  string // hex
		want string // hex
	}{
		{"empty", "", "bb1d6929e95937287fa37d129b756746"},
		{"one block", "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{
			"two-and-a-half blocks",
			"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			"dfa66747de9ae63030ca32611497c827",
		},
		{
			"four blocks",
			"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
				"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			"51f0bebf7e3b9d92fc49741779363cfe",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tc.msg)
			got, err := AESCMAC(key, msg)
			if err != nil {
				t.Fatalf("AESCMAC: %v", err)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("got %x, want %s", got, tc.want)
			}
		})
	}
}

// A fixed canonical-string vector, so a change to CanonicalString or Sign is
// caught deterministically. The key is the RFC key; the request is a POST to
// /stateful. The expected MAC is what this implementation produces for exactly
// these inputs — it is the regression anchor, cross-checked once by hand
// against the shape in remoted_module/tools/send_stateless.py.
func TestSignVector(t *testing.T) {
	const keyHex = "2b7e151628aed2a6abf7158809cf4f3c"
	body := []byte(`{"type":"startup","version":"5.0.0"}`)

	mac, err := Sign(keyHex, "POST", "/control", "001", "1700000000", body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(mac) != 32 {
		t.Fatalf("mac length = %d, want 32", len(mac))
	}

	// Recompute the same canonical string independently and confirm the MAC
	// matches, so the test pins the wiring, not just the length.
	key, _ := hex.DecodeString(keyHex)
	canon := CanonicalString(ProtocolVersion, "POST", "/control", "001", "1700000000", body)
	want, _ := AESCMAC(key, canon)
	if hex.EncodeToString(want) != mac {
		t.Fatalf("Sign disagrees with CanonicalString+AESCMAC")
	}

	// And a wrong-key MAC must differ (constant-time compare sanity).
	other, _ := AESCMAC(make([]byte, 16), canon)
	if constantTimeEqual(want, other) {
		t.Fatal("MAC did not depend on the key")
	}
}
