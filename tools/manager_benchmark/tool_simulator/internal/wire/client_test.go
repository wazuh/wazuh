package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testKeyHex is a 64-hex-character (32-byte) key, the shape client.keys carries.
const testKeyHex = "0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff"

// verifyBearer is a minimal test-side verifier: HS256 over "header.payload" with the decoded key,
// then the claims. It stands in for the manager to check what actually reached the server.
func verifyBearer(t *testing.T, authorization, keyHex string) jwtClaims {
	t.Helper()
	if !strings.HasPrefix(authorization, "Bearer ") {
		t.Fatalf("Authorization = %q, want a Bearer token", authorization)
	}
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	key, _ := DecodeAgentKey(keyHex)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if b64.EncodeToString(mac.Sum(nil)) != parts[2] {
		t.Fatalf("signature does not verify with the agent key")
	}
	var claims jwtClaims
	raw, _ := b64.DecodeString(parts[1])
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	return claims
}

// TestDoSendsAFreshBearerOnEveryRequest: the URL carries the global prefix, the Authorization
// header carries a wazuh-agent+jwt token that verifies with the agent's key and names the agent,
// protocol-version is 1 -- and two requests never share a token.
func TestDoSendsAFreshBearerOnEveryRequest(t *testing.T) {
	cases := []struct {
		name    string
		prefix  string
		target  string
		wantURI string
	}{
		{"unprefixed", "", "/control", "/control"},
		{"prefixed", "/wazuh-manager", "/control", "/wazuh-manager/control"},
		{"prefixed with query", "/p", "/stateful?x=1", "/p/stateful?x=1"},
		{"nested prefix", "/edge/wazuh-5", "/scan/vd", "/edge/wazuh-5/scan/vd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotURI string
			var gotAuth, gotVersion []string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotURI = r.URL.RequestURI()
				gotAuth = append(gotAuth, r.Header.Get("Authorization"))
				gotVersion = append(gotVersion, r.Header.Get("protocol-version"))
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			addr := srv.Listener.Addr().(*net.TCPAddr)
			c := NewAgentClient(Identity{ID: "001", Key: testKeyHex},
				addr.IP.String(), addr.Port, 5*time.Second, false, tc.prefix)

			const ts int64 = 1700000000
			body := []byte(`{"k":"v"}`)
			for i := 0; i < 2; i++ {
				if _, err := c.Do("POST", tc.target, body, "application/json", "", ts, false); err != nil {
					t.Fatalf("Do: %v", err)
				}
			}

			if gotURI != tc.wantURI {
				t.Errorf("request URI = %q, want %q", gotURI, tc.wantURI)
			}
			for i, auth := range gotAuth {
				claims := verifyBearer(t, auth, testKeyHex)
				if claims.Sub != "001" || claims.Iss != "wazuh-agent/001" {
					t.Errorf("request %d names %q/%q, want agent 001", i, claims.Sub, claims.Iss)
				}
				if claims.Iat != ts || claims.Nbf != ts || claims.Exp != ts+TokenLifetime {
					t.Errorf("request %d times = iat %d nbf %d exp %d", i, claims.Iat, claims.Nbf, claims.Exp)
				}
				if gotVersion[i] != ProtocolVersion {
					t.Errorf("request %d protocol-version = %q", i, gotVersion[i])
				}
			}
			if gotAuth[0] == gotAuth[1] {
				t.Error("two requests carried the same token: the bearer is not fresh per attempt")
			}
		})
	}
}

// A uds client must never carry a global prefix: the module's admin socket is not
// published under the manager's prefix. The guarantee is structural (NewUDSClient has no
// prefix parameter), and this pins it so a future refactor cannot quietly add one.
func TestUDSClientHasNoGlobalPrefix(t *testing.T) {
	c := NewUDSClient("001", "/tmp/does-not-need-to-exist.sock", time.Second)
	if c.globalPrefix != "" {
		t.Fatalf("uds client carries global prefix %q, want empty", c.globalPrefix)
	}
}
