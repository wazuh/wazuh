package wire

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// testKeyHex is a 32-hex-character (16-byte) AES key, the shape client.keys carries.
const testKeyHex = "0123456789abcdef0123456789abcdef"

// TestDoSignsExactlyWhatItSends is the regression test for the failure mode the global
// prefix introduces: the URL and the signed target drifting apart. That bug compiles,
// passes every other test in this package, and only shows up as uniform 401s against a
// real manager -- so it is checked here by recomputing the MAC over the target the
// server actually received and comparing it against the header that arrived with it.
func TestDoSignsExactlyWhatItSends(t *testing.T) {
	cases := []struct {
		name    string
		prefix  string
		target  string
		wantURI string
	}{
		{"unprefixed", "", "/control", "/control"},
		{"prefixed", "/wazuh-manager-5", "/control", "/wazuh-manager-5/control"},
		{"prefixed with query", "/p", "/stateful?x=1", "/p/stateful?x=1"},
		{"nested prefix", "/edge/wazuh-5", "/scan/vd", "/edge/wazuh-5/scan/vd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotURI, gotAuth string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotURI = r.URL.RequestURI()
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			addr := srv.Listener.Addr().(*net.TCPAddr)
			c := NewAgentClient(Identity{ID: "001", Key: testKeyHex},
				addr.IP.String(), addr.Port, 5*time.Second, false, tc.prefix)

			const ts int64 = 1700000000
			body := []byte(`{"k":"v"}`)
			if _, err := c.Do("POST", tc.target, body, "application/json", "", ts, false); err != nil {
				t.Fatalf("Do: %v", err)
			}

			if gotURI != tc.wantURI {
				t.Errorf("request URI = %q, want %q", gotURI, tc.wantURI)
			}

			// The MAC the manager would compute over what it received.
			mac, err := Sign(testKeyHex, "POST", gotURI, "001", strconv.FormatInt(ts, 10), body)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			want := "Wazuh 001:" + strconv.FormatInt(ts, 10) + ":" + mac
			if gotAuth != want {
				t.Errorf("Authorization signs a different target than the one sent:\n got %q\nwant %q", gotAuth, want)
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
