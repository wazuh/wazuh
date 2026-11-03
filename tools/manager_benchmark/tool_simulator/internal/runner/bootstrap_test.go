package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// tokenText is a mintable-looking enrollment token: the compact document authd
// prints, base64url without padding. Only `key` matters here -- the sender
// targets --manager/--port and ignores `adr` (docu/16).
func tokenText(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	doc := fmt.Sprintf(`{"ver":1,"adr":"127.0.0.1","pin":"deadbeef","key":%q}`,
		base64.RawURLEncoding.EncodeToString(key))
	return base64.RawURLEncoding.EncodeToString([]byte(doc))
}

// enrollServer stands up a TLS /enroll that answers `status`, minting a distinct
// record per request, and records the names it was asked to enroll.
func enrollServer(t *testing.T, status int) (host string, port int, names *[]string) {
	t.Helper()
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		seen = append(seen, body["name"])
		n := len(seen)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != 200 {
			_, _ = w.Write([]byte(`{"error":{"code":9008,"message":"Duplicate agent name"}}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":"%03d","name":%q,"ip":"any","key":"key-%03d","reenroll_secret":"sec-%03d"}`,
			n, body["name"], n, n)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p, &seen
}

func tokenRunner(t *testing.T, host string, port int, agents int, token string) *Runner {
	t.Helper()
	r := New(Config{
		Scenario: &scenario.Scenario{
			Name:   "bootstrap-test",
			Mode:   "agent",
			Fleets: []scenario.Fleet{{Name: "linux", Agents: agents, FirstID: 1}},
		},
		Mode: "agent", Bootstrap: BootstrapEnrollToken,
		Manager: host, Port: port, Timeout: 5 * time.Second,
		EnrollToken: token,
	})
	if err := r.prepareEnrollToken(); err != nil {
		t.Fatalf("prepareEnrollToken: %v", err)
	}
	return r
}

func TestEnrollWithTokenAdoptsTheWholeRecord(t *testing.T) {
	host, port, names := enrollServer(t, 200)
	r := tokenRunner(t, host, port, 1, tokenText(t))
	ag := &agent{r: r, fleet: r.scn.Fleets[0], name: "bench-linux-0001",
		enroll: wire.NewEnrollClient(host, port, 5*time.Second, false, "")}

	ident, err := r.enrollWithToken(ag)
	if err != nil {
		t.Fatalf("enrollWithToken: %v", err)
	}
	if ident.ID != "001" || ident.Key != "key-001" || ident.ReenrollSecret != "sec-001" {
		t.Errorf("identity = %+v", ident)
	}
	if len(*names) != 1 || (*names)[0] != "bench-linux-0001" {
		t.Errorf("enrolled names = %v, want the agent's own name", *names)
	}
}

// The bootstrap is all-or-nothing: a fleet that half enrolled measures nothing,
// so a contract status is a setup failure that names its remedy.
func TestEnrollWithTokenRefusesAnyNon200(t *testing.T) {
	host, port, _ := enrollServer(t, 409)
	r := tokenRunner(t, host, port, 1, tokenText(t))
	ag := &agent{r: r, fleet: r.scn.Fleets[0], name: "bench-linux-0001",
		enroll: wire.NewEnrollClient(host, port, 5*time.Second, false, "")}

	_, err := r.enrollWithToken(ag)
	if err == nil {
		t.Fatal("enrollWithToken: want an error for a 409")
	}
	if !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "cleanup_agents.sh") {
		t.Errorf("error = %v, want the status and what to do about it", err)
	}
}

func TestBuildAgentsBootstrapsTheFleetOverTheToken(t *testing.T) {
	host, port, names := enrollServer(t, 200)
	r := tokenRunner(t, host, port, 2, tokenText(t))

	agents, err := r.buildAgents(context.Background())
	if err != nil {
		t.Fatalf("buildAgents: %v", err)
	}
	if len(agents) != 2 || r.enrolled != 2 {
		t.Fatalf("agents = %d, enrolled = %d, want 2 and 2", len(agents), r.enrolled)
	}
	// Each agent runs under the id the manager assigned it, not the fleet index.
	if agents[0].id != "001" || agents[1].id != "002" {
		t.Errorf("ids = %q, %q", agents[0].id, agents[1].id)
	}
	if len(*names) != 2 || (*names)[0] == (*names)[1] {
		t.Errorf("enrolled names = %v, want two distinct ones", *names)
	}
	if r.Meta().Bootstrap != BootstrapEnrollToken {
		t.Errorf("meta.bootstrap = %q", r.Meta().Bootstrap)
	}
}

func TestPrepareEnrollTokenNeedsATokenOnlyWhenSomethingUsesOne(t *testing.T) {
	cases := map[string]struct {
		mode, bootstrap string
		lanes           map[string][]scenario.Step
		wantErr         bool
	}{
		"agent mode, token bootstrap":  {"agent", BootstrapEnrollToken, nil, true},
		"agent mode, 1515 bootstrap":   {"agent", Bootstrap1515, nil, false},
		"1515 bootstrap, but a step":   {"agent", Bootstrap1515, map[string][]scenario.Step{"l": {{Kind: "enroll_https"}}}, true},
		"uds mode ignores the default": {"uds", BootstrapEnrollToken, nil, false},
	}
	for name, c := range cases {
		r := New(Config{
			Scenario: &scenario.Scenario{Name: "t", Mode: c.mode, Lanes: c.lanes},
			Mode:     c.mode, Bootstrap: c.bootstrap,
		})
		err := r.prepareEnrollToken()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr = %v", name, err, c.wantErr)
		}
	}
}
