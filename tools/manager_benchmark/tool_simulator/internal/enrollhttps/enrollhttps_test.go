package enrollhttps

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// The frozen vector's token key and id (testdata/jwt_vectors.json, "enroll_token"): what matters
// here is the request SHAPE, so any 32-byte key and canonical kid would do -- the vector ones make
// the recorded bearer recognisable.
const (
	vectorKeyHex = "5da72b786a15757caa8d825a74a3474c3f15b048fd1064b49863ffc715a95860"
	vectorKid    = "AAECAwQFBgcICQoLDA0ODw"
)

type seen struct {
	method, path, contentType, protocolVersion, authorization string
	body                                                      map[string]string
}

// serve stands up a TLS server answering `status`/`body` and returns a client pointed at it plus
// the request it received.
func serve(t *testing.T, status int, body string, prefix string) (*wire.Client, *seen) {
	t.Helper()
	got := &seen{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		got.contentType = r.Header.Get("Content-Type")
		got.protocolVersion = r.Header.Get("protocol-version")
		got.authorization = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return wire.NewEnrollClient(u.Hostname(), port, 5*time.Second, false, prefix), got
}

func vectorKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		v, err := strconv.ParseUint(vectorKeyHex[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		key[i] = byte(v)
	}
	return key
}

func TestRequestSendsTheEnrollBodyAndTheTokenBearer(t *testing.T) {
	client, got := serve(t, 200, `{"id":"042","name":"bench-linux-0001-tk-1","ip":"any","key":"c0ffee"}`, "/wazuh-manager")

	res, err := Request(client, vectorKey(t), vectorKid, "bench-linux-0001-tk-1", "5.0.0", 1700000000)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if res.Status != 200 || res.AgentID != "042" {
		t.Errorf("result = %+v", res)
	}
	if got.method != "POST" || got.path != "/wazuh-manager/enroll" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.contentType != "application/json" || got.protocolVersion != wire.ProtocolVersion {
		t.Errorf("headers: Content-Type %q protocol-version %q", got.contentType, got.protocolVersion)
	}
	if !strings.HasPrefix(got.authorization, "Bearer ") {
		t.Fatalf("Authorization = %q", got.authorization)
	}
	// The bearer is the enrollment-token form: its header names the kid and the enroll typ.
	header, err := decodeSegment(strings.Split(strings.TrimPrefix(got.authorization, "Bearer "), ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	if header["kid"] != vectorKid || header["typ"] != wire.EnrollTokenType || header["alg"] != "HS256" {
		t.Errorf("bearer header = %v", header)
	}
	if got.body["name"] != "bench-linux-0001-tk-1" || got.body["version"] != "5.0.0" || len(got.body) != 2 {
		t.Errorf("body = %v", got.body)
	}
}

func TestContractStatusesAreRecordedNotFatal(t *testing.T) {
	for _, status := range []int{401, 403, 409} {
		client, _ := serve(t, status, `{"error":{"code":0,"message":"x"}}`, "")
		res, err := Request(client, vectorKey(t), vectorKid, "bench-a-tk-1", "5.0.0", 1700000000)
		if err != nil {
			t.Errorf("%d: err = %v, want a recorded result", status, err)
		}
		if res.Status != status {
			t.Errorf("status = %d, want %d", res.Status, status)
		}
	}
}

func TestUnexpectedAnswersAreProtocolErrors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"500":                          {500, `{"error":{"code":9001}}`},
		"400 (a body remoted refused)": {400, `{"error":{"code":0,"message":"Missing or invalid field: name"}}`},
		"200 without the record":       {200, `{"ok":true}`},
		"200 for another name":         {200, `{"id":"1","name":"someone-else","ip":"any","key":"k"}`},
	}
	for name, c := range cases {
		client, _ := serve(t, c.status, c.body, "")
		res, err := Request(client, vectorKey(t), vectorKid, "bench-a-tk-1", "5.0.0", 1700000000)
		if _, ok := err.(*ErrProtocol); !ok {
			t.Errorf("%s: err = %v, want ErrProtocol", name, err)
		}
		if res.Status != c.status {
			t.Errorf("%s: the real status is still recorded: got %d", name, res.Status)
		}
	}
}

func decodeSegment(seg string) (map[string]string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	return out, json.Unmarshal(raw, &out)
}
