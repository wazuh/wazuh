package wire

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Response is the outcome of one request the sender records: status, the
// Retry-After header (empty if absent), the body, and the wall-clock latency.
type Response struct {
	Status     int
	RetryAfter string
	Body       []byte
	Latency    time.Duration
}

// Client sends one agent's requests. There is one per agent so that identities
// are never mixed on a shared connection (docu/08). In agent mode it targets
// remoted over HTTPS with a fresh bearer token per request; in uds mode it
// targets the module's Unix socket and sets X-Wazuh-Agent-Id itself.
type Client struct {
	http    *http.Client
	agentID string
	keyHex  string // empty in uds mode: no bearer

	// agentMode: HTTPS to remoted with a wazuh-agent+jwt bearer. Otherwise: HTTP over UDS.
	agentMode bool
	baseURL   string // "https://host:1517" (agent) or "http://unix" (uds)
	timeout   time.Duration

	// globalPrefix is the manager's <remote><https><global_prefix>, already through
	// NormalizeGlobalPrefix. Only NewAgentClient sets it: a UDS client physically
	// cannot carry one, which is the admin-plane rule enforced by construction rather
	// than by a mode check at each call site.
	globalPrefix string
}

// NewAgentClient builds an HTTPS client for one enrolled agent. reuse toggles
// HTTP keep-alive; the run records which was used, since it changes the
// connection-establishment cost materially. globalPrefix is the manager's configured
// global endpoint prefix, already normalized (see prefix.go); "" means unprefixed.
func NewAgentClient(id Identity, host string, port int, timeout time.Duration, reuse bool, globalPrefix string) *Client {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: !reuse,
	}
	return &Client{
		http:         &http.Client{Transport: transport, Timeout: timeout},
		agentID:      id.ID,
		keyHex:       id.Key,
		agentMode:    true,
		baseURL:      fmt.Sprintf("https://%s:%d", host, port),
		timeout:      timeout,
		globalPrefix: globalPrefix,
	}
}

// NewUDSClient builds a client that speaks HTTP/1.1 over the module's Unix
// socket. One request per connection is the peer contract, so keep-alive is
// disabled regardless of reuse.
func NewUDSClient(agentID, socketPath string, timeout time.Duration) *Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		http:      &http.Client{Transport: transport, Timeout: timeout},
		agentID:   agentID,
		agentMode: false,
		baseURL:   "http://unix",
		timeout:   timeout,
	}
}

// Do sends one request and returns its Response. setAgentIDHeader controls
// whether X-Wazuh-Agent-Id is set: the caller sets it for uds /stateful and
// /agents routes, and never for agent-mode routes (remoted sets it there).
// contentEncoding, when non-empty, is sent as Content-Encoding: the caller
// already compressed body. Authentication does not look at the body (or the
// target): the bearer token binds the agent's identity only.
func (c *Client) Do(method, target string, body []byte, contentType, contentEncoding string, now int64, setAgentIDHeader bool) (Response, error) {
	// The global prefix is purely a routing matter: routes live under it on the manager,
	// so it goes into the URL (see prefix.go for the failure modes). In uds mode
	// globalPrefix is always empty, so full == target.
	full := c.globalPrefix + target

	req, err := http.NewRequest(method, c.baseURL+full, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}

	if c.agentMode {
		// A fresh token per call: every attempt, retries included, carries its own jti/iat.
		headers, err := AuthHeaders(c.keyHex, c.agentID, now)
		if err != nil {
			return Response{}, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	if setAgentIDHeader {
		req.Header.Set("X-Wazuh-Agent-Id", c.agentID)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return Response{
		Status:     resp.StatusCode,
		RetryAfter: resp.Header.Get("Retry-After"),
		Body:       data,
		Latency:    time.Since(start),
	}, nil
}
