// Package control builds and sends the POST /control messages an agent emits:
// startup, notify (the keepalive) and shutdown. It VALIDATES the response
// (status 200, parseable JSON) and otherwise DISCARDS its contents, with ONE
// exception: a notify response's vd_feed_offset is read out and returned,
// because a real agent uses it to decide when to request a VD re-scan
// (docu/03-control-protocol.md, docu/05-flatbuffers-messages.md). No other
// field of any reply changes the sender's behavior.
package control

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

const path = "/control"

// HostInfo is the optional host block of a notify.
type HostInfo struct {
	Hostname     string
	IP           string
	Architecture string
	OSName       string
	OSVersion    string
	OSPlatform   string
	OSType       string
}

// Result is what the caller records: the status, latency and body size. The
// body itself is intentionally not returned — it is validated and dropped
// here, except for VDFeedOffset (see the package doc).
type Result struct {
	Status   int
	Latency  time.Duration
	BodySize int
	// VDFeedOffset is the notify response's vd_feed_offset (0 for Startup and
	// Shutdown, which never carry it, or if the field was absent/non-numeric).
	VDFeedOffset uint64
}

// ErrProtocol signals a malformed or unexpected control answer: a run-
// invalidating condition (docu/10), distinct from an ordinary result.
type ErrProtocol struct{ msg string }

func (e *ErrProtocol) Error() string { return e.msg }

// Startup sends {"type":"startup","version":version} and validates the reply.
func Startup(c *wire.Client, version string, now int64) (Result, error) {
	body := mustJSON(map[string]any{"type": "startup", "version": version})
	return send(c, body, now)
}

// Notify sends a keepalive. host may be nil for the cheap variant.
func Notify(c *wire.Client, version string, host *HostInfo, now int64) (Result, error) {
	msg := map[string]any{"type": "notify", "agent": map[string]any{"version": version}}
	if host != nil {
		msg["host"] = map[string]any{
			"hostname":     host.Hostname,
			"ip":           host.IP,
			"architecture": host.Architecture,
			"os": map[string]any{
				"name":     host.OSName,
				"version":  host.OSVersion,
				"platform": host.OSPlatform,
				"type":     host.OSType,
			},
		}
	}
	return send(c, mustJSON(msg), now)
}

// Shutdown sends {"type":"shutdown"}; the reply is the literal {}.
func Shutdown(c *wire.Client, now int64) (Result, error) {
	return send(c, mustJSON(map[string]any{"type": "shutdown"}), now)
}

func send(c *wire.Client, body []byte, now int64) (Result, error) {
	resp, err := c.Do("POST", path, body, "application/json", "", now, false)
	if err != nil {
		return Result{}, err
	}
	result := Result{Status: resp.Status, Latency: resp.Latency, BodySize: len(resp.Body)}

	// A control error (400, or the 401 the gateway maps every credential
	// problem to) means the run is misconfigured — surface it, do not fold it
	// into load. The caller decides fatality; here it is an ErrProtocol.
	if resp.Status != 200 {
		return result, &ErrProtocol{fmt.Sprintf("control %s answered %d: %s", bodyType(body), resp.Status, truncate(resp.Body))}
	}

	// Validate-and-mostly-discard: the body must be a JSON object; the only
	// field read out of it is vd_feed_offset (see the package doc).
	var reply map[string]any
	if err := json.Unmarshal(resp.Body, &reply); err != nil {
		return result, &ErrProtocol{fmt.Sprintf("control %s: 200 with a non-JSON body: %v", bodyType(body), err)}
	}
	if raw, ok := reply["vd_feed_offset"]; ok {
		if f, ok := raw.(float64); ok && f >= 0 {
			result.VDFeedOffset = uint64(f)
		}
	}
	return result, nil
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err) // the inputs are hand-built maps; a marshal failure is a bug
	}
	return data
}

func bodyType(body []byte) string {
	var probe struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(body, &probe)
	return probe.Type
}

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}
