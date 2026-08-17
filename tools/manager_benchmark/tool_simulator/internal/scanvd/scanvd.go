// Package scanvd sends the on-demand Vulnerability Detection re-scan request an
// agent makes when a /control notify tells it this node's feed has moved past
// the offset it last synced against: POST /scan/vd with
// {"type":"feed_update","feed_offset":N} (docu/14-scan-vd.md).
//
// It is deliberately separate from the inventory path: a VDFirst/VDSync
// /stateful session scans the inventory it CARRIES, while this endpoint asks
// the manager to re-scan the inventory it ALREADY has, against a newer feed.
// Same offset gate on both, one source of truth (VdClient::getOffset()), but
// different manager-side machinery -- remoted's own worker pool here, the
// inventory_sync_server's VD scan lane there.
package scanvd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

const path = "/scan/vd"

// Result is what the caller records: the status, latency and body size, plus
// the offset a 409 reported. The body is otherwise validated and dropped, like
// every other response the sender handles (docu/03).
type Result struct {
	Status   int
	Latency  time.Duration
	BodySize int
	// CurrentVersion is the current_version a 409 version_mismatch carried (0
	// otherwise). Recorded as evidence, NOT fed back into the next request: a
	// real agent retries with it, but a load generator that reshapes itself
	// from the server's answer produces runs that cannot be compared.
	CurrentVersion uint64
}

// ErrProtocol signals a run-invalidating answer: a 401 (the gateway's opaque
// credential failure) or any 400, all of which mean the sender built a request
// the manager cannot even parse -- a sender bug, not load (docu/10).
type ErrProtocol struct{ msg string }

func (e *ErrProtocol) Error() string { return e.msg }

// Request sends one feed_update scan request for the offset the caller resolved.
//
// 200 (queued), 409 (version_mismatch) and 503 (scan_queue_full) are all
// ORDINARY results the caller records: the last two are contract outcomes of a
// real fleet's traffic, not failures of the measurement. Only 400/401 return an
// ErrProtocol.
func Request(c *wire.Client, feedOffset uint64, now int64) (Result, error) {
	body, err := json.Marshal(map[string]any{"type": "feed_update", "feed_offset": feedOffset})
	if err != nil {
		return Result{}, err // hand-built map; a marshal failure is a bug
	}
	resp, err := c.Do("POST", path, body, "application/json", "", now, false)
	if err != nil {
		return Result{}, err
	}
	result := Result{Status: resp.Status, Latency: resp.Latency, BodySize: len(resp.Body)}

	switch resp.Status {
	case 200:
		// The reply is the literal {}. It says "queued", NOT "scanned": the scan
		// itself happens later, on remoted's worker pool, so nothing downstream
		// may read this latency as a scan duration.
		var reply map[string]any
		if err := json.Unmarshal(resp.Body, &reply); err != nil {
			return result, &ErrProtocol{fmt.Sprintf("scan/vd: 200 with a non-JSON body: %v", err)}
		}
	case 409:
		var reply struct {
			Error          string  `json:"error"`
			CurrentVersion float64 `json:"current_version"`
		}
		if err := json.Unmarshal(resp.Body, &reply); err == nil && reply.CurrentVersion >= 0 {
			result.CurrentVersion = uint64(reply.CurrentVersion)
		}
	case 400, 401:
		return result, &ErrProtocol{fmt.Sprintf("scan/vd answered %d: %s", resp.Status, truncate(resp.Body))}
	}
	return result, nil
}

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}
