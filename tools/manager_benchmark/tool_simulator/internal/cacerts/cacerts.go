// Package cacerts fetches the CA that signs the manager's HTTPS listener
// certificate: GET /cacerts, the unauthenticated, body-less route an agent uses
// to bootstrap trust in the manager without an out-of-band copy of the PEM
// (docu/15-cacerts.md).
//
// The harness itself never needs the answer -- its TLS client skips
// verification (wire.NewAgentClient uses InsecureSkipVerify), so the PEM is
// validated for shape and dropped like every other body (docu/03). What the
// step measures is the route's contract and cost under a fleet: a trust
// bootstrap that is 404 (no CA file) or 503 (the manager refuses a CA that does
// not sign its own certificate) is what a real fleet would hit on first contact.
package cacerts

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

const path = "/cacerts"

// pemContentType is the media type a 200 must carry; pemMarker the block every
// served file must contain (the manager answers 404 otherwise, so a 200 without
// it is a contract violation on the manager's side).
const (
	pemContentType = "application/x-pem-file"
	pemMarker      = "-----BEGIN CERTIFICATE-----"
)

// Result is what the caller records: the status, latency and body size. The
// body is otherwise validated and dropped.
type Result struct {
	Status   int
	Latency  time.Duration
	BodySize int
}

// ErrProtocol signals a run-invalidating answer: a 200 whose body is not a PEM
// (or is not labelled as one), or a status the contract does not name. Either
// means the sender is not talking to the route it thinks it is (a proxy, a
// prefix mismatch answered by something else), not load (docu/10).
type ErrProtocol struct{ msg string }

func (e *ErrProtocol) Error() string { return e.msg }

// Request sends one GET /cacerts.
//
// 200 (PEM served), 404 (the manager has no CA file) and 503 (the manager
// refuses to hand out a CA that does not sign its own certificate) are all
// ORDINARY results the caller records: the last two are contract outcomes a
// real fleet can meet, not failures of the measurement. Do() adds the bearer in
// agent mode; the route ignores it, so it is harmless.
func Request(c *wire.Client, now int64) (Result, error) {
	resp, err := c.Do("GET", path, nil, "", "", now, false)
	if err != nil {
		return Result{}, err
	}
	result := Result{Status: resp.Status, Latency: resp.Latency, BodySize: len(resp.Body)}

	switch resp.Status {
	case 200:
		// A "success" that would not let an agent trust anything is worse than a
		// refusal: name it rather than count it as a served CA.
		if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(resp.ContentType, ";")[0])); mediaType != pemContentType {
			return result, &ErrProtocol{fmt.Sprintf("cacerts: 200 with Content-Type %q, want %q", resp.ContentType, pemContentType)}
		}
		if !bytes.Contains(resp.Body, []byte(pemMarker)) {
			return result, &ErrProtocol{fmt.Sprintf("cacerts: 200 without a certificate block: %s", truncate(resp.Body))}
		}
	case 404, 503:
		// Contract outcomes, recorded as such.
	default:
		return result, &ErrProtocol{fmt.Sprintf("cacerts answered %d: %s", resp.Status, truncate(resp.Body))}
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
