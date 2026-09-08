package runner

import (
	"context"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/cacerts"
)

// runCacerts sends one GET /cacerts: the CA-distribution request a real agent
// makes to bootstrap trust in the manager before it verifies anything
// (docu/15-cacerts.md). Body-less, unauthenticated, and answered from a file
// the manager re-reads per request -- the cheapest route on the listener, which
// is exactly why it is worth a lane of its own: it shows the fixed per-request
// cost of the TLS listener with no downstream behind it.
//
// The harness does not USE the PEM (its TLS client skips verification); it
// checks the answer's shape and records the status.
func (a *agent) runCacerts(ctx context.Context, lane string) {
	if err := a.r.sessionLimiter.Wait(ctx); err != nil {
		return
	}

	a.r.requestStarted()
	res, err := cacerts.Request(a.client, now())
	a.r.requestFinished()

	if err != nil {
		// A protocol error still produced a real answer, so record it and then
		// invalidate the run: a 200 without a PEM, or a status the contract does
		// not name, means the sender is not talking to remoted's /cacerts (docu/10).
		if perr, ok := err.(*cacerts.ErrProtocol); ok {
			a.r.reg.RecordCacerts(a.fleet.Name, lane, res.Status, us(res.Latency))
			a.r.fatalf("agent %s cacerts: %v", a.id, perr)
			return
		}
		a.r.reg.RecordTransportError(a.fleet.Name, lane)
		return
	}

	// 404 (no CA file on the manager) and 503 (the manager refuses a CA that
	// does not sign its own certificate) are the manager's contract outcomes,
	// recorded as such; a scenario's `expected` block decides whether they are
	// acceptable for the run.
	a.r.reg.RecordCacerts(a.fleet.Name, lane, res.Status, us(res.Latency))
}
