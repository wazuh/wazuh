package runner

import (
	"context"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scanvd"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

// runScanVD sends one POST /scan/vd: the feed-update re-scan a real agent
// requests once a /control notify shows the node's feed has moved past what the
// agent last synced against (docu/14-scan-vd.md).
//
// It is NOT the scan a VDFirst/VDSync session triggers. That one rides the
// inventory the session carries, through the inventory_sync_server's VD scan
// lane; this one asks the manager to re-scan the inventory it already holds,
// through remoted's own worker pool. A lane that does `full_resync` (VD dump)
// then `scan_vd` therefore walks BOTH paths in the order a real agent does.
//
// The recorded latency is admission only — a 200 means "queued", and the scan
// runs afterward, one agent at a time inside the VD module. Whether it actually
// ran is visible in modulesd's log (`reason=feed_update`), never here.
func (a *agent) runScanVD(ctx context.Context, lane string, step scenario.Step) {
	// Resolved first, and outside the rate limiter: in agent mode this blocks
	// until the keepalive loop has learned an offset, and a token taken before
	// that wait would price the wait as load.
	offset := a.feedOffsetFor(step)
	if err := a.r.sessionLimiter.Wait(ctx); err != nil {
		return
	}

	a.r.requestStarted()
	res, err := scanvd.Request(a.client, offset, now())
	a.r.requestFinished()

	if err != nil {
		// A protocol error (400/401) still produced a real answer, so record it
		// and then invalidate the run: it means the sender built a request the
		// manager cannot parse, or the fleet's keys are not loaded (docu/10).
		if perr, ok := err.(*scanvd.ErrProtocol); ok {
			a.r.reg.RecordScanVD(a.fleet.Name, lane, res.Status, us(res.Latency))
			a.r.fatalf("agent %s scan/vd: %v", a.id, perr)
			return
		}
		a.r.reg.RecordTransportError(a.fleet.Name, lane)
		return
	}

	// 409 carries the node's real offset. A real agent would adopt it and retry;
	// the sender deliberately does not (docu/03: nothing but notify's
	// vd_feed_offset may reshape what it sends), so the 409 stands as the
	// recorded outcome of a fleet whose offset knowledge went stale.
	a.r.reg.RecordScanVD(a.fleet.Name, lane, res.Status, us(res.Latency))
}
