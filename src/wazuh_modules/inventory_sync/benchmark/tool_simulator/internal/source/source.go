// Package source unifies inventory_sync and engine-event payload sources
// behind a single interface. The lane runner doesn't know which kind of
// source it is invoking.
package source

import (
	"context"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
)

// Source executes one step's worth of work on one agent. RepeatCount /
// InitialDelay / RepeatDelay loops are handled by the lane runner.
type Source interface {
	// Run drives a single iteration of the source. Returning context.Canceled
	// is allowed; any other error is logged and counted as a session failure.
	Run(ctx context.Context, conn *agent.Conn, c *metrics.Counters) error
	// Label returns a short string used in logs/metrics ("dump:foo",
	// "kind:fim_file", "engine:syslog.log").
	Label() string
}
