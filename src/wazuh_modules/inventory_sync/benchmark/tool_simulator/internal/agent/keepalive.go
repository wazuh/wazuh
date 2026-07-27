package agent

import (
	"context"
	"strings"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// KeepaliveResult is fired by the ticker once per emission attempt.
// Wired to metrics counters from the supervisor.
type KeepaliveResult struct {
	Err error // nil on success
}

// KeepaliveOptions controls one agent's keepalive ticker.
type KeepaliveOptions struct {
	// Interval between two keepalives. 0 disables the ticker (returns a
	// no-op stop function).
	Interval time.Duration
	// Groups reported in the JSON's `agent.groups` array. Empty slice or
	// nil omits the field entirely. The real agent reports the manager-
	// assigned groups; the simulator always uses {"default"}.
	Groups []string
	// OnTick (optional) is invoked synchronously after every send attempt
	// — successful or not. Used to bump telemetry counters.
	OnTick func(KeepaliveResult)
}

// StartKeepalive launches a goroutine that emits a `#!-<JSON>` control
// message every opts.Interval. Returns a cancel function that stops the
// ticker without blocking. Safe to call multiple times only if you keep
// the most recent cancel; older ones become no-ops.
//
// Cancellation honors both ctx and the returned stop func. The first one
// to fire wins.
func (c *Conn) StartKeepalive(ctx context.Context, opts KeepaliveOptions) (stop func()) {
	if opts.Interval <= 0 {
		return func() {}
	}
	kctx, cancel := context.WithCancel(ctx)
	go c.runKeepalive(kctx, opts)
	return cancel
}

func (c *Conn) runKeepalive(ctx context.Context, opts KeepaliveOptions) {
	t := time.NewTicker(opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			payload := c.buildKeepaliveJSON(opts.Groups)
			err := c.SendText("#!-" + payload)
			if opts.OnTick != nil {
				opts.OnTick(KeepaliveResult{Err: err})
			}
			// Errors are tolerated — the next tick will retry. If the
			// socket has died the runner will tear the whole agent down
			// shortly.
		}
	}
}

// buildKeepaliveJSON returns the minimal control-message payload the
// manager accepts: only agent.{id,name,version,merged_sum,groups}. The
// real agent (client-agent/src/notify.c build_json_keepalive) emits a
// fuller payload with host/os/cluster, but those fields are optional from
// the manager's standpoint — see secure.c parse_json_keepalive which
// fills them with defaults when absent.
func (c *Conn) buildKeepaliveJSON(groups []string) string {
	sum := c.MergedSum()
	var b strings.Builder
	b.Grow(128 + 16*len(groups))
	b.WriteString(`{"version":"1.0","agent":{"id":`)
	writeJSONString(&b, c.identity.ID)
	b.WriteString(`,"name":`)
	writeJSONString(&b, c.identity.Name)
	b.WriteString(`,"version":"` + wire.AgentVersion + `","merged_sum":`)
	writeJSONString(&b, sum)
	if len(groups) > 0 {
		b.WriteString(`,"groups":[`)
		for i, g := range groups {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(&b, g)
		}
		b.WriteByte(']')
	}
	b.WriteString(`}}`)
	return b.String()
}

// writeJSONString writes s as a JSON string literal (with surrounding
// quotes), escaping the minimum set of characters that JSON requires:
// `"`, `\`, and control chars < 0x20. We don't need full Unicode escaping
// — id/name/version/group values are ASCII in practice.
func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}
