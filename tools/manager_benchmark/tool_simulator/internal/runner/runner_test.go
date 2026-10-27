package runner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

// TestAdmitAgentsStopsAdmittingOnCancel pins that a cancelled run admits no
// one else: the first agent cancels the run while every other one is still
// waiting for a slot, and none of them may start afterwards.
func TestAdmitAgentsStopsAdmittingOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	var started int64
	admitted := admitAgents(ctx, 10, 1, &wg, func(i int) {
		atomic.AddInt64(&started, 1)
		if i == 0 {
			cancel()
		}
	})
	wg.Wait()

	if admitted != 1 {
		t.Errorf("admitted %d agents, want 1 (only the one running when the run was cancelled)", admitted)
	}
	if got := atomic.LoadInt64(&started); got != 1 {
		t.Errorf("%d agents ran, want 1", got)
	}
}

// TestAdmitAgentsAdmitsNoneWhenAlreadyCancelled covers a run cancelled before
// admission began (a signal during enrollment, a deadline already past): even
// with free slots, nobody starts.
func TestAdmitAgentsAdmitsNoneWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var wg sync.WaitGroup
	var started int64
	admitted := admitAgents(ctx, 5, 5, &wg, func(int) { atomic.AddInt64(&started, 1) })
	wg.Wait()

	if admitted != 0 || atomic.LoadInt64(&started) != 0 {
		t.Errorf("admitted %d and ran %d agents on a cancelled run, want 0 and 0",
			admitted, atomic.LoadInt64(&started))
	}
}

// TestAdmitAgentsRespectsTheConcurrencyCap is the uncancelled path: every agent
// runs, never more than limit at once.
func TestAdmitAgentsRespectsTheConcurrencyCap(t *testing.T) {
	var wg sync.WaitGroup
	var running, peak, started int64
	admitted := admitAgents(context.Background(), 20, 3, &wg, func(int) {
		now := atomic.AddInt64(&running, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if now <= p || atomic.CompareAndSwapInt64(&peak, p, now) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt64(&running, -1)
		atomic.AddInt64(&started, 1)
	})
	wg.Wait()

	if admitted != 20 || atomic.LoadInt64(&started) != 20 {
		t.Errorf("admitted %d and ran %d agents, want 20 and 20", admitted, atomic.LoadInt64(&started))
	}
	if p := atomic.LoadInt64(&peak); p > 3 {
		t.Errorf("%d agents ran at once, want at most 3", p)
	}
}

// TestMetaRecordsTheEffectiveKeepaliveInterval pins that meta.keepalive_interval
// is the interval the keepalive loop uses, not the raw scenario value: absent
// or zero is the 10 s default, never "0s".
func TestMetaRecordsTheEffectiveKeepaliveInterval(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
		want     string
	}{
		{"absent", 0, "10s"},
		{"negative", -time.Second, "10s"},
		{"set", 5 * time.Second, "5s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scn := &scenario.Scenario{Name: "keepalive"}
			scn.Defaults.Control.Enabled = true
			scn.Defaults.Control.KeepaliveInterval = scenario.Duration(tc.interval)
			r := New(Config{Scenario: scn, Mode: "agent", Bootstrap: BootstrapEnrollToken})

			if got := r.keepaliveInterval().String(); got != tc.want {
				t.Errorf("keepaliveInterval() = %s, want %s", got, tc.want)
			}
			if got := r.Meta().KeepaliveInterval; got != tc.want {
				t.Errorf("meta.keepalive_interval = %q, want %q", got, tc.want)
			}
		})
	}
}
