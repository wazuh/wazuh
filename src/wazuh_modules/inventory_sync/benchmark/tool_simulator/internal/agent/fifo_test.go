package agent

import (
	"container/list"
	"sync"
	"testing"

	fb "github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fb/Wazuh/SyncSchema"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fbbuild"
)

func newConn(t *testing.T) *Conn {
	t.Helper()
	return &Conn{
		identity:      Identity{ID: "001"},
		pendingStarts: list.New(),
		sessions:      make(map[uint64]InboundCallback),
	}
}

func mkPending(tag string, cb StartAckCallback) *PendingStart {
	ps := &PendingStart{cb: cb, tag: tag}
	ps.alive.Store(true)
	return ps
}

// TestDispatch_MatchesStartAckByTag is the cardinal test for the
// session-id-mixup fix. Two concurrent Starts (different modules) are
// pending; the manager replies for the SECOND module first. Without
// tag-based matching, the FIRST runner would steal the second's session
// id. With tag matching each runner gets its own.
func TestDispatch_MatchesStartAckByTag(t *testing.T) {
	c := newConn(t)
	var (
		mu      sync.Mutex
		got     = make(map[string]uint64)
	)
	mkCb := func(name string) StartAckCallback {
		return func(session uint64, _ fb.Status) {
			mu.Lock()
			got[name] = session
			mu.Unlock()
		}
	}
	psSyscoll := mkPending("syscollector_sync", mkCb("syscollector"))
	psFim := mkPending("fim_sync", mkCb("fim"))
	c.pendingStarts.PushBack(psSyscoll)
	c.pendingStarts.PushBack(psFim)

	// Manager replies for fim FIRST (size=27726 dump finishes processing
	// faster, say). Without tag matching, syscollector_sync's callback
	// would fire with fim's session id.
	c.dispatch("fim_sync", fbbuild.Inbound{Type: fb.MessageTypeStartAck, Session: 222})
	c.dispatch("syscollector_sync", fbbuild.Inbound{Type: fb.MessageTypeStartAck, Session: 111})

	mu.Lock()
	defer mu.Unlock()
	if got["fim"] != 222 {
		t.Errorf("fim got %d, want 222", got["fim"])
	}
	if got["syscollector"] != 111 {
		t.Errorf("syscollector got %d, want 111", got["syscollector"])
	}
	if c.pendingStarts.Len() != 0 {
		t.Errorf("FIFO should be empty, has %d", c.pendingStarts.Len())
	}
}

// TestDispatch_FIFOWithinSameTag verifies that two pending Starts on the
// SAME module are still matched in FIFO order (preserves Python semantics
// for the common case).
func TestDispatch_FIFOWithinSameTag(t *testing.T) {
	c := newConn(t)
	var firstSession, secondSession uint64
	psA := mkPending("syscollector_sync", func(s uint64, _ fb.Status) { firstSession = s })
	psB := mkPending("syscollector_sync", func(s uint64, _ fb.Status) { secondSession = s })
	c.pendingStarts.PushBack(psA)
	c.pendingStarts.PushBack(psB)
	c.dispatch("syscollector_sync", fbbuild.Inbound{Type: fb.MessageTypeStartAck, Session: 1})
	c.dispatch("syscollector_sync", fbbuild.Inbound{Type: fb.MessageTypeStartAck, Session: 2})
	if firstSession != 1 || secondSession != 2 {
		t.Errorf("first=%d second=%d, want 1, 2", firstSession, secondSession)
	}
}

// TestDispatch_SkipsOrphans verifies orphan handling (timed-out runners).
func TestDispatch_SkipsOrphans(t *testing.T) {
	c := newConn(t)
	var fired uint64
	psOrphan := mkPending("syscollector_sync", func(uint64, fb.Status) {
		t.Fatal("orphan callback fired")
	})
	psLive := mkPending("syscollector_sync", func(s uint64, _ fb.Status) { fired = s })
	psOrphan.Cancel()
	c.pendingStarts.PushBack(psOrphan)
	c.pendingStarts.PushBack(psLive)

	c.dispatch("syscollector_sync", fbbuild.Inbound{Type: fb.MessageTypeStartAck, Session: 42})
	if fired != 42 {
		t.Errorf("live runner got %d, want 42", fired)
	}
	if c.pendingStarts.Len() != 0 {
		t.Errorf("FIFO not drained: %d", c.pendingStarts.Len())
	}
}

// TestDispatch_LiveEntryFiresNormally is the happy-path sanity test.
func TestDispatch_LiveEntryFiresNormally(t *testing.T) {
	c := newConn(t)
	var fired uint64
	ps := mkPending("fim_sync", func(s uint64, _ fb.Status) { fired = s })
	c.pendingStarts.PushBack(ps)
	c.dispatch("fim_sync", fbbuild.Inbound{Type: fb.MessageTypeStartAck, Session: 7})
	if fired != 7 {
		t.Fatalf("got %d, want 7", fired)
	}
}

// TestDispatch_NoMatchingTagIsDropped verifies that when no live entry
// matches the tag, the StartAck is silently dropped (and other entries
// are NOT consumed).
func TestDispatch_NoMatchingTagIsDropped(t *testing.T) {
	c := newConn(t)
	ps := mkPending("syscollector_sync", func(uint64, fb.Status) {
		t.Fatal("wrong-tag callback fired")
	})
	c.pendingStarts.PushBack(ps)

	c.dispatch("fim_sync", fbbuild.Inbound{Type: fb.MessageTypeStartAck, Session: 99})

	// syscollector entry should still be in the FIFO, awaiting its own ack.
	if c.pendingStarts.Len() != 1 {
		t.Errorf("FIFO should still have 1 entry, has %d", c.pendingStarts.Len())
	}
}

// TestStripIdentifier_ManagerInbound verifies the parser extracts the tag
// from the manager-side `#!-<tag> <fb>` format.
func TestStripIdentifier_ManagerInbound(t *testing.T) {
	cases := []struct {
		in      string
		wantTag string
		wantFB  string
	}{
		{"#!-syscollector_sync " + string(make([]byte, 16)), "syscollector_sync", string(make([]byte, 16))},
		{"#!-fim_sync " + string(make([]byte, 16)), "fim_sync", string(make([]byte, 16))},
		{"#!-syscollector_vd_sync " + string(make([]byte, 16)), "syscollector_vd_sync", string(make([]byte, 16))},
		{"#!-agent ack ", "", ""},                   // control msg → reject
		{"#!-foo_bar " + string(make([]byte, 16)), "", ""}, // doesn't end with _sync → reject
		{"s:syscollector_sync:" + string(make([]byte, 16)), "syscollector_sync", string(make([]byte, 16))},
	}
	for _, tc := range cases {
		gotTag, gotFB := stripIdentifier([]byte(tc.in))
		if gotTag != tc.wantTag {
			t.Errorf("in=%q: tag=%q, want %q", tc.in, gotTag, tc.wantTag)
		}
		if string(gotFB) != tc.wantFB {
			t.Errorf("in=%q: fb-len=%d want %d", tc.in, len(gotFB), len(tc.wantFB))
		}
	}
}
