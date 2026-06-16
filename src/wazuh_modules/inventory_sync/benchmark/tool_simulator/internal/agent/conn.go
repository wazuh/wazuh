package agent

import (
	"bytes"
	"container/list"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	fb "github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fb/Wazuh/SyncSchema"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fbbuild"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// MergedSumObserver is fired whenever the reader extracts a new merged.mg
// hash from a `#!-up file <md5> merged.mg` frame. Wired to a metrics
// counter from the supervisor so we can graph "how often did the manager
// resync the agent's shared file".
type MergedSumObserver func(newMD5 string)

// StartAckCallback receives the manager's StartAck for the next pending
// runner (FIFO). status comes straight from the FB enum.
type StartAckCallback func(session uint64, status fb.Status)

// PendingStart is one entry in the per-agent StartAck FIFO.
//
// Two safeguards prevent session-id mixups when the manager processes
// concurrent Starts out of order or a reply is lost:
//
//  1. `alive` is cleared by the runner on timeout / cancel; the dispatcher
//     skips dead entries (mirrors Python's start_pending filter).
//  2. `tag` records the module-sync routing identifier we sent with the
//     Start. The dispatcher MATCHES inbound StartAcks against this tag
//     (the manager echoes it in the `#!-<tag> <fb>` wire prefix), so when
//     two concurrent Starts on different modules race, each runner gets
//     its OWN session id, not the other one's.
type PendingStart struct {
	cb    StartAckCallback
	tag   string
	alive atomic.Bool
}

// Cancel marks this pending start as abandoned so the next StartAck
// arriving will skip past it. Safe to call multiple times; safe to call
// from any goroutine.
func (p *PendingStart) Cancel() { p.alive.Store(false) }

// InboundCallback receives EndAck/ReqRet frames routed by session id.
type InboundCallback func(msg fbbuild.Inbound)

// Conn is one agent's outbound socket + reader goroutine.
type Conn struct {
	identity Identity
	aesKey   []byte
	manager  string
	port     int

	sock net.Conn

	sendMu sync.Mutex
	// pendingStarts is the FIFO of StartAckCallbacks awaiting their ack.
	// Protected by sendMu so wire order == FIFO order.
	pendingStarts *list.List

	sessionsMu sync.RWMutex
	sessions   map[uint64]InboundCallback

	// mergedSum is the MD5 the manager last advertised for the agent's
	// group (`default`). Updated by the reader when it parses a
	// `#!-up file <md5> merged.mg` frame. Read by the keepalive builder.
	// Empty until the manager pushes us the file (typically right after
	// the first keepalive with merged_sum=""). Atomic so the keepalive
	// goroutine can read it lock-free.
	mergedSum         atomic.Pointer[string]
	mergedSumObserver MergedSumObserver

	readerCtx    context.Context
	readerCancel context.CancelFunc
	readerDone   chan struct{}

	socketAlive atomic.Bool
}

// New creates a Conn, derives its AES key from the identity. Call Dial to
// open the TCP socket and StartReader to spawn the demuxer.
func New(identity Identity, manager string, port int) *Conn {
	return &Conn{
		identity:      identity,
		aesKey:        wire.DeriveAESKey(identity.ManagerKey, identity.Name, identity.ID),
		manager:       manager,
		port:          port,
		pendingStarts: list.New(),
		sessions:      make(map[uint64]InboundCallback),
	}
}

// Identity returns the agent's id+name (read-only).
func (c *Conn) Identity() Identity { return c.identity }

// Dial opens the TCP socket to remoted and sends the startup control msg.
func (c *Conn) Dial(timeout time.Duration) error {
	addr := net.JoinHostPort(c.manager, fmt.Sprintf("%d", c.port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("remoted dial: %w", err)
	}
	c.sock = conn
	c.socketAlive.Store(true)

	ctrl := wire.BuildStartupControlMessage(c.identity.Name, c.identity.ID)
	frame, err := wire.EncodeText(c.aesKey, c.identity.ID, ctrl)
	if err != nil {
		return fmt.Errorf("encode control: %w", err)
	}
	if err := wire.WriteFrame(c.sock, frame); err != nil {
		return fmt.Errorf("write control: %w", err)
	}
	// Give remoted ~1s to ingest then drain any incidental bytes.
	time.Sleep(time.Second)
	return nil
}

// Close shuts the socket and stops the reader.
func (c *Conn) Close() {
	c.socketAlive.Store(false)
	if c.readerCancel != nil {
		c.readerCancel()
	}
	if c.sock != nil {
		_ = c.sock.Close()
	}
	if c.readerDone != nil {
		select {
		case <-c.readerDone:
		case <-time.After(2 * time.Second):
		}
	}
}

// Alive returns whether the socket is still considered live.
func (c *Conn) Alive() bool { return c.socketAlive.Load() }

// sendStartLocked pushes a PendingStart onto the FIFO and writes the
// frame, all under sendMu so wire order == FIFO order.
func (c *Conn) sendStartLocked(ps *PendingStart, frame []byte) error {
	c.pendingStarts.PushBack(ps)
	if err := wire.WriteFrame(c.sock, frame); err != nil {
		// On failure, undo the push so the FIFO doesn't drift.
		c.pendingStarts.Remove(c.pendingStarts.Back())
		return err
	}
	return nil
}

// SendStart atomically pushes a PendingStart onto the FIFO and writes the
// Start frame. cb is invoked from the reader goroutine when the manager's
// StartAck for THIS module's Start arrives — matched by tag, so two
// concurrent Starts on different modules can't swap session ids. The
// caller MUST call ps.Cancel() if it gives up before receiving the
// StartAck. See docu/04-agent-state-machine.md.
func (c *Conn) SendStart(identifier string, fbBytes []byte, cb StartAckCallback) (*PendingStart, error) {
	frame, err := wire.EncodeBinary(c.aesKey, c.identity.ID, identifier, fbBytes)
	if err != nil {
		return nil, err
	}
	ps := &PendingStart{cb: cb, tag: identifier}
	ps.alive.Store(true)

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if !c.socketAlive.Load() {
		return nil, fmt.Errorf("socket not alive")
	}
	if err := c.sendStartLocked(ps, frame); err != nil {
		return nil, err
	}
	return ps, nil
}

// SendBinary writes an inventory_sync FlatBuffer payload (non-Start type).
// Caller is responsible for any session-id bookkeeping via RegisterSession.
func (c *Conn) SendBinary(identifier string, fbBytes []byte) error {
	frame, err := wire.EncodeBinary(c.aesKey, c.identity.ID, identifier, fbBytes)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if !c.socketAlive.Load() {
		return fmt.Errorf("socket not alive")
	}
	return wire.WriteFrame(c.sock, frame)
}

// SendText writes a plain-text payload (engine event / control). For
// engine events the caller passes "1:<location>:<line>" verbatim.
func (c *Conn) SendText(text string) error {
	frame, err := wire.EncodeText(c.aesKey, c.identity.ID, text)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if !c.socketAlive.Load() {
		return fmt.Errorf("socket not alive")
	}
	return wire.WriteFrame(c.sock, frame)
}

// SendShutdown emits the agent farewell control message
// (`#!-agent shutdown `, no payload). Best-effort: errors are returned
// for telemetry but the caller is expected to Close() right after.
// Mirrors send_agent_stopped_message() in client-agent/src/start_agent.c.
func (c *Conn) SendShutdown() error {
	return c.SendText("#!-agent shutdown ")
}

// MergedSum returns the most recently observed `merged.mg` MD5 advertised
// by the manager. Returns "" until the first `#!-up file` arrives.
func (c *Conn) MergedSum() string {
	if p := c.mergedSum.Load(); p != nil {
		return *p
	}
	return ""
}

// SetMergedSumObserver installs an optional callback fired every time
// the reader observes a new merged.mg hash from the manager. Used by
// the supervisor to bump a `merged_sum_updates` counter.
func (c *Conn) SetMergedSumObserver(obs MergedSumObserver) {
	c.mergedSumObserver = obs
}

// fileUpdatePrefix is the wire-level header the manager uses to push a
// shared file (typically merged.mg) to the agent. See
// remoted/src/manager.c:1731 — `snprintf(... "%s%s%s %s\n", CONTROL_HEADER,
// FILE_UPDATE_HEADER, sum, name)`.
var fileUpdatePrefix = []byte("#!-up file ")

// parseFileUpdate extracts the MD5 hash from a payload that begins with
// `#!-up file <md5> <name>\n<body>`. Stores it in c.mergedSum and fires
// the observer if one is set. Tolerates short / malformed payloads
// silently — the file body is discarded.
func (c *Conn) parseFileUpdate(payload []byte) {
	rest := payload[len(fileUpdatePrefix):]
	sp := bytes.IndexByte(rest, ' ')
	if sp < 32 {
		// MD5 hex is exactly 32 chars; anything shorter is malformed.
		return
	}
	md5 := string(rest[:sp])
	for i := 0; i < len(md5); i++ {
		b := md5[i]
		isHex := (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
		if !isHex {
			return
		}
	}
	prev := c.MergedSum()
	c.mergedSum.Store(&md5)
	if md5 != prev && c.mergedSumObserver != nil {
		c.mergedSumObserver(md5)
	}
}

// RegisterSession remembers a callback for inbound frames carrying this
// session id. Call UnregisterSession when the runner is done.
func (c *Conn) RegisterSession(sessionID uint64, cb InboundCallback) {
	c.sessionsMu.Lock()
	c.sessions[sessionID] = cb
	c.sessionsMu.Unlock()
}

// UnregisterSession removes the inbound routing for a session id.
func (c *Conn) UnregisterSession(sessionID uint64) {
	c.sessionsMu.Lock()
	delete(c.sessions, sessionID)
	c.sessionsMu.Unlock()
}

// StartReader spawns the per-agent reader goroutine. It returns when ctx
// is canceled or the socket reports EOF.
func (c *Conn) StartReader(ctx context.Context) {
	c.readerCtx, c.readerCancel = context.WithCancel(ctx)
	c.readerDone = make(chan struct{})
	go c.readLoop()
}

func (c *Conn) readLoop() {
	defer close(c.readerDone)
	for {
		select {
		case <-c.readerCtx.Done():
			return
		default:
		}
		frame, err := wire.ReadFrame(c.sock)
		if err != nil {
			c.socketAlive.Store(false)
			c.wakeAll()
			return
		}
		payload, err := wire.DecodeFrame(c.aesKey, frame)
		if err != nil {
			// drop; manager garbage shouldn't kill the reader
			continue
		}
		// Shared-file push from the manager:
		//   "#!-up file <md5> <filename>\n<body>"
		// We don't care about the file body — only the MD5 so the next
		// keepalive can echo a matching merged_sum and break the manager's
		// "not synced → resend" loop. See remoted/src/manager.c:1731.
		if bytes.HasPrefix(payload, fileUpdatePrefix) {
			c.parseFileUpdate(payload)
			continue
		}
		tag, fbBytes := stripIdentifier(payload)
		if fbBytes == nil {
			// Control acks (`#!-agent ack`), unknown shapes, etc. Ignored.
			continue
		}
		in, err := fbbuild.ParseInbound(fbBytes)
		if err != nil {
			continue
		}
		c.dispatch(tag, in)
	}
}

func (c *Conn) dispatch(tag string, in fbbuild.Inbound) {
	switch in.Type {
	case fb.MessageTypeStartAck:
		// Match this StartAck to the FIRST live PendingStart whose tag
		// equals `tag`. Skipping non-matching live entries handles the
		// case where the manager processes two concurrent Starts (on
		// different modules) out of wire order — without this match by
		// tag, the wrong runner would capture a foreign session id and
		// subsequent DataValues would be rejected with "seq exceeds
		// declared size". Dead orphans are pruned along the way.
		var cb StartAckCallback
		c.sendMu.Lock()
		for e := c.pendingStarts.Front(); e != nil; {
			next := e.Next()
			ps := e.Value.(*PendingStart)
			if !ps.alive.Load() {
				c.pendingStarts.Remove(e)
				e = next
				continue
			}
			if ps.tag == tag {
				cb = ps.cb
				c.pendingStarts.Remove(e)
				break
			}
			// Live entry for a different module — leave it in place; its
			// own StartAck will arrive later.
			e = next
		}
		c.sendMu.Unlock()
		if cb != nil {
			cb(in.Session, in.Status)
		}
	case fb.MessageTypeEndAck, fb.MessageTypeReqRet:
		c.sessionsMu.RLock()
		target := c.sessions[in.Session]
		c.sessionsMu.RUnlock()
		if target != nil {
			target(in)
		}
	}
}

// wakeAll notifies pending Start callbacks and registered session
// callbacks that the socket is gone.
func (c *Conn) wakeAll() {
	c.sendMu.Lock()
	pending := make([]*PendingStart, 0, c.pendingStarts.Len())
	for e := c.pendingStarts.Front(); e != nil; e = e.Next() {
		pending = append(pending, e.Value.(*PendingStart))
	}
	c.pendingStarts.Init() // clear
	c.sendMu.Unlock()
	for _, ps := range pending {
		if ps.alive.Load() {
			ps.cb(0, fb.StatusOffline)
		}
	}
	c.sessionsMu.RLock()
	regs := make([]InboundCallback, 0, len(c.sessions))
	for _, cb := range c.sessions {
		regs = append(regs, cb)
	}
	c.sessionsMu.RUnlock()
	for _, cb := range regs {
		cb(fbbuild.Inbound{Type: fb.MessageTypeEndAck, Status: fb.StatusOffline})
	}
}

// stripIdentifier returns the module tag and FlatBuffer bytes from an
// inbound payload. Two routing formats are accepted, matching Python's
// _parse_response:
//
//	"s:<tag>:<fbBytes>"      — agent → manager (and any echo back)
//	"#!-<tag> <fbBytes>"      — manager → agent for inventory_sync responses
//
// The control-message ack `#!-agent ack ` (empty body) returns ("", nil)
// so the reader skips it. Same for any other unknown shape.
func stripIdentifier(payload []byte) (string, []byte) {
	if len(payload) < 4 {
		return "", nil
	}
	// Manager → agent: `#!-<module>_sync <fbBytes>`. We only accept tags
	// that end with `_sync` (the inventory_sync routing convention) so that
	// control responses such as `#!-agent ack` are filtered out before
	// they reach the FlatBuffer parser, which would crash on non-FB input.
	if payload[0] == '#' && payload[1] == '!' && payload[2] == '-' {
		sp := indexByte(payload[3:], ' ')
		if sp < 0 {
			return "", nil
		}
		tag := string(payload[3 : 3+sp])
		if len(tag) < 5 || tag[len(tag)-5:] != "_sync" {
			return "", nil
		}
		fb := payload[3+sp+1:]
		// FlatBuffer Message needs at least the 4-byte root offset + a
		// vtable, so anything below 8 bytes can't be a valid Message.
		if len(fb) < 8 {
			return "", nil
		}
		return tag, fb
	}
	// Agent → manager (or echo): `s:<module>_sync:<fbBytes>`
	if payload[0] == 's' && payload[1] == ':' {
		for i := 2; i < len(payload); i++ {
			if payload[i] == ':' {
				return string(payload[2:i]), payload[i+1:]
			}
		}
	}
	return "", nil
}

// indexByte is bytes.IndexByte without the import (kept inline so this
// file stays focused).
func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
