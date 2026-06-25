# 10 — Go implementation notes

Implementation reference for the benchmark sender. Library picks, code
snippets, build instructions, and CLI flags.

## Recommended libraries

| Purpose                    | Library                                   | Notes                                                                                |
| -------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------ |
| FlatBuffers                | `github.com/google/flatbuffers/go`         | Pure Go, no cgo. Regenerate stubs with `flatc --go inventorySync.fbs`.               |
| AES-256-CBC                | stdlib `crypto/aes` + `crypto/cipher`      | Pure Go.                                                                             |
| zlib                       | stdlib `compress/zlib`                     | Pure Go.                                                                             |
| MD5                        | stdlib `crypto/md5`                        | For both key derivation and the inner-event checksum.                                |
| TLS for authd              | stdlib `crypto/tls`                        | `InsecureSkipVerify: true` (manager cert is self-signed).                            |
| Token-bucket EPS           | `golang.org/x/time/rate`                   | `burst=1` for strict leaky-bucket semantics.                                         |
| Goroutine groups + cancel  | `golang.org/x/sync/errgroup`               | Cleaner than hand-rolled `WaitGroup`+error channel for the per-agent fan-out.        |
| CLI                        | stdlib `flag`                              | Keep dashed-flag style.                                                          |
| JSON (data payloads)       | stdlib `encoding/json`                     | Streams large dumps; use `json.Decoder` for the items array of huge dumps.           |
| CSV writer                 | stdlib `encoding/csv`                      | Wrap in `bufio.Writer` with explicit `Flush()` per row.                              |
| Structured logging         | stdlib `log/slog`                          | Available since Go 1.21.                                                             |

**Do not** add cgo dependencies (NFR-5). The build target is a single
statically-linkable binary.

## Reference snippets in the repo

Two existing Go scripts in
[`engine/tools/devContainer/scripts/`](../../../../../engine/tools/devContainer/scripts/)
contain useful patterns:

- [`wazuh_sec_socket.go`](../../../../../engine/tools/devContainer/scripts/wazuh_sec_socket.go) —
  shows the `secureMessage()` pattern: 4-byte little-endian length prefix
  followed by the payload. The same encoding is used for the remoted frame.
- [`event_sock_v2.go`](../../../../../engine/tools/devContainer/scripts/event_sock_v2.go) —
  TCP/Unix socket with timeout helpers; useful as a base for the per-agent
  connection wrapper.

Neither implements AES or FlatBuffers, but the framing and timeout idioms
carry over.

## Project layout

The Go sender lives under [`tool_simulator/`](../):

```
benchmark/                          # orchestrator + scenarios + sample payloads
├── run_benchmark.sh                # calls the sender binary directly
├── scenarios/
├── sample_payloads/
└── tool_simulator/                 # Go sender (self-contained module)
    ├── go.mod
    ├── go.sum
    ├── Makefile                    # `make benchmark_sender_go`, `make regen_fb_stubs`
    ├── benchmark_sender            # built binary (gitignored)
    ├── docu/                       # this folder
    ├── cmd/
    │   └── benchmark_sender/
    │       └── main.go
    └── internal/
        ├── scenario/
        ├── agent/
        ├── inventory/
        ├── engine/
        ├── source/
        ├── wire/
        ├── fb/Wazuh/SyncSchema/
        ├── fbbuild/
        ├── metrics/
        ├── pacing/
        └── runner/
```

`internal/` keeps everything unimportable from outside `tool_simulator/`
— the sender is a self-contained binary, not a library.

## Build

Build from the `tool_simulator/` directory:

```bash
cd benchmark/tool_simulator
make benchmark_sender_go
# equivalent to: CGO_ENABLED=0 go build -trimpath -o benchmark_sender ./cmd/benchmark_sender
```

`-trimpath` keeps the binary reproducible. No CGO is used (NFR-5).

When the binary runs, it auto-resolves the bench dir as the parent of the
directory containing the executable — so scenario-relative paths like
`sample_payloads/...` and `scenarios/...` resolve correctly without any
extra flag.

## CLI flags

| Flag                       | Default                  | Meaning                                                                          |
| -------------------------- | ------------------------ | -------------------------------------------------------------------------------- |
| `--scenario PATH`          | (required)               | Scenario JSON file.                                                              |
| `--manager HOST`           | `127.0.0.1`              | Manager hostname/IP.                                                             |
| `--port N`                 | `1514`                   | Remoted port.                                                                    |
| `--reg-port N`             | `1515`                   | Authd port.                                                                      |
| `--drain-timeout SECS`     | `60`                     | Drain budget. Overrides scenario's `drain_timeout`.                              |
| `--summary-json PATH`      | (unset → no file written) | Output JSON summary.                                                             |
| `-o`, `--output PATH`      | `bench.csv`              | CSV output.                                                                      |
| `--key-wait SECS`          | `35`                     | Sleep between enrolment and remoted connect.                                     |
| `--keepalive-interval DUR` | `20s`                    | Keepalive ping interval per agent.                                               |
| `--debug`                  | `false`                  | Verbose logging.                                                                 |
| `--report-engine`          | `true`                   | Include engine-event metrics in summary JSON.                                    |

## Critical-path code sketches

### Key derivation

```go
import "crypto/md5"
import "encoding/hex"

func DeriveAESKey(managerKey, name, id string) []byte {
    h1 := md5.Sum([]byte(name))
    h2 := md5.Sum([]byte(id))
    sum := md5.Sum([]byte(hex.EncodeToString(h1[:]) + hex.EncodeToString(h2[:])))
    sum1 := hex.EncodeToString(sum[:])[:15]

    h3 := md5.Sum([]byte(managerKey))
    sum2 := hex.EncodeToString(h3[:])

    enc := sum2 + sum1                              // 47 ASCII bytes
    return []byte(enc)[:32]                         // AES-256 key
}
```

### Encrypt + wrap

```go
func wrapFrame(aesKey []byte, agentID string, identifier []byte) ([]byte, error) {
    inner := buildInner(identifier)                 // MD5(msg) || msg
    z, err := zlibCompress(inner)
    if err != nil { return nil, err }

    pad := (8 - len(z)%8) % 8
    if pad > 0 {
        z = append(bytes.Repeat([]byte{'!'}, pad), z...)
    }

    iv := []byte("FEDCBA0987654321")
    block, _ := aes.NewCipher(aesKey)
    mode := cipher.NewCBCEncrypter(block, iv)
    ct := make([]byte, len(z))
    mode.CryptBlocks(ct, z)

    header := fmt.Sprintf("!%s!#AES:", agentID)
    payload := append([]byte(header), ct...)

    lp := make([]byte, 4)
    binary.LittleEndian.PutUint32(lp, uint32(len(payload)))
    return append(lp, payload...), nil
}
```

### Inner-event construction

```go
func buildInner(identifier []byte) []byte {
    const prefix = "55555" + "1234567891" + ":" + "5555" + ":"
    msg := append([]byte(prefix), identifier...)
    h := md5.Sum(msg)
    return append([]byte(hex.EncodeToString(h[:])), msg...)
}
```

### Leaky-bucket pacing

```go
import "golang.org/x/time/rate"

lim := rate.NewLimiter(rate.Limit(step.MaxEPS), 1)
for _, item := range items {
    if err := lim.Wait(ctx); err != nil { return err }
    send(item)
}
```

`burst=1` enforces strict leaky-bucket semantics.

### Per-agent StartAck FIFO

```go
// PendingStart carries the module tag so the dispatcher can match each
// StartAck to the correct runner when two concurrent Starts on different
// modules race (the manager may process them out of wire order).
type PendingStart struct {
    tag   string       // module identifier echoed by the manager in "#!-<tag> <fb>"
    alive atomic.Bool  // cleared on runner timeout / cancel
    cb    StartAckCallback
}

type AgentConn struct {
    mu            sync.Mutex
    conn          net.Conn
    pendingStarts list.List // FIFO of *PendingStart, matched by tag
    sessions      sync.Map  // session_id → InboundCallback (Established)
}

func (a *AgentConn) SendStart(tag string, cb StartAckCallback, payload []byte) error {
    ps := &PendingStart{tag: tag, cb: cb}
    ps.alive.Store(true)
    a.mu.Lock()
    a.pendingStarts.PushBack(ps)
    err := a.writeFrame(payload)
    if err != nil {
        a.pendingStarts.Remove(a.pendingStarts.Back())
    }
    a.mu.Unlock()
    return err
}

// onStartAck matches the ack to the FIRST live PendingStart whose tag
// equals `tag`. Dead (cancelled) entries and entries for other modules
// are skipped. Within the same tag, FIFO order is preserved.
func (a *AgentConn) onStartAck(tag string, sessionID uint64, status Status) {
    var cb StartAckCallback
    a.mu.Lock()
    for e := a.pendingStarts.Front(); e != nil; {
        next := e.Next()
        ps := e.Value.(*PendingStart)
        if !ps.alive.Load() {
            a.pendingStarts.Remove(e)
            e = next
            continue
        }
        if ps.tag == tag {
            cb = ps.cb
            a.pendingStarts.Remove(e)
            break
        }
        e = next // live entry for a different module — leave in place
    }
    a.mu.Unlock()
    if cb != nil {
        cb(sessionID, status)
    }
}
```

## Testing

- Unit tests for `wrapFrame`/`unwrapFrame`: feed in known
  `(aesKey, agentID, identifier)` triples, assert byte-identical output
  against the golden files in `testdata/`.
- Unit tests for `DeriveAESKey`: same fixture approach.
- Parser tests for FlatBuffers: ship byte fixtures as `testdata/`, decode
  and assert field values.
- Scenario-loader tests: every committed scenario in
  [`scenarios/`](../../scenarios/) MUST parse without error.
- Integration tests: spawn a fake manager (stdlib `net` listener) that
  reads one frame, decrypts it, asserts the FlatBuffer type, sends a
  scripted ack — let the sender complete the session.

## Performance pointers

- Profile early with `runtime/pprof`. The hot path will be: FlatBuffer
  build (60%) + AES encrypt (20%) + zlib (15%) + write (5%).
- AES-NI is the difference between "1 core can do 100k EPS" and "1 core can
  do 5k EPS". Confirm `crypto/aes` is using the AES-NI fast path on the
  CI runner (it does by default on x86_64).
- zlib at `BestSpeed` (level 1) instead of `DefaultCompression` (level 6)
  may cut CPU significantly. **Do not change this without confirming the
  manager still parses the frames** — and even then, it changes wire
  output. Tackle it as a follow-up.
