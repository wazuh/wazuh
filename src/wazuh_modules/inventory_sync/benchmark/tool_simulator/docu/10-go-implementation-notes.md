# 10 — Go implementation notes

Practical guidance for the Go re-implementer. Library picks, snippets,
build/CLI contract, and the compatibility shim used during the migration.

## Recommended libraries

| Purpose                    | Library                                   | Notes                                                                                |
| -------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------ |
| FlatBuffers                | `github.com/google/flatbuffers/go`         | Pure Go, no cgo. Regenerate stubs with `flatc --go inventorySync.fbs`.               |
| AES-256-CBC                | stdlib `crypto/aes` + `crypto/cipher`      | Pure Go.                                                                             |
| zlib                       | stdlib `compress/zlib`                     | Pure Go.                                                                             |
| MD5                        | stdlib `crypto/md5`                        | For both key derivation and the inner-event checksum.                                |
| TLS for authd              | stdlib `crypto/tls`                        | `InsecureSkipVerify: true` (matches Python's `CERT_NONE`).                           |
| Token-bucket EPS           | `golang.org/x/time/rate`                   | `burst=1` for parity with Python's leaky-bucket pacing.                              |
| Goroutine groups + cancel  | `golang.org/x/sync/errgroup`               | Cleaner than hand-rolled `WaitGroup`+error channel for the per-agent fan-out.        |
| CLI                        | stdlib `flag` (or `github.com/spf13/pflag`)| Keep dashed-flag style for parity with Python.                                       |
| JSON (data payloads)       | stdlib `encoding/json`                     | Streams large dumps; use `json.Decoder` for the items array of huge dumps.           |
| CSV writer                 | stdlib `encoding/csv`                      | Wrap in `bufio.Writer` with explicit `Flush()` per row.                              |
| Structured logging         | stdlib `log/slog`                          | Available since Go 1.21.                                                             |

**Do not** add cgo dependencies (NFR-5). The build target is a single
statically-linkable binary.

## Reference snippets already in the repo

Two existing Go scripts in
[`engine/tools/devContainer/scripts/`](../../../../../engine/tools/devContainer/scripts/)
contain patterns directly applicable here:

- [`wazuh_sec_socket.go`](../../../../../engine/tools/devContainer/scripts/wazuh_sec_socket.go) —
  shows the `secureMessage()` pattern: 4-byte little-endian length prefix
  followed by the payload. Reuse the same encoding for the remoted frame.
- [`event_sock_v2.go`](../../../../../engine/tools/devContainer/scripts/event_sock_v2.go) —
  TCP/Unix socket with timeout helpers; useful as a base for the per-agent
  connection wrapper.

Neither implements AES or FlatBuffers, but the framing and timeout idioms
carry over.

## Project layout

The Go code is encapsulated under [`tool_simulator/`](../),
fully separate from the legacy Python sender and the orchestrator scripts:

```
benchmark/                          # orchestrator + scenarios + sample payloads
├── benchmark_sender.py             # legacy Python sender, kept during migration
├── run_benchmark.sh                # picks engine via --engine python|go
├── scenarios/                      # consumed by both senders
├── sample_payloads/                # consumed by both senders
└── tool_simulator/                 # Go reimplementation (self-contained module)
    ├── go.mod
    ├── go.sum
    ├── Makefile                    # `make benchmark_sender_go`, `make regen_fb_stubs`
    ├── benchmark_sender            # built binary (gitignored or committed per release)
    ├── docu/                       # this folder (functional spec + design docs)
    ├── cmd/
    │   └── benchmark_sender/       # main package
    │       └── main.go
    └── internal/
        ├── scenario/               # JSON loader + validator (03-scenario-schema.md)
        ├── agent/                  # outer state machine + Conn (04-agent-state-machine.md)
        ├── inventory/              # inventory_sync Source + payload loader
        ├── engine/                 # engine-event Source (12-engine-event-streams.md)
        ├── source/                 # Source interface unifying both
        ├── wire/                   # framing, crypto, control msg (05-wire-protocol.md)
        ├── fb/Wazuh/SyncSchema/    # generated FlatBuffers stubs (06-flatbuffers-messages.md)
        ├── fbbuild/                # builders/parsers for the Message union
        ├── metrics/                # counters + latency hist + CSV + summary (08-metrics-and-output.md)
        ├── pacing/                 # rate-limiter wrapper (07-concurrency-and-pacing.md)
        └── runner/                 # supervisor: fleets → agents → lanes → steps
```

`internal/` keeps everything unimportable from outside `tool_simulator/`
— the sender is a self-contained binary, not a library.

## Build

The orchestrator [`run_benchmark.sh`](../../run_benchmark.sh) calls the
sender via:

```bash
"$PYTHON" "$SCRIPT_DIR/benchmark_sender.py" ...           # --engine=python (default)
"$SCRIPT_DIR/tool_simulator/benchmark_sender" ...         # --engine=go
```

The Go binary lives at [`tool_simulator/benchmark_sender`](../).
Build it from the `tool_simulator/` directory:

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

## CLI contract (parity with Python)

The current Python flags are documented in `benchmark_sender.py`'s argparse
block. Reproduce them all, with the same defaults:

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
| `--debug`                  | `false`                  | Verbose logging.                                                                 |
| `--engine python|go`       | new flag — see below     | Used by the shim to pick the implementation. Default `python` during migration.  |

The `--engine` flag is interpreted by `run_benchmark.sh`, not by the
binary itself; both binaries silently ignore it.

## Compatibility shim during the migration

Phase 1 — both implementations coexist:

```bash
# run_benchmark.sh excerpt
BENCH_ENGINE="${BENCH_ENGINE:-python}"     # or read from --engine
case "$BENCH_ENGINE" in
    python) "$PYTHON" "$SCRIPT_DIR/benchmark_sender.py" "$@" ;;
    go)     "$SCRIPT_DIR/tool_simulator/benchmark_sender" "$@" ;;
    *)      echo "unknown engine: $BENCH_ENGINE" >&2; exit 2 ;;
esac
```

Phase 2 — once parity is signed off (see
[11-acceptance-criteria.md](./11-acceptance-criteria.md)):

- Default flips to `go`.
- Python sender is moved aside (`benchmark_sender.py.legacy`) but kept for
  one release cycle.

Phase 3 — clean up. Drop the shim. Remove `benchmark_sender.py`.

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

`burst=1` keeps it equivalent to the Python algorithm.

### Per-agent StartAck FIFO

```go
type AgentConn struct {
    mu             sync.Mutex
    conn           net.Conn
    pendingStarts  list.List           // FIFO of *Runner waiting for StartAck
    sessions       sync.Map            // session_id → *Runner (Established)
}

func (a *AgentConn) SendStart(r *Runner, payload []byte) error {
    a.mu.Lock()
    a.pendingStarts.PushBack(r)
    err := a.writeFrame(payload)
    a.mu.Unlock()
    return err
}

func (a *AgentConn) onStartAck(sessionID uint64, status Status) {
    a.mu.Lock()
    front := a.pendingStarts.Front()
    a.pendingStarts.Remove(front)
    a.mu.Unlock()
    r := front.Value.(*Runner)
    r.startResult <- StartResult{Session: sessionID, Status: status}
    if status == Status_Ok {
        a.sessions.Store(sessionID, r)
    }
}
```

## Testing the Go port

- Unit tests for `wrapFrame`/`unwrapFrame`: feed in known
  `(aesKey, agentID, identifier)` triples, assert byte-identical output
  vs Python (capture once from the Python script, store as `testdata/`).
- Unit tests for `DeriveAESKey`: same fixture approach.
- Parser tests for FlatBuffers: build messages in Python, ship their
  bytes as `testdata/`, decode and assert field values.
- Scenario-loader tests: every committed scenario in
  [`scenarios/`](../../scenarios/) MUST parse without error.
- Integration tests: spawn a fake manager (stdlib `net` listener) that
  reads one frame, decrypts it, asserts the FlatBuffer type, sends a
  scripted ack — let the Go sender complete the session.

## Performance pointers

- Profile early with `runtime/pprof`. The hot path will be: FlatBuffer
  build (60%) + AES encrypt (20%) + zlib (15%) + write (5%).
- AES-NI is the difference between "1 core can do 100k EPS" and "1 core can
  do 5k EPS". Confirm `crypto/aes` is using the AES-NI fast path on the
  CI runner (it does by default on x86_64).
- zlib at `BestSpeed` (level 1) instead of `DefaultCompression` (level 6)
  may cut CPU significantly. **Do not change this without confirming the
  manager still parses the frames** — and even then, it changes wire
  output and breaks NFR-2 parity for the duration of the migration.
  Tackle it as a follow-up.
