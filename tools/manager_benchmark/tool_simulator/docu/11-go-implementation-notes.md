# 11 — Go implementation notes

Guidance for F9c-2. The retired simulator's choices that still apply are kept deliberately, so the
two tools read alike where they do the same thing.

## Libraries

| Need | Choice | Why |
|---|---|---|
| CLI | stdlib `flag` | Same dashed-flag style as the retired sender; no dependency for a dozen knobs |
| HTTP client | stdlib `net/http` | Custom `DialContext` covers both TLS/1517 and `unix://`; per-agent client for identity isolation |
| TLS | stdlib `crypto/tls` with `InsecureSkipVerify` | Test managers are self-signed; no client certificate is required |
| AES-CMAC | stdlib `crypto/aes` + a CMAC implementation | Go's stdlib has no CMAC; a small vetted implementation (or ~40 lines following RFC 4493) is preferable to a heavy dependency. **MUST** be unit-tested against a known vector and against the reference in `remoted_module/tools/send_stateless.py` |
| FlatBuffers | `github.com/google/flatbuffers/go` + `flatc --go` at build time | Bindings generated, never committed (see [05](05-flatbuffers-messages.md)) |
| Pacing | `golang.org/x/time/rate` | Leaky bucket, same as the retired sender |
| `github.com/klauspost/compress/zstd` | `Content-Encoding: zstd` request bodies (remoted's contract) and the `.json.zst` dump corpus | Pure Go: the no-cgo rule below rules out binding the repo's vendored C zstd |
| Goroutine groups | `golang.org/x/sync/errgroup` | Fleet supervision with first-error propagation |
| JSON | stdlib `encoding/json` | Control bodies are tiny; the session bodies are FlatBuffers |

**No cgo.** The tool must cross-build and run from a plain `go build`.

## Package layout

```text
tool_simulator/
├── cmd/benchmark_sender/main.go   # flags, scenario load, runner wiring, signals, exit code
├── internal/
│   ├── wire/        # enrollment (authd), AES-CMAC signing, HTTPS and UDS transports
│   ├── control/     # startup / notify / shutdown: build, send, validate-and-discard
│   ├── fbbuild/     # scenario step -> Message{FullSession} bytes
│   ├── fb/          # GENERATED bindings (flatc --go); gitignored
│   ├── engine/      # H/E batch framing for POST /stateless (an engine-stream lane)
│   ├── scenario/    # lanes/fleets schema types, loader, strict validation
│   ├── source/      # deterministic document/event generation (count, size, checksum, log lines)
│   ├── runner/      # fleet admission; per-agent keepalive loop + one goroutine per lane; drain
│   ├── metrics/     # counters + per-kind histograms, sliced by lane and fleet; bench.csv + summary JSON
│   └── pacing/      # shared session limiter + per-lane limiters
└── docu/            # this documentation set
```

Boundaries worth keeping: `wire` knows nothing about scenarios, `fbbuild` and `engine` know nothing
about transports, and `metrics` is the only package that formats artifacts (so
[09](09-metrics-and-output.md) has exactly one implementation). The `metrics` package is also the
only one that knows a run is sliced by lane and fleet — every count and histogram is keyed by
`(fleet, lane, kind)` and aggregated up, so the three granularities in the summary are one code
path, not three.

## Practices

- **One `http.Client` per agent**, with its own connection pool. Sharing across identities makes
  connection cost unattributable.
- **Build the session buffer once per step**, not per retry: FR-11's re-send **MUST** reuse the same
  bytes — that is what makes it a test of idempotency rather than of the builder.
- **Percentiles from a histogram**, not from a slice of every sample: a long run must not grow
  unboundedly. Buckets in the low-millisecond range matter most; the manager's answers cluster there.
- **Counters are atomics read by the writer goroutine**; the CSV row is a snapshot, so a row may sit
  microseconds apart from another counter's increment. That is acceptable and **MUST** be stated in
  the report rather than fixed with a lock on the hot path.
- **Deterministic document generation** from a seed recorded in `meta`: two runs of the same scenario
  must send byte-identical payloads, or the comparison is not one.
- **`go vet ./...` clean** and `gofmt`-formatted; a `Makefile` target regenerates the FlatBuffers
  bindings and builds.

## Verifying the wire without a manager

The sender **SHOULD** ship two self-tests that need nothing running:

1. a CMAC vector test (fixed key, timestamp, method, target, body → expected hex), cross-checked
   against the Python reference;
2. a FlatBuffers round-trip test: build a session, parse it back with the generated bindings, assert
   the mode/option/payload and the document count.

Everything else needs a manager, and belongs to F9c-2's smoke and F9c-3's scenarios.
