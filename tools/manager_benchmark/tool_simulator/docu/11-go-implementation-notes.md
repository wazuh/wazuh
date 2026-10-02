# 11 — Go implementation notes

Guidance for F9c-2, kept in step with what was built (`go.mod`: Go 1.26.2). The retired simulator's
choices that still apply are kept deliberately, so the two tools read alike where they do the same
thing.

## Libraries

| Need | Choice | Why |
|---|---|---|
| CLI | stdlib `flag` | Same dashed-flag style as the retired sender; no dependency for a dozen knobs |
| HTTP client | stdlib `net/http` | HTTPS to 1517 with the default transport, and a custom `DialContext` for the Unix socket; per-agent client for identity isolation |
| TLS | stdlib `crypto/tls` with `InsecureSkipVerify` | Test managers are self-signed; no client certificate is required |
| `wazuh-agent+jwt` bearer | stdlib `crypto/hmac` + `crypto/sha256` + `encoding/json` + `encoding/base64` (`RawURLEncoding`) | No JWT library: the profile is six fixed claims and HS256, and a library's tolerance is exactly what the manager rejects. **MUST** reproduce the frozen vector in `internal/wire/testdata/jwt_vectors.json` byte for byte (shared with the manager's C++ library and the Python tools) |
| FlatBuffers | `github.com/google/flatbuffers/go` + `flatc --go` at build time | Bindings generated, never committed (see [05](05-flatbuffers-messages.md)) |
| Pacing | `golang.org/x/time/rate` | Leaky bucket, same as the retired sender |
| zstd | `github.com/klauspost/compress/zstd` | `Content-Encoding: zstd` request bodies (remoted's contract) and the `.json.zst` dump corpus. Pure Go: the no-cgo rule below rules out binding the repo's vendored C zstd |
| Goroutine groups | stdlib `sync.WaitGroup` + `context` | Fleet supervision; the first run-invalidating error is kept by a `sync.Once` and cancels the run's context (`runner.fatalf`) |
| `wazuh-enroll+jwt` bearer and the enrollment token | stdlib `crypto/hmac` + `crypto/sha256` (HKDF written out) | Same reasoning as the agent bearer; pinned by the `"enroll"` and `"enroll_token"` vectors in the same file |
| JSON | stdlib `encoding/json` | Control bodies are tiny; the session bodies are FlatBuffers |

**No cgo.** The tool must cross-build and run from a plain `go build`.

## Package layout

```text
tool_simulator/
├── cmd/benchmark_sender/main.go   # flags, scenario load, runner wiring, signals, exit code
├── internal/
│   ├── wire/        # legacy 1515 enrollment, enrollment-token decoding, bearer minting, global prefix, zstd, HTTPS and UDS transports
│   ├── control/     # startup / notify / shutdown: build, send, validate-and-discard
│   ├── scanvd/      # POST /scan/vd request and its answer classification
│   ├── cacerts/     # GET /cacerts request and its answer classification
│   ├── enrollhttps/ # POST /enroll with an enrollment-token bearer (bootstrap and measured step)
│   ├── fbbuild/     # scenario step -> Message{FullSession} bytes
│   ├── fb/          # GENERATED bindings (flatc --go); gitignored
│   ├── engine/      # H/E batch framing for POST /stateless (an engine-stream lane)
│   ├── scenario/    # lanes/fleets schema types, loader, strict validation
│   ├── source/      # deterministic document generation (count, size, checksum) and dump loading
│   ├── runner/      # fleet admission; per-agent keepalive loop + one goroutine per lane; drain
│   ├── metrics/     # counters + per-kind histograms, sliced by lane and fleet; bench.csv + summary JSON
│   ├── verdict/     # the optional `expected` block: validation and evaluation
│   └── pacing/      # shared request limiter + per-agent engine limiters
├── Makefile         # generate / build / vet / test / clean
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
- **Build the session buffer once per step**, not per retry: a bare-`503` re-send reuses the same
  bytes — that is what makes it a test of idempotency rather than of the builder. The exception is
  FR-11's feed-not-ready retry, which re-encodes so that `Start.feed_offset` is current (every other
  byte comes out identical, because generation is deterministic).
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

1. a JWT vector test (fixed key, agent id, `iat`, `jti` → the exact frozen token), the same vector
   the manager's C++ tests and the Python tools use;
2. a FlatBuffers round-trip test: build a session, parse it back with the generated bindings, assert
   the mode/option/payload and the document count.

Both ship (`internal/wire/jwt_test.go`, `internal/fbbuild/session_test.go`), alongside unit tests
for the enrollment token, the global prefix, zstd, the HTTP client, pacing, the scenario loader,
document and dump generation, metrics snapshots, the verdict and the bootstrap. `make test` runs
them all (`go test ./...`); the FlatBuffers test needs `make generate` first. Everything else needs
a manager, and belongs to F9c-2's smoke and F9c-3's scenarios.
