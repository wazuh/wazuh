# indexer_client — process-wide client for the Wazuh indexer

## Purpose

`indexer_client` is the shared library that replaced the v1 connector library (removed in 5.x). It is built to serve the four
consumers of the indexer, one consumer at a time, with:

- one **runtime per process**, owned by a single `RuntimeOwner`;
- **buckets** declared by each consumer (a queue with its own quota, retry, overflow, bulk and
  conflict policies);
- a **final result per operation** (`OpResult`) and a single failure classification (`Cause`);
- three-state node health (`Available`, `Throttled`, `Down`);
- a managed point in time (PIT) for queries;
- metrics exposed as a snapshot;
- typed configuration validated from one `IConfigSource`.

**Status.** The library is complete for its consumers (the Inventory Sync Server, the Vulnerability Scanner and the engine): write admission, buckets and DRR scheduling over an internal curl [Transport](#transport-internal) (HTTP, HTTPS, credentials), the [node health probe](#node-health), the [response classifier and retry lane](#response-classification-and-retry-lane) driven by the [bulk sender](#bulk-sender) with its [per-node load control](#load-control), the [client close and shutdown](#closing-and-shutdown), the [metrics snapshot and catalog](#metrics), the [edge-triggered logging](#log-lines), the per-operation conflict policy, `ReplacePreserving`, confirmable groups, [`ordered` buckets](#ordered-buckets), [`cancel(tag)`](#cancellation), the [queries](#queries) and the [managed point in time](#point-in-time). `requestClose()` closes admission and the queued writes keep draining until `awaitClosed(deadline)`, which then resolves the rest and stops callbacks from starting. See [Known limits](#known-limits).
The v1 connector library no longer exists in the tree; where this document says "the v1" it is that library, kept only as the
reference the tests and benchmarks were written against.

Strict C++17: the target requires `cxx_std_17` publicly and is pinned to 17, so consumers built
with a C++17 floor can include the headers. Only `INDEXER_CLIENT_API` symbols are exported
(`-fvisibility=hidden`, `ASIO_DISABLE_VISIBILITY`, `--exclude-libs,ALL`); no public header names
asio or curl.

## Public API

Headers are in `include/indexer_client/`; `indexerClient.hpp` is the umbrella.

| Header | Type | One line |
|---|---|---|
| `types.hpp` | `Duration`, `TimePoint`, `Deadline` | Milliseconds, steady-clock instant, absolute wait limit |
| | `Unit` | Empty value for operations that only succeed or fail |
| | `ProcessId` | `Analysisd`, `Modulesd`, `Standalone`; selects the internal-options prefix |
| | `Status`, `Cause`, `ItemOutcome` | Final status (`Ok`/`Failed`/`Dropped`), single failure classification, per-item write outcome |
| | `toString(Cause)` | Stable lowercase name for logs, metrics labels and tests |
| | `Outcome<T>` | Value or failure: `cause`, `httpStatus`, `reason`, `responseTooLarge` (queries: the failure is the [response cap](#response-cap)); `ok()` is `cause == Cause::None` |
| | `OpResult` | Final result of one write; `itemErrorType` truncated to 64 B, `reason` to 512 B |
| | `RetryPolicy`, `Overflow`, `BulkThresholds`, `ConflictPolicy`, `WriteMode` | Per-bucket / per-query policies |
| | `Op`, `Callback` | One write (`Index`, `IndexAutoId`, `IndexDataStream`, `Delete`, `IndexVersionedScript`); completion callback that runs on the CPU pool |
| | `BucketSpec` | A consumer-declared queue: name, weight, quota, retry, overflow, bulk, conflict policy, `ordered`, `onAmbiguous5xx`, `trustedBodies` (default `false`: the producer guarantees compact JSON without a raw `\n`, so the per-op `\n` search is skipped; a stray `\n` is then not caught locally: it fails that whole bulk with 400, or, when what follows it is a valid action line, injects an operation, the batch is requeued and every retry runs it again and duplicates each `IndexAutoId` and each `IndexDataStream` without an `id` of the batch; only for producers that guarantee compact JSON, see [Encoding per kind](#encoding-per-kind)) |
| | `AmbiguousPolicy` | `Retry` (default) or `Fail`: what a bucket does with a `_bulk` answered 500, 502 or 504, or whose response went over `max_response_bytes` (see [Ambiguous 5xx](#ambiguous-5xx)) |
| | `Slice`, `CursorQuery`, `PitOptions`, `DbqOptions`, `QueryOptions`, `PitPage` | Query and PIT parameters and page |
| | `HealthView` | `nodes[]` (`url`, `state`, `reason`), `clusterRed`, `localFault`, `anyAvailable()`, `anyUsable()`; returned by `Client::health()` (see [Node health](#node-health)) |
| | `CloseReport` | Close accounting |
| `metrics.hpp` | `MetricsSnapshot`, `ClientMetrics`, `BucketMetrics`, `NodeMetrics`, `QueryMetrics`, `PitMetrics`, `LatencyHistogram` | Typed snapshots of `RuntimeRef::snapshot()` and `Client::metrics()` (see [Metrics](#metrics)) |
| | `RejectCause`, `DropCause`, `FailCause`, `RetryCause`, `toString(...)` | The closed per-cause sets |
| | `MetricKind`, `forEachMetric`, `sanitizeMetricName` | The catalog of canonical names |
| `iConfigSource.hpp` | `IConfigSource` | The only way configuration and credentials reach the library |
| `types.hpp` | `Credentials` | Indexer `user` and `password`; no `operator<<` |
| `keyValueConfigSource.hpp` | `KeyValueConfigSource` | `IConfigSource` over `key=value` text plus an `<indexer>` JSON string |
| `runtimeConfig.hpp` | `SslConfig`, `RuntimeConfig` | Typed, validated configuration; `prefixFor()` and `from()` |
| `runtime.hpp` | `LogFunction`, `setLogFunction` | Log sink of the library; valid only while no runtime runs (see [Logging](#logging)) |
| | `RuntimeOwner` | Single owner of the process runtime: `start`, `beginShutdown`, `shutdown`, `running` |
| | `RuntimeRef` | Non-owning reference: `client()`, `snapshot()`, `shutdownDeadline()`, `valid()` |
| | `detail::testing::*` | Test seams: `postToPool`, `postToIoLoop`, `onRuntimeThread`, `usageErrors` |
| `client.hpp` | `Client` | A consumer's handle on the runtime; implements `IClient` |
| | `IClient`, `IWriter`, `IQuery` | Abstract interfaces for consumers' mocks |
| | `Ticket`, `GroupTicket`, `CancelTicket` | Handles on a pending write, a group of writes and a cancel; `ready()` and `wait(Deadline)` |
| | `Submit` | Result of `submit`: `accepted`, `cause`, `reason` (why it was refused; `InvalidArgument` names the field first), `ticket` |
| | `Posted` | Result of `post`: `accepted`, `cause`, `reason`; no ticket |
| | `Group` | Confirmable group of writes: `add(Op)` reserves its quota at once, `commit()` enqueues all together; dropped without commit it releases its reservation; `lastAddReason()` (see [Groups](#groups)) |
| | `Pit`, `PitSession` | Shared PIT handle (`cursor`, `search`, `generation`) and its cursors (`next`, `exhausted`); see [Point in time](#point-in-time) |

**Write handles.** `Writer::submit` validates, encodes, charges and queues the operation (see
[Write path](#write-path)); a refusal carries its `reason` (`InvalidArgument` names the field first, as the internal
reason of `encode` does; `QueueFull`, `PayloadTooLarge` and the rest carry their own). `Writer::post(Op)` is `submit` for a
producer that never waits on a result (the engine): the same validation, admission, overflow policy and `Reentrancy`, but no
`Ticket` and no callback, so it answers only `Posted{accepted, cause, reason}`. An accepted `post` has no per-operation result for
its producer: its outcome is counted only in the bucket's snapshot and in the `CloseReport`, and in a `DropNewest` or `DropOldest`
bucket it may still end `Dropped(QueueFull)` (dropped at once, or evicted later by a newer operation) without the producer knowing. `Writer::group()` returns a real
[`Group`](#groups). `Writer::cancel(tag)` returns a [`CancelTicket`](#cancellation). `Client::writer(bucket)` returns the writer bound to that bucket of
the client; once the runtime is gone it returns a stub writer, which answers `Unavailable`.

`CloseReport` (from `Client::awaitClosed`); the fields are described in [Closing and shutdown](#closing-and-shutdown):

| Field | Meaning |
|---|---|
| `callbacksInFlight` | Callbacks of this client started and not finished when `awaitClosed` returned |
| `droppedClientClosed` | Operations of this client resolved `Dropped(ClientClosed)` |
| `droppedShutdown` | Operations of this client resolved `Dropped(Shutdown)` |
| `callbacksSkipped` | Completions past the callback cutoff: the `Ticket` is complete and the callback was not called |
| `callbackOverruns` | Callbacks that took longer than `callback_budget_ms` |
| `drained` | Operations resolved after `requestClose()` that are not `Dropped(ClientClosed)` or `Dropped(Shutdown)`: the drain's own results |

Operations dropped by an overflow policy (`Dropped(QueueFull)`) have no field of their own; they are in the per-bucket counters (one
resolved after `requestClose()`, an eviction racing the close, counts in `drained`).

Mocks of the interfaces (`tests/mocks/mockIndexerClient.hpp`) and an in-process fake indexer
(`tests/fake/fakeIndexer.hpp`) are test helpers, not part of the installed API.

## Lifecycle

One runtime per process, created and destroyed by the **owner thread**: the thread that calls
`RuntimeOwner::start()`.

```text
RuntimeOwner::start(process, source)      owner thread, before the first consumer
  -> RuntimeRef                           non-owning, valid until shutdown()
RuntimeRef::client(consumer, buckets)     -> shared_ptr<Client>
  ...
RuntimeOwner::beginShutdown(deadline)     owner thread, once
Client::requestClose() / awaitClosed()    each consumer
RuntimeOwner::shutdown()                  owner thread, joins every runtime thread
```

- **`start`** validates the configuration, creates K network threads and M CPU threads, and
  restores the calling thread's signal mask afterwards. A second `start()` while running returns
  `Cause::InvalidState` and leaves the running runtime intact. An invalid configuration fails with
  `Cause::InvalidConfig` and leaves no thread behind.
- **Signals blocked.** Runtime threads are created with every asynchronous signal blocked
  (`pthread_sigmask` around thread creation), so a signal sent to the process never interrupts an
  I/O loop or a pool thread. The owner operations must run on a normal thread, never inside a
  signal handler: the handler only sets a flag and wakes the owner thread.
- **Owner thread.** While a runtime is running, `start`, `beginShutdown` and `shutdown` called from
  any thread other than its owner return `Cause::UsageError`. While no runtime is running, any
  (non-runtime) thread may call `start()` and becomes the owner of the new runtime. From a runtime
  thread the three always return `Cause::UsageError`.
- **`beginShutdown(deadline)`** fixes the single shutdown deadline. Later calls are ignored: the
  first deadline wins. Consumers read it through `RuntimeRef::shutdownDeadline()`.
- **`shutdown()`** joins every runtime thread. A second call is a no-op (`Cause::None`). Taking a
  `RuntimeRef` from a previous runtime does not make it valid again after a restart.
- **Exit without `shutdown()`.** A runtime that never went through `shutdown()` is joined during
  static destruction, at `exit()`. A thread blocked
  in I/O or in a long callback can hang that `exit()`: the owner must call `shutdown()` before the
  process exits.
  Measured for a fatal `exit()` from any thread with a `Client` held in a static and a `_bulk` the
  indexer never answers: the process does not hang, but `~Client` first waits for its
  drain, `drain_ms − 2·callback_budget_ms` (about 9.6 s with the defaults), then the leftover
  transfer is cancelled and the runtime threads are joined in milliseconds. Each such static client
  adds its own wait.
- **`requestClose()` / `awaitClosed(deadline)`.** `Client::requestClose()` never blocks and is
  valid from any thread; it closes admission and the queued writes keep draining. `Client::awaitClosed()` blocks and is for consumer
  threads only: it waits for the drain up to `deadline`, resolves what is left and returns a `CloseReport` (see
  [Closing and shutdown](#closing-and-shutdown)). The `Client` destructor is `requestClose()` plus `awaitClosed()` with the
  shutdown deadline (or the default). After `requestClose()`, `writer()` and `query()` return `nullptr`: a closing client
  hands out no new handles. Destroying a `Client` from a runtime thread is a usage error: it is
  logged to stderr, counted (`detail::testing::usageErrors()`) and turned into a non-blocking
  `requestClose()` plus an immediate sweep; it never aborts, not even in debug builds. That path does not release the consumer
  name (only `awaitClosed()` does, or the client state's own destruction), so the name stays taken until the state dies.
- **Internal errors never abort.** The manager's Release flags (`-O3 -s`, `src/CMakeLists.txt`) do not define
  `NDEBUG`, so an `assert` would abort the packaged manager: the library has none. A broken internal invariant is logged at ERROR
  (`internal error (please report it): ...`), counted (`testing_hooks::internalErrors()`, test build only) and followed by its
  recovery: `encode()` finds the precomputed size of an operation's lines different from the encoded bytes → the operation is
  refused `InvalidState` (`internal error: ...`) before it is charged (counted with the bucket's `InvalidArgument` refusals);
  a `Bucket` destroyed with operations still queued → it completes them (a ticket or group slot gets `Dropped(ClientClosed)`,
  the callback is not called), returns their charge and also counts a usage error; an operation resolved through a bucket other
  than its own (`OpState::owner`, `WritePath::resolve` and `Bucket::settleBulk`) → the resolution goes on with the caller's
  bucket. The component cases `WriteInternalErrorTest.*` break each invariant on purpose (the seam `encodeSizeSkew`, a bucket
  built directly).
- **Reentrancy.** Every wait in the library (`Ticket::wait`, `GroupTicket::wait`,
  `CancelTicket::wait`, `PitSession::next`, blocking queries, `awaitClosed`) is the library's own
  and returns `Cause::Reentrancy` when called from a runtime thread. From a callback a consumer
  may only request (a non-blocking `submit`, `requestClose()`), never wait; that includes a `Group::add` in `Block` that would
  have to wait and `GroupTicket::wait`.
  `detail::testing::onRuntimeThread()` exposes the flag this relies on.

## Configuration

The library **never opens a file**. All configuration arrives through `IConfigSource`:

| Method | Returns |
|---|---|
| `raw(key)` | Raw value of an internal option, or `nullopt` when unset |
| `keysWithPrefix(prefix)` | Every key of the source that starts with `prefix` (including the ones `problem()` reports); used to reject unknown keys |
| `problem(key)` | Why a present key is unusable (malformed line, empty value), or `nullopt`; defaults to `nullopt` |
| `indexerSectionJson()` | The `<indexer>` section as canonical JSON |
| `credentials()` | The indexer `Credentials{user, password}` (pure virtual; see [Credentials](#tls-and-credentials)) |

`KeyValueConfigSource::parse(text, indexerSectionJson, Credentials)` is the stock implementation (the `Credentials` are returned as is by `credentials()`): `key=value`
lines, judged **per key** like wazuh's C internal-options reader (`_read_file` in
`src/shared/src/validate_op.c`): outside the process prefix nothing is judged. Under the prefix it is
**stricter than C**: a malformed line is fatal wherever it appears (C logs `FGETS_ERROR` and skips it)
and values are strict unsigned decimals (C uses `atoi`).

- a line that is empty or starts with `#`, a **space** or a **tab** is a comment (an indented line is
  never a key; the C reader never matches a tab-indented line either);
- the **first** occurrence of a key wins; later duplicates are not read (nor validated). This also
  holds for an empty value (`k=1` then `k=` → 1; `k=` then `k=2` → problem, both as in C); a line
  without `=` has the whole line as its key, so it never collides with a real key;
- parsing never fails on a line. A non-comment line without `=` (its key is the whole trimmed line)
  or with an empty value (`key=`) is **recorded** against its key, with its line number, and
  `problem(key)` returns that text. A line with an empty key (`= 5`) can match no key and is skipped.
- `RuntimeConfig::from()` fails with `Cause::InvalidConfig` and that text **only** when the recorded
  key is under the process prefix. A broken line of another daemon (`remoted.foo`, or the other
  process's `indexer_client_*` family) is ignored, as the C reader ignores it for every key it
  does not match.

The caller reads the file; the class only parses text. In the manager build there is one
internal-options file: modulesd passes exactly `/etc/wazuh-manager/wazuh-manager-internal-options.conf`
(`WAZUH_LDEFINES`, `src/shared/include/defs.h`). The defaults are `kSchema`'s, the same model the C
side uses with `getDefine_Int_default()`: there is no default file to concatenate. The engine is
expected to wrap its own `conf` in its own `IConfigSource`.

`RuntimeConfig::from(process, source)` builds the typed configuration. Unknown keys under the
prefix, keys under the prefix that `problem()` reports, non-decimal values, out-of-range values,
`uint64` overflow and an invalid `<indexer>` JSON are all `Cause::InvalidConfig`, with the
offending key in `reason`. Values are strict unsigned
decimal integers (surrounding blanks allowed).

**`<indexer>` section.** `indexerSectionJson()` must return exactly the `indexer` section of
`wazuh-manager.conf` as `manager_config`'s `sectionJson("indexer")` produces it: an object with
`hosts` and, optionally, `ssl`; any other member is rejected. The engine builds it from its
`<indexer>` section (manager) or from `wiconnector::Config::toJson()` (standalone), which emit
exactly those two members.

| Path | Type | Rule |
|---|---|---|
| `hosts` | array of strings | Required, at least one entry, each non-empty |
| `ssl.certificate_authorities` | array of strings | Optional, entries non-empty |
| `ssl.certificate` | string | Optional |
| `ssl.key` | string | Optional |
| `ssl.verify_certificates` | boolean | Optional, default `true` (also when absent); see [TLS](#tls-and-credentials) |

**Internal options.** Full key = prefix + name. The prefix is `analysisd.indexer_client_` for
`ProcessId::Analysisd` and `ProcessId::Standalone`, and `wazuh_modules.indexer_client_` for
`ProcessId::Modulesd`. The table is the `kSchema` of `src/config/runtimeConfig.cpp` (the single
source; every minimum is 1 except `log_summary_interval_ms`, whose minimum is 1000; bounds are inclusive):

| Name (after the prefix) | Type | Unit | Range | Default |
|---|---|---|---|---|
| `network_threads` | unsigned integer | count | 1 – 64 | 1 |
| `cpu_threads` | unsigned integer | count | 1 – 64 | 2 |
| `global_quota_bytes` | unsigned integer | bytes | 1 – 68719476736 (64 GiB) | 268435456 (256 MiB) |
| `max_response_bytes` | unsigned integer | bytes | 1 – 1073741824 (1 GiB) | 67108864 (64 MiB) |
| `drr_quantum_bytes` | unsigned integer | bytes | 1 – 67108864 (64 MiB) | 1048576 (1 MiB) |
| `request_timeout_ms` | unsigned integer | ms | 1 – 3600000 (1 h) | 60000 |
| `probe_timeout_ms` | unsigned integer | ms | 1 – 300000 (5 min) | 5000 |
| `probe_interval_ms` | unsigned integer | ms | 1 – 3600000 (1 h) | 10000 |
| `drain_ms` | unsigned integer | ms | 1 – 600000 (10 min) | 10000 |
| `ambiguous_retry_window_ms` | unsigned integer | ms | 1 – 3600000 (1 h) | 30000 |
| `latency_target_ms` | unsigned integer | ms | 1 – 600000 (10 min) | 2000 |
| `pace_initial_ms` | unsigned integer | ms | 1 – 60000 (1 min) | 100 |
| `pace_relax_after` | unsigned integer | count | 1 – 1000000 | 20 |
| `retry_after_max_ms` | unsigned integer | ms | 1 – 3600000 (1 h) | 60000 |
| `callback_budget_ms` | unsigned integer | ms | 1 – 60000 (1 min) | 200 |
| `max_open_pits` | unsigned integer | count | 1 – 10000 | 64 |
| `node_window_max` | unsigned integer | count | 1 – 64 | 4 |
| `bulk_min_bytes` | unsigned integer | bytes | 1 – 33554432 (32 MiB) | 65536 (64 KiB) |
| `log_summary_interval_ms` | unsigned integer | ms | 1000 – 3600000 (1 h) | 60000 |

A change to `kSchema` must change this table, the `RuntimeConfig` initializers (checked by the
`DefaultsWhenUnset` test) and the tests together. The operator-facing page is
[`docs/ref/modules/indexer_client/`](../../../docs/ref/modules/indexer_client/README.md) (`README.md`, `configuration.md`,
`metrics.md`); a change here that an operator can see must update it.

## Threads

Per process, the runtime owns **K + M** threads, fixed by configuration:

| Threads | Count | Role |
|---|---|---|
| Network | K = `network_threads` | One I/O loop each (asio `io_context`) |
| CPU | M = `cpu_threads` | CPU pool; completion callbacks run here |

No consumer, bucket or `Client` creates threads. The network threads run the transport's curl
loops and the CPU pool runs its result callbacks; the test seams (`detail::testing::postToPool`,
`postToIoLoop`) still accept test tasks. `MetricsSnapshot` reports `networkThreads`, `cpuThreads` and
`clients`. curl's own DNS resolver threads are auxiliary threads outside K + M; the transport sets
`CURLMOPT_QUICK_EXIT` so they never block shutdown.

## Transport (internal)

`detail::Transport` (`src/transport/transport.hpp`) is the HTTP layer the probe, the bulk
path and the queries build on. It is **not public API**: no installed header names it and
neither asio nor curl types appear in it. `RuntimeOwner::start` creates it after the runtime threads
exist; internal users reach it through `detail::runtimeTransport()`, a weak view that never keeps
the runtime alive. The normative contract is the transport contract of the Indexer Client plan (outside the repository).

- **Loops.** Each of the K network threads runs one libcurl multi on its `io_context`
  (`src/transport/curlLoop.cpp`). Under the admission mutex a request goes to the loop with the
  fewest admitted-and-unresolved transfers, ties broken round-robin (`pickLoop`,
  `src/transport/transport.cpp:220`).
- **Admission.** `submit(HttpRequest, ResultCallback)` is synchronous and returns
  `Admission{admitted, cause, id}`. `id` is monotonic per runtime and never reused. Only `GET`,
  `HEAD`, `POST`, `PUT`, `DELETE` and the schemes `http` and `https` are admitted (`https` with or without a configured CA: the trust anchor is the policy of [TLS](#tls-and-credentials));
  anything else, or a stopped transport, is not admitted (`InvalidArgument` / `Shutdown`) and the
  callback never runs. The `id` is registered before the post to the loop, so `stop()` resolves it
  even if the post never arrived.
- **One result per admitted request.** The callback runs exactly once, on a CPU-pool thread
  (`ic-cpu-*`), never on a network thread. The first event that touches a transfer (completion,
  `cancel`, `stop`) wins.
- **`cancel(id)`** never blocks and is valid from any thread, runtime threads included. An unknown
  or already resolved `id` returns `false`, and so does an `id` whose loop has already closed (a stop
  is in progress and delivers `Shutdown`). Otherwise it posts to the owning loop, which removes the
  easy handle from the multi before resolving with `Cancelled`. No post captures `this`; a post to a
  closed loop is refused and counted. Descriptors curl opens itself (the multi's wake-up pair) are
  only released, never closed, and are assumed long-lived: they are tracked by number, so a curl or
  c-ares change that reports a per-resolve socket closed before its `CURL_POLL_REMOVE` would need a
  close-before-remove guard (checked against curl 8.20: `lib/multi.c:1139-1143`).
- **`stop(deadline)`** is idempotent and safe to call concurrently; it always joins and returns
  `true` when everything finished within `deadline` (a measured objective, not a cut-off). Order:
  (1) close admission; (2) remove every transfer from its multi and resolve it as `Shutdown`;
  (3) `curl_multi_cleanup` on each loop's own thread, with `CURLMOPT_QUICK_EXIT` so the resolver
  threads are not joined; (4) the runtime joins the loops and drains the CPU pool. Only
  `RuntimeOwner::shutdown` and the destructor of the runtime state call it.
- **Classification.** The transport classifies and never retries (`src/transport/classify.cpp`):

| curl code | `TransportCause` | `nodeAttributable` |
|---|---|---|
| none (an HTTP response arrived, any status) | `None` | no |
| 28 | `Timeout` | yes |
| 6, 7 | `Connect` | yes |
| 55 | `SendError` | yes |
| 56, 52, 61 (undecodable gzip body) | `RecvError` | yes |
| 18 | `PartialResponse` | yes |
| 23 with the response cap tripped | `ResponseTooLarge` | no |
| 2, 27, a `curl_multi_socket_action` error, 23 without the cap flag, any other | `LocalError` | no |
| `cancel` won the race | `Cancelled` | no |
| resolved by `stop` | `Shutdown` | no |

- **`mayHaveSent`** is set when `CURLOPT_PREREQFUNCTION` ran: the connection was ready and the
  request was about to be written. It is conservative (true against a server that accepts and stays
  silent) and is reset on every use of an easy handle. `HttpResult.uploadedBytes` carries
  `CURLINFO_SIZE_UPLOAD_T`.
- **`freshConnection`** (`HttpRequest`, off by default) sets `CURLOPT_FRESH_CONNECT`: the request goes on a new
  connection, never a pooled one. libcurl resends a request by itself, inside the same submission and on a fresh
  connection, when its **reused** keep-alive connection died before any response byte (or with a send error), even if
  the whole request had been written (`Curl_retry_request`, curl 8.20 `lib/transfer.c`, which requires
  `conn->bits.reuse`; its other branch, a refused HTTP/2 stream, is not built). The caller never sees that resend, so
  no attempt limit counts it. A request on a fresh connection is never resent that way: it leaves at most once, at the
  cost of one TCP/TLS handshake. The connection then joins the pool like any other (no `CURLOPT_FORBID_REUSE`: the next
  such request opens its own). Only the query engine sets it, for a single-attempt delete- or update-by-query
  ([One attempt](#one-attempt)); reads, the bulk path and the probe keep connection reuse.
- **Response cap.** `max_response_bytes` is enforced only in the write callback
  (`writeCb` in `curlLoop.cpp`), which sets the cap flag and fails the transfer; `HttpResult.body` is never
  larger than the cap. `CURLOPT_MAXFILESIZE_LARGE` is not used. The transport sets
  `CURLOPT_ACCEPT_ENCODING "gzip"` (gzip only; `configure` in `curlLoop.cpp`); curl decompresses before the write callback, so
  `max_response_bytes` counts **decompressed** bytes (a gzip bomb yields `ResponseTooLarge`) and a corrupt gzip body (curl 61) is a
  `RecvError`, attributable to the node. Measured against OpenSearch 3.6.0: bulk errors 363 594 to 13 217 B, a page of 1 000 hits
  200 722 to 11 744 B.
- **`Retry-After`** is parsed byte by byte (`src/transport/retryAfter.cpp`): no locale, no
  `strptime`/`mktime`, so neither the global locale nor `TZ` changes the result. The value is
  capped at `retry_after_max_ms` and parsed on the CPU pool.
- **Fixed options.** Per easy: `CURLOPT_PROTOCOLS_STR "http,https"`, `CURLOPT_NOSIGNAL`,
  `CURLOPT_PROXY ""` (never a proxy from the environment); `Expect` is left to curl (100-continue on bodies over 1 MiB,
  as the v1). Per multi:
  `CURLMOPT_MAX_HOST_CONNECTIONS` = 8 (a constant; the sender's window is the [limiter's](#load-control)),
  `CURLMOPT_MAXCONNECTS` = configured hosts x 8 (curl's default pool, 4 x the transfers running, closed connections
  after every burst and the next burst reconnected; it caps idle connections, not transfers) and
  `CURLMOPT_QUICK_EXIT`. `curl_global_init` runs once (`std::call_once`).
- **Timings.** `HttpResult.timings` (`TransferTimings`: `total`, `connect`, `appConnect`) is in
  **microseconds**, and is also filled for `Cancelled` and `Shutdown` results. `appConnect` is 0 in clear text.
- **TLS and credentials** are described in [TLS and credentials](#tls-and-credentials); they add `Tls`
  and `TlsConfig` to `TransportCause`.

### TLS and credentials

**TLS material.** `RuntimeOwner::start` calls `loadTlsMaterial` (`src/transport/tlsMaterial.cpp`)
before creating any thread, and does so **whenever the material is configured, whatever the hosts'
scheme**: a typo in a path fails at start, not on the day `https` is used. A failure is
`Cause::InvalidConfig`, names the path or the host, and creates no thread. What is required:

- every host is `http` or `https` (case-insensitive);
- every file is at most **1 MiB**;
- every file in `ssl.certificate_authorities` exists, parses the way curl parses `CAINFO_BLOB`
  (`PEM_X509_INFO_read_bio` over the whole file: a malformed PEM block anywhere fails) and holds at
  least one certificate. The files are concatenated, so a later CA is as valid as the first; the
  concatenation is parsed again and must stay below curl's blob limit (8 000 000 bytes);
- `ssl.certificate` and `ssl.key` come **together or not at all**; `""` counts as absent (the
  manager's config fills defaults). The certificate file is the leaf plus optional intermediates,
  parsed the way curl parses `SSLCERT_BLOB` (the leaf, then only PEM certificates up to the end), and
  is sent whole; the key must be PEM, **unencrypted**, and match the **first** certificate.

Because the validation uses curl's own OpenSSL primitives, 58 and 77 cannot come from the content of
the files any more (a file changed on disk after start does not matter: the material is in memory).

How it reaches curl: relative paths resolve against the process's working directory (the manager
runs with cwd = home); the files are read once into memory (`TlsMaterial`, held by the transport) and
passed as `CAINFO_BLOB`, `SSLCERT_BLOB` and `SSLKEY_BLOB` with `CURL_BLOB_NOCOPY`, so no temporary file
and no CA directory (`CAPATH` is null). The minimum protocol is TLS 1.2. The material is read only at
start: **rotating a CA, certificate or key requires a restart**.

**Verification policy (`ssl.verify_certificates`).** `loadTlsMaterial` also decides what curl
verifies, with the v1's behaviour (http-request's `urlRequest.hpp`) so that an update from 5.0 keeps
connecting:

| `verify_certificates` | CA configured | Trust anchor (curl) | `VERIFYPEER` / `VERIFYHOST` | Log at start |
|---|---|---|---|---|
| `true` (default) | yes | `CAINFO_BLOB` | 1 / 2 | — |
| `true` | no, a system store exists | `CAINFO` = the first **existing** of `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/usr/share/ssl/certs/ca-bundle.crt`, `/usr/local/share/certs/ca-root-nss.crt`, `/etc/ssl/cert.pem` | 1 / 2 | INFO `indexer TLS: using the system CA store <path>` |
| `true` | no, and none of the five exists | `CAINFO` null (explicitly: never curl's compiled-in bundle) | 0 / 2 (the host name is still checked) | WARN `indexer TLS: no CA configured and no system CA store found (<paths>); the server certificate is not verified (the host name is) for https host(s) <hosts>; the indexer credentials are sent to an unverified server` |
| `false` | either | the configured CA, else null | 0 / 0 | WARN `indexer TLS: certificate and host name verification disabled (verify_certificates is false) for https host(s) <hosts>; the indexer credentials are sent to an unverified server` |

- The system store is only **located** at start, never read: curl loads it by path (no 1 MiB cap and
  no strict PEM check). "Exists" is `std::filesystem::status`: only "not found" and "not a directory"
  mean absent; any other error (permission, symlink loop...) picks that path, so the handshake fails
  instead of switching verification off. The first existing path wins whatever it holds: a broken
  store fails every handshake (77/60) and the next path is never tried.
- A configured CA always wins, and a malformed one is `InvalidConfig` whatever `verify_certificates`
  says: with `false` the CA and the client pair are still loaded and validated.
- The INFO and the WARN are logged once per start, and only when some host is `https`.
- Tests replace the list of paths through the `systemCaPaths()` seam (`src/transport/seams.hpp`, not in
  the `.so`).

**TLS causes.** Added to the classification table:

| curl code | `TransportCause` | `nodeAttributable` | Meaning |
|---|---|---|---|
| 35 (handshake), 60 (verification: CA, hostname), 98 (the node wants a client certificate) | `Tls` | yes | A fault of the node or of what it presents |
| 58 (our certificate or pair), 77 (our CA bundle) | `TlsConfig` | no | curl rejected bytes our validation accepted: local |
| 53, 54, 59, 66, 82, 83, 90, 91 | `TlsConfig` | no | Listed for completeness; unreachable with our options (no `SSLENGINE`, cipher list, `CRLFILE`, `ISSUERCERT`, pinned public key nor `VERIFYSTATUS`) |
| 43 | `LocalError` | no | Stays generic |

**Credentials.** `IConfigSource::credentials()` returns the `Credentials`; the process
reads them from its own keystore, the library never does. They are **mandatory, also with `http`**:
`start` copies them and fails with `InvalidConfig` (before any thread) when the user or the password
is empty or `credentials()` throws. They travel on every request as `CURLOPT_USERNAME` and
`CURLOPT_PASSWORD` (never `USERPWD`, so a `:` in the password arrives intact) and survive the
destruction of the source. They never appear in a `reason`, a log or `stats()`. Wiping memory is
**best effort**: the transport calls `OPENSSL_cleanse` over its own copies of the password and the
key when it is destroyed (also when its construction fails), `TlsMaterial` wipes the key whenever it
dies and `KeyValueConfigSource` wipes its password copy in its destructor, but curl and OpenSSL keep
copies of their own that the library cannot reach, the `Credentials` returned by `credentials()` are
the caller's, and a moved-from string may keep stale bytes; do not rely on it as a guarantee.

## Node health

The runtime knows at every moment which indexer nodes it can use. Each node is in one of three states
(`HealthView::NodeState`): `Available`, `Throttled` (the node answered 429) or `Down`. In `view()` every node starts `Down`
until the first probe round says otherwise. The state lives in an internal `NodeSet` (`src/health/nodeSet.{hpp,cpp}`) fed by the
`Prober` (`src/health/prober.{hpp,cpp}`) and, later, by the data path.

**The probe.** The `Prober` sends one `GET {host}/_cluster/health/wazuh-*,.wazuh-*` per configured node through the
[Transport](#transport-internal), with `request.timeout` = `probe_timeout_ms`. The index expression
(`MANAGER_INDEX_PATTERN` in `src/health/prober.hpp`, not configurable) limits the answer to the indices the manager reads
(`.wazuh-*`) and writes (`wazuh-*`; a wildcard resolves a data stream to its backing indices): a red index the manager does
not use (an alerting or ISM index, a user's own) no longer marks every node `Down`, while a manager index that loses its
primary still does. It is not configurable because a pattern matching nothing answers `green` for an empty index list.
There is no `local=true`: the answer comes from the elected cluster manager, so a node cut off from the cluster fails its
probe instead of answering from its stale copy of the cluster state. It works in **rounds**:

- the first round is armed when the runtime starts (no wait for the interval), then one round every `probe_interval_ms`;
- a round is complete when every node has produced exactly one result; the `NodeSet` applies the whole round at once, under
  its mutex;
- rounds never overlap: if the interval expires while the previous round is still in flight, that tick is skipped and counted
  (`ProberStats::roundsSkipped`);
- the timer is an asio `steady_timer` on network loop 0 and is only touched from that loop. **Only the probe returns a node to
  `Available`.**

**Probe result table** (`classify()` in `src/health/nodeSet.cpp`; `Node.reason` holds the text for `Down`):

| Result | State | Reason / effect |
|---|---|---|
| 2xx, body JSON with string `status` `green` or `yellow` | Available | |
| 2xx, `status` `red` (some manager index lost a primary) | Down, **every** node | The round is red: `clusterRed` is set, every node's reason is `cluster health is red (reported by '<host>')` (a node already Down by its own result keeps its own reason) and no node returns to Available while a round holds `red` |
| 2xx, `status` missing, not a string, any other value, or body not JSON | Down | `invalid _cluster/health body` |
| 429 | Throttled | `error.durability` or `error.root_cause[0].durability` equal to `PERMANENT` marks the answer as a permanent breaker; anything else, or an unreadable body, is transient. A node whose own probe answers a permanent breaker on **3 consecutive rounds** gets one WARN (see [Logging](#logging)); any other answer ends the streak, and a passive 429 (a bulk or a query) never counts. One trip is not enough: OpenSearch labels a parent-breaker trip `PERMANENT` whenever fielddata outweighs the transient children, and the forced GC that could free the garbage runs at most once every 5 s |
| 401, 403 | Down | `HTTP <status>: check indexer credentials / permissions` |
| any other HTTP status | Down | `HTTP <status>` |
| transport cause with `nodeAttributable` (`Timeout`, `Connect`, `SendError`, `RecvError`, `PartialResponse`, `Tls`) | Down | `<cause> (curl <code>)` |
| `TlsConfig`, `LocalError`, `ResponseTooLarge` | Down **and** `localFault` | `<cause> (curl <code>)`; a probe the transport did not admit reports `probe not admitted: <cause>` |
| `Cancelled`, `Shutdown` | ignored | The whole round is discarded: no transition, no log |

`localFault` is set while the last complete round had a local result (the runtime, not the node, is at fault) and is cleared by
the first complete round without one.

**Passive signals.** `NodeSet::report(index, HttpResult)` is for the data path (the [bulk sender](#bulk-sender) calls it on a failover and on a 429; the queries and the PIT registry call it too). It applies at once,
outside the rounds, and can only degrade: a node-attributable failure sets `Down`; a 429 sets `Throttled` from `Available`. A
passive success never promotes. A 429 that carries a `Retry-After` also **parks** the node, see below.

**Selector.** `NodeSet::choose()` is round-robin among the `Available` nodes; a `Throttled` node is chosen only when none is
`Available`; it returns nothing when every node is `Down`. A **parked** node (see below) is skipped in both passes. `choose(allowed)` applies the same order among the nodes the filter
accepts; the filter runs under the `NodeSet` mutex (the bulk sender's takes its own, see [lock order](#bulk-sender)).

**Parking a node.** Every `Node` has a `notBefore`. A 429 that carries a `Retry-After`, from **any** path (bulk, query,
PIT, and the probe round's own result), raises it to `now + Retry-After` with a `max`: it is only ever raised, never shortened, and the
value is already capped by `retry_after_max_ms`. The node's state does not matter (a `Down` node keeps the wait for when the probe brings it
back); the state transition of a 429 stays `Available` to `Throttled` only. While `notBefore > now` the node is parked: nothing is sent to it
by anybody.

- `NodeSet::choose` skips parked nodes before it runs the caller's filter.
- The [bulk sender](#bulk-sender) mirrors the `NodeSet`'s `notBefore` into its own slot (`refreshMirror`, `max` with the pacing state it
  already holds) and arms its `notBefore` timer, so `capacity()` is 0 while the node is parked and the timer wakes the scheduler when it ends:
  loop 0 neither spins nor loses the wake-up.
- A read (query or PIT creation) with **every not-`Down` node parked** waits for the first of them (`NodeSet::earliestNotBefore()`) within its
  own deadline, instead of ending `Unavailable`; the wait never passes the deadline. A node that is `Down` is not waited for.
- The PIT registry reschedules its timer to the same instant when a delete finds no node to choose.

**`HealthView`** (`Client::health()`, a copy taken under the mutex; empty when the runtime is gone):

| Member | Meaning |
|---|---|
| `nodes[]` | In the order of `hosts`: `url`, `state`, `reason` (why it is `Down`, empty otherwise) |
| `clusterRed` | The last complete round contained a `red` cluster; every node is `Down` |
| `localFault` | The local reason of the last complete round, when there is one |
| `anyAvailable()` | At least one node `Available`; the strict aggregate, for the vulnerability scanner |
| `anyUsable()` | At least one node not `Down`; the lenient aggregate, for inventory sync. It ignores parking: a parked node still counts |
| `noUsableAfterProbes()` | Why a call should not wait for a node: when every node has already been through a probe round (`Down` with a reason) and none is usable, the `url: reason` of each node in order, joined by `; `. `std::nullopt` with no node, with a usable one, or before the first probe round. Used by the engine's `wiconnector` and by the Content Manager's `contentIndexerClientAdapter` to fail a read fast with the same message as before |

**For the next stages.** `NodeSet` also exposes `generation()` (+1 per node transition), `transitions(index)` and
`onTransition(hook)`, called after each transition outside the mutex; `Prober::stats()` reports `rounds`, `roundsApplied`,
`roundsDiscarded`, `roundsSkipped`, `submitsRefused` and `resultsAfterStop`. They are internal.

**Stop order.** `RuntimeState::stopAndJoin` stops the [write path](#close-and-shutdown) first, then the prober, then the transport, then the loops, then the CPU pool.
`Prober::stop()` sets a flag, posts the timer cancellation to loop 0 and waits for it, so no round is armed and no probe is
submitted after it returns.

## Write path

`Writer::submit` validates and encodes the operation, charges its memory against the bucket's quota and the global cap, applies
the bucket's overflow policy when there is no room, and queues it. A DRR scheduler on network loop 0 forms batches from the
queues and hands them to an internal sink. The production sink is the [bulk sender](#bulk-sender). The code is in `src/write/` (`encoding`, `bucket`, `budget`, `scheduler`, `sink`,
`writer`, `response`, `sender`); none of it is public API. Counters are reachable only through `detail::writeStats()`.

### Encoding per kind

`encode(Op&&, const ConflictPolicy&, bool trustedBody = false, HeadTable* heads = nullptr)` (`src/write/encoding.hpp`, normative
for the details below) runs in `submit`, `post` and in `Group::add`, on the producer's thread, once; those pass the bucket's
`BucketSpec::trustedBodies` and the write path's `HeadTable`. The result is the operation's NDJSON lines (each ends in `\n`) as an
`Encoded{head, cachedHead, body}`: on the wire the operation is `headView()` + `body` + `\n` (the `\n` only with a
body; `appendWire`), `wire()` is its exact size on the wire, and a retry re-sends them without re-encoding. `headView()` is the
cached head when there is one, else `head`; the wire size, the charge, the batch builder and the sender all read the head through
it.

- `Index` (`Replace`): `head` is the action line with its `\n`, built with an exact `reserve`; `body` is `op.body` itself, moved
  in with its buffer: the document is never copied nor re-reserved on the producer's thread.
- `IndexAutoId`, and `IndexDataStream` without an `id`: `body` as above; the action line depends only on kind and index, so it is **shared**
  (`cachedHead`, a plain pointer to a line of the write path's `HeadTable`; `head` stays empty). The table is append-only, holds at most 256 lines in fixed slots and lives as long as the write path, which outlives
  every reader of a line (the runtime joins its CPU pool first; a group of a dead path never reads its lines); past 256 an op
  builds its own `head`. The cap is per runtime lifetime (the table never shrinks): once 256 (kind, index) pairs were seen, an
  op of a new pair finds the table full without a lock and only builds its line, never taking the table's append mutex.
  Each producer thread keeps a 16-entry `thread_local` cache {table generation, kind, index, line} (the
  engine alternates its raw and events indices): on a hit (same table, same kind, index equal byte for byte) the index is not
  validated again and no line is built; on a miss the op is validated as always and, once valid, its line is found (lock-free) or
  interned in the table and takes an entry of the cache (an invalid index never enters either). The rest of the validation runs in the same order either way, so the first
  failure still wins. The charge does not count the shared line apart: every op charges its own `wire()` (which includes it) plus
  its body's heap slack, as any other op ([Charge and quota](#charge-and-quota)).
- `IndexDataStream` **with an `id`**: `head` is its own action line, `{"create":{"_index":"<i>","_id":"<id>"}}` plus `\n`, built with
  `appendEscaped` like the `Index` line; `body` as above. That line is never shared: it is not cached per thread and never enters the
  `HeadTable`, so a thread that alternates ops with and without an id for the same index keeps the shared line for the ones without
  (`cachedHead` is `nullptr` only for the ones with an id). A resend carries the same line, byte for byte, with the same `_id`.
- The update kinds (`IndexVersionedScript`, every `ReplacePreserving`) and `Delete`: `head` holds every line (the update kinds copy
  the document twice, which is their wire format) and `body` is empty.

On success `op.body` is left empty (moved from, or freed for the update kinds); on failure `op` is untouched. The shapes are
byte-for-byte the v1's (`indexerConnectorSyncImpl.hpp` of the deleted v1 library):

| Kind | Lines |
|---|---|
| `Index` | `{"index":{"_index":"<i>","_id":"<id>"}}` + body |
| `IndexAutoId` | `{"index":{"_index":"<i>"}}` + body |
| `IndexDataStream` | `{"create":{"_index":"<i>"}}` + body, or with an `id` `{"create":{"_index":"<i>","_id":"<id>"}}` + body (the line with an id is not shared and is not in the `HeadTable`) |
| `Delete` | `{"delete":{"_index":"<i>","_id":"<id>"}}` (one line, no body) |
| `IndexVersionedScript` | `{"update":{"_index":"<i>","_id":"<id>"<R>}}` + `{"script":{...,"params":{"doc_version":<version>,"doc":<body>}},"upsert":<body>,"scripted_upsert":true}`; the Painless source keeps the document unless `document_version` is older, then sets `ctx.op = 'none'`; the document travels twice |
| `Index` + `ReplacePreserving` | `{"update":{"_index":"<i>","_id":"<id>"<R>}}` + `{"script":{"source":"<PRESERVE_SOURCE>","lang":"painless","params":{"paths":<P>,"doc":<body>}},"upsert":<body>,"scripted_upsert":true}` |
| `IndexVersionedScript` + `ReplacePreserving` | as above with `"<PRESERVE_VERSIONED_SOURCE>"` and `"params":{"doc_version":<version>,"paths":<P>,"doc":<body>}` |

`<R>` is `,"retry_on_conflict":<n>` and appears only on the `update` actions (`IndexVersionedScript` and every `ReplacePreserving`
line) and only when the effective [conflict policy](#conflict-policy) is `Retry`; with `Success` the line is the plain one (v1
parity). An `index`, `create` or `delete` line never carries it (OpenSearch answers 400 to the whole request). `<P>` is the preserved
paths in the given order, each an array of its segments, e.g. `[["case"],["a","b"]]`.

**`ReplacePreserving`.** It is admitted only for `Index` and `IndexVersionedScript`; with `Delete`, `IndexAutoId` or
`IndexDataStream` the op is `InvalidArgument` (`mode: ...`). The document travels twice, as in `IndexVersionedScript`: once in
`params.doc` and once as `upsert` (a missing document is created by running the script on the upsert). The two Painless sources are
**constants** exported by `encoding.hpp` (`PRESERVE_SOURCE`, `PRESERVE_VERSIONED_SOURCE`): OpenSearch caches the compiled script per
source, so the paths travel in `params.paths`, never inside the source. Semantics, in this order:

1. (versioned only) the version guard first: an older `doc_version` sets `ctx.op = 'none'` (a noop) and nothing else runs;
2. each path is looked up in the stored `ctx._source`, walking only through `instanceof Map` and `containsKey`: a missing key or a
   non-map intermediate means "absent" and the walk never throws;
3. `ctx._source` becomes a copy of `params.doc` (fields the agent no longer sends disappear; `params.doc` itself is never mutated);
4. every path that was present is restored, copying each intermediate map before the `put`: the stored value wins over the agent's
   at that path. An absent path leaves the agent's value (or nothing).

**Caveat.** The in-process fake indexer does not run Painless: the tests freeze the bytes of both shapes and check the
outcomes the sender maps (`updated`, `noop`, `created`), but the preservation itself is proven only against a real OpenSearch.

Validation failures are `Cause::InvalidArgument`, counted in the bucket (`invalidArgument`), and the op is not charged. The
field is first in the reason (`index: ...`, `id: ...`, `version: ...`, `body: ...`, `mode: ...`,
`onConflict.retryOnConflict: ...`), which `Submit::reason` and `Group::lastAddReason()` hand to the consumer.

| Field | Rule |
|---|---|
| `index` | Non-empty and only `[a-zA-Z0-9._*-]` (the v1 allowlist, `isSafeIndexName`) |
| `id` | Required for `Index`, `Delete` and `IndexVersionedScript`; must be empty for `IndexAutoId`; optional for `IndexDataStream`, where, when present, it is at most 512 bytes (`id: longer than 512 bytes`) and valid UTF-8 (`id: not valid UTF-8`); the two limits apply to that kind only, `Index` and `Delete` have no bound. Escaped as the v1 does: `"`, `\`, the short escapes and any other control character below 0x20 as `\u00XX` |
| `version` | Only for `IndexVersionedScript`, where it must be a canonical integer in [0, `INT64_MAX`] (digits only, no leading zero); empty for every other kind |
| `body` | Required and free of `\n` for every kind but `Delete`; must be empty for `Delete`. With `BucketSpec::trustedBodies` the `\n` search is skipped (the producer vouches for compact JSON; a stray `\n` breaks the NDJSON framing: if what follows is not a valid action line the indexer answers 400 to that whole bulk; if it is one, the indexer runs the injected operation and answers 2xx with one item more than operations, the whole batch is requeued `{true, Backoff}` and every retry runs the injected operation again and duplicates each `IndexAutoId` and each `IndexDataStream` without an `id` of the batch until `Failed(RetryExhausted)`. Only for producers that guarantee compact JSON — the engine escapes every `\n`) |
| `mode` | `ReplacePreserving` only with `Index` or `IndexVersionedScript`; `preservedPaths` non-empty only with `ReplacePreserving` |
| `preservedPaths` | With `ReplacePreserving`: 1 to 16 paths; each 1 to 8 segments of 1 to 64 characters from `[A-Za-z0-9_@-]` (written dot-separated); no two equal and none a segment prefix of another; with `IndexVersionedScript` none may be `state`, `state.document_version` or below it (it would defeat the guard) |
| `onConflict` | Optional per-operation [conflict policy](#conflict-policy); `Retry` needs `retryOnConflict` in 1 to 100 (`MAX_RETRY_ON_CONFLICT`) |

### Conflict policy

A 409 on a `_bulk` item (`version_conflict_engine_exception`) is resolved by the **effective policy**: `Op::onConflict` when the
operation sets it, otherwise the bucket's `BucketSpec::onConflict`. The choice is stored with the operation (`OpState::conflictRetry`)
when it is admitted.

| Policy | A 409 item |
|---|---|
| `Success` | The op resolves `Ok` keeping the 409 and the error type (the default) |
| `Retry` | The op is requeued with backoff on the retry lane, with `LastError {VersionConflict, 409, type, reason}`; when the bucket's retry budget runs out it resolves `Failed(RetryExhausted)` carrying that last error. The wire line also carries `retry_on_conflict` (update actions only, see [Encoding per kind](#encoding-per-kind)) |

`retryOnConflict` must be 1 to 100 for a `Retry` policy, both in `Op::onConflict` (`InvalidArgument`, field
`onConflict.retryOnConflict`) and in the bucket's spec (registration refuses it). `Retry` on `create`
(`IndexDataStream`), `IndexAutoId` or `Index`/`Delete` is accepted but only changes how a 409 item is treated: for `create` the 409
means "the document exists", so retrying it can never succeed and is useless.

**Deduplicated 409.** A `create` carrying an `_id` (`IndexDataStream` with an `id`) that the indexer answers with a 409
`version_conflict_engine_exception` means the document is already there, typically because an earlier attempt of the same bulk was applied
after a timeout or a connection loss. With the `Success` policy the op resolves `Ok` (the 409 is kept) and the item is counted in the
bucket's `deduplicated` counter ([Catalog](#catalog)), in `submit` with a callback or ticket, in `post` and in a `Group` alike. Only that
combination counts: a 409 of an `IndexDataStream` without `_id`, of any other kind, or resolved by `Retry` does not. The library cannot tell a resend
from an `_id` the producer reused: a reused `_id` is counted (and logged) the same way, and its second document is not indexed, so
producers must generate a new `_id` for every write. Such items are
reported by a WARN at most once per `log_summary_interval_ms` ([Logging](#log-lines)). `ordered` buckets are described in [Ordered buckets](#ordered-buckets).

### Groups

`Writer::group()` returns a `Group` (the normative detail is `src/write/group.hpp`). It lets a consumer reserve room
for a set of writes first and release them to the scheduler all together.

- **States.** `Building` -> `Committed` -> `Done`, or `Building` -> `Abandoned`. A `Group` is single-owner and not thread-safe; two
  groups may be built concurrently from different threads.
- **`add(op)`** (`Building` only, else `InvalidState`) validates and encodes exactly as `submit` (failure is `InvalidArgument`, the
  reason is kept for `lastAddReason()`, empty after an accepted add) and **reserves the quota now**: payload plus `RESULT_RESERVE`
  against the bucket and the global cap. The op stays charged and outside the queue until `commit`. Refusals: `PayloadTooLarge`
  (above `bulk.maxBytes`, or the single charge above the quota or global cap), `GroupTooLarge` (what the group already holds plus
  this op would exceed the quota or the global cap; the group stays usable and can still be committed), `QueueFull`,
  `SubmitTimeout`, `Reentrancy`, the close cause, `Unavailable` (its client is gone; with the runtime shut down the add answers the
  close cause). `DropNewest` and `DropOldest` behave like `Reject` for a group: nothing is evicted and nothing is dropped.
  With `Block` the call waits for room like `submit`, except that it **never waits on a group in `Building`**: when the room is
  held by groups still being built (the bucket's or the global `building` charge) it returns `QueueFull` at once, so two half-built
  groups cannot deadlock each other.
- **`commit()`** (first call only; a second returns a ready ticket with `InvalidState`) enqueues every op under one bucket lock and
  makes them eligible **now**, whatever the thresholds (`maxAge`, `maxDocs`) say, and it always notifies the scheduler. An empty
  group is a ready ticket with success and an empty vector. If the bucket closed in between, the ops resolve `Dropped(cause)`; a
  group committed after the runtime is gone resolves every op `Dropped(Shutdown)` without touching the bucket (a `Group` may
  outlive `RuntimeOwner::shutdown()`: no bucket call is made without a live write path, because the bucket references the
  runtime's budget).
  Committed ops are ordinary pending ops (`DropOldest` of other submits may evict them; close and shutdown sweep them).
- **Results.** The `GroupTicket` completes when the last op has resolved (an op requeued by the retry lane or split is not resolved:
  the ticket waits), with the `OpResult`s in `add` order. There is no callback and no pool task.
- **Abandonment.** Destroying (or move-assigning over) a `Building` group returns its payload, its reserves, the bucket's and the
  global `building` charge at once and wakes blocked producers; the ops count as `groupAbandoned` and `resolvedDropped`.
- **Reserves.** The `RESULT_RESERVE` of every `add` returns when the shared group state dies (the last of the `Group`, the
  `GroupTicket` and the committed ops), through weak references to the write path and the bucket like a plain submit's reserve
  handle; if the bucket is gone the global budget gets it back. The group's mutex is a leaf: never held while calling the bucket,
  the scheduler, the write path or the budget.
- **Statistics.** `BucketStats` adds `groupBuilding` (ops reserved by uncommitted groups), `groupAbandoned` and
  `rejectedGroupTooLarge` (counted under `submitted`). The invariant is now `accepted = resolved + retained + groupBuilding`.
- **Reentrancy.** A `Block` `add` that would have to wait, and `GroupTicket::wait`, called from a runtime thread return `Reentrancy`.
- **Cancellation.** `cancel(tag)` does not see groups in `Building` (their ops are outside the queue); the ops of a committed
  group are ordinary pending ops and `cancel` reaches them (see [Cancellation](#cancellation)).

### Charge and quota

Every accepted operation is charged `payload + RESULT_RESERVE` (`RESULT_RESERVE` = 2048, `src/write/bucket.hpp`) against its
bucket's `quotaBytes` and against the runtime-wide `global_quota_bytes`.

- **The payload** is what the operation holds in the queue and in a batch: its **wire** bytes plus the heap slack of the
  moved-in body (`capacity - size` when the body lives on the heap; 0 for an empty body, a body in the small-string buffer, a
  `Delete` and the update kinds, whose `head` is reserved exactly). `Encoded::charge()` / `OpState::payload`. The rule: the
  **quota and the global cap** compare `payload + RESULT_RESERVE`; **`bulk.maxBytes`** (`PayloadTooLarge`), the bucket's
  thresholds, `Batch::bytes`, the DRR credit and the 413 split compare the **wire** size (`wire()`), which is what the indexer
  receives. A producer that moves in a body with spare capacity pays for it in quota, never in what is sent. The payload is
  released once, when the operation resolves (or at once when `DropOldest` evicts it).
- **`RESULT_RESERVE`** covers what the operation keeps after its lines are gone: its internal state, the ticket state, the callback
  slot and an `OpResult` with its strings at their caps. It is released after the callback has run (also when the callback throws)
  and, for an operation without a callback, when the last `Ticket` is destroyed. `Ticket::wait()` does not consume it. An
  operation of `post` has neither: its reserve is returned at its resolution, together with its payload.
- **How the constant was measured.** `ResultReserveMeasured` replaces the global `operator new` of the test executable with an
  allocation counter (usable size of every block) and measures the heap an accepted operation keeps besides its lines in six
  phases: retained with a callback; resolved with its completion queued behind a busy pool and its batch still held (the worst
  one); callback run with the `Ticket` alive; resolved without a callback; and requeued into the retry lane with its
  last error at its caps (1138.6 B) and the composed case: requeued with its last error at its caps, sliced again, then resolved
  `Failed(ItemPermanent)` with an `OpResult` at its caps while its completion waits behind the busy pool (1396.7 B). The
  resolution frees the operation's last-error strings (`Bucket::releasePayload`), so a retried operation keeps no more than one
  that was never requeued; with the strings kept the composed case measured 1992.7 B. The worst phase of the plain write path measured 1308.5 B
  per operation, 1404.1 B once the retry state was added to `OpState`; an `ordered` operation with a 256-byte tag pinned in the
  retry lane measured 1555.2 B; with the moved-in body and the shared action head in `OpState` (`body`, `sharedHead`), the same
  operation measures **1603.4 B**, x 1.25 = 2004.3, rounded up to a multiple of 64: **2048**. The case is a regression guard, skipped under
  ASAN/TSAN (they own `operator new`), and the constant is re-measured when the internal state grows.
- **What it does not cover.** Only the library's state: a callback whose captures exceed `std::function`'s small buffer (the
  measurement uses an 8-byte capture) allocates consumer memory that is not charged. `IWriter::submit(Op op, ...)` takes the
  operation by value: `submit(std::move(op))` avoids a copy of the body before the encoding moves it. `maxAge` counts from the
  moment `submit` was called, so time blocked in `Block` counts toward it. The bulk sender's body of a request in flight is a
  fresh concatenation of the batch's lines while the operations keep theirs: up to `node_window_max x nodes x bulk.maxBytes` of
  transient memory per runtime outside the quota. Whether to charge it or to send from the lines without the copy is an open choice.
- **Global cap.** `GlobalBudget` reserves with a lock-free compare-and-swap loop (never add-then-roll-back, which would refuse
  other buckets spuriously). Buckets whose quotas add up to more than the cap compete for it, and the one that does not fit
  applies its overflow policy as if its own quota were full.
- **Too large.** `Submit{false, PayloadTooLarge}` (or `Posted`) when the wire size is above `bulk.maxBytes`, or the charge
  (`payload + RESULT_RESERVE`) is above the bucket's `quotaBytes` or above the global cap. It is counted (`payloadTooLarge`).
- **Registration rule.** `RuntimeRef::client` rejects a bucket (`InvalidArgument`, field named in `reason`) unless
  `bulk.maxBytes + RESULT_RESERVE <= quotaBytes` (`validateBucket`, `src/runtime/runtime.cpp`), together with the older
  `bulk.maxBytes <= quotaBytes <= global_quota_bytes`. So the largest admissible operation always fits an empty bucket.
  `ordered = true` registers (`validateBucket` has no refusal for it); `onConflict.kind = Retry` registers with
  `retryOnConflict` 1 to 100.

### Overflow policies

When the charge does not fit, the bucket's `Overflow` decides:

| Policy | Result |
|---|---|
| `Reject` | `Submit{false, QueueFull}` (`rejectedQueueFull`) |
| `Block` | The producer sleeps until room, close or `blockTimeout`: `SubmitTimeout` on timeout (`submitTimeout`), the close cause (`ClientClosed` or `Shutdown`) on close (`rejectedClosed`) |
| `DropNewest` | The new operation is accepted but never queued and resolves `Dropped(QueueFull)`. Without a callback nothing is charged and the ticket is completed in `submit` (no pool task). With a callback only `RESULT_RESERVE` is charged, returned after the callback; if even that does not fit, `Submit{false, QueueFull}`. The pool backlog from drops is therefore bounded by `quotaBytes / RESULT_RESERVE` |
| `DropOldest` | Evicts the fewest oldest **pending** operations that make room (never one already delivered to the sink); each resolves `Dropped(QueueFull)`, its payload is released at once and its reserve after its callback. The evicted bytes pass to the new operation without a window in which another bucket could take them. If evicting everything pending would not be enough, nothing is evicted and the new operation gets the `DropNewest` treatment |

- **Block wake-ups.** `GlobalBudget` keeps the set of buckets with blocked producers (a bucket enters and leaves under its own
  mutex). Any release, local or global, that finds the set non-empty takes each such bucket's mutex (alone, holding no other lock)
  and notifies, so a release that frees global room wakes a producer blocked on another bucket. `requestClose()` and the shutdown
  wake every blocked producer.
- **Reentrancy.** A `submit` in `Block` that would have to wait, called from a runtime thread (a callback, for example), returns
  `Reentrancy` without sleeping (`reentrancy`), as every other wait in the library does.
- **Counters.** Each bucket keeps `submitted`, `accepted`, `rejectedQueueFull`, `rejectedClosed`, `submitTimeout`, `reentrancy`,
  `payloadTooLarge`, `invalidArgument`, `droppedNewest`, `droppedOldest`, `rejectedGroupTooLarge`, `groupBuilding`, `groupAbandoned`, `cancelled`, `orderedAmbiguous`, `orderedAmbiguousFailover`, `resolvedOk`, `resolvedFailed`, `resolvedDropped`,
  `retained`, `charge` and `peakCharge` (`BucketStats`; `WriteStats` adds `globalCharge` and `globalCap`). Invariants:
  `submitted = accepted + rejectedQueueFull + rejectedClosed + submitTimeout + reentrancy + payloadTooLarge + invalidArgument + rejectedGroupTooLarge`
  and `accepted = resolved + retained + groupBuilding` (the last term is the ops of groups not committed yet, see
  [Groups](#groups)). A drop is never silent: every `DropNewest` and each `DropOldest` eviction is counted and
  resolved.
- **Locks.** A bucket's mutex is a leaf: it is never held while posting, running a callback or destroying a ticket state, and
  the only other lock taken under it is the waiter registry's (itself a leaf).

### Staged admission of `post`

A bucket with `Overflow::DropNewest` that is not `ordered` (the engine's `events` and `raw` buckets) admits the `post()`
calls without a tag in batches. Everything else admits operation by operation as above: `submit()`, a group's
`add()`, a `post()` with a tag (so `cancel(tag)` sees it) and every `post()` on another policy or an ordered bucket.

- **Stripes.** The bucket has `K = max(1, min(64, 2 x hardware_concurrency()))` stripes; each producer thread always uses the
  same one. A staged `post()` takes only its stripe's mutex. The stripe is flushed with **one** take of the bucket's mutex
  (the rules of `admit` per operation, in stripe order) when it holds 64 operations, when its staged payload reaches
  `min(bulk.maxBytes, quotaBytes / (2K))`, when its oldest operation is `min(1 ms, bulk.maxAge)` old (the scheduler's pass on
  loop 0 flushes it whether or not the sink has capacity) and when the bucket closes. Each operation of a flush is admitted
  (or dropped) whole or not at all: a failure leaves it and the rest staged for the next flush. The quota edge lines a flush
  crosses ([Logging](#log-lines)) are written once the stripe's mutex is dropped too, by the thread that flushed
  it: the posting thread, loop 0 for a deadline flush, or the closing thread.
- **Deadline wake-up.** Loop 0's timer, not the producer, flushes a stripe at its deadline
  (`oldest + min(1 ms, maxAge)`). On the empty → non-empty transition the stripe publishes `oldest` and notifies the scheduler
  only if that deadline is earlier than the one loop 0 last armed for the bucket (published after the timer is armed; unknown,
  so always notified, while a pass runs or when none is armed). Otherwise the pass at the armed deadline reads the stripe and
  re-arms, so the operation is still admitted within `min(1 ms, maxAge)` plus a tick, without a scheduler post per transition.
  The stripes' deadline is armed on its own when the bucket's other deadline is already past and waits for sink capacity (an
  expired pending operation or a committed group while every node is down or the send window is full): a staged operation
  never waits for capacity (`WriteLocalBatch.StripeDeadlineWithExpiredPendingAndNoCapacity`).
  It rests on a Dekker pair, every access `seq_cst`: the producer stores `oldest` and then loads the armed deadline; the pass
  invalidates the armed deadline at its start and then reads every stripe's `oldest` (when it computes the next deadline), so
  at least one of them sees the other's store. The component case `WriteLocalBatch.StageRacingPassArmsDeadline` races both
  orders through two seams.
- **`Posted`.** A staged `post()` returns `accepted` at once: with `DropNewest` a full quota is accepted anyway, and an
  overflow found at the flush is counted `droppedNewest` and resolved `Dropped(QueueFull)` as before. An operation that can
  never fit (`PayloadTooLarge`: wire above `bulk.maxBytes`, or payload + `RESULT_RESERVE` above the quota or the global cap)
  and any `post()` on a closing bucket are not staged: they are refused at once with today's cause and counters.
- **Lag of the snapshot.** `submitted`, `accepted`, `charge`, `retained` and the metrics built from them move
  when a stripe is flushed: up to 64 operations per stripe, so up to `K x 64` per bucket, or `min(1 ms, maxAge)`, behind
  the `post()` calls.
- **Memory outside the quota.** Staged operations are not charged: they are outside the bucket's quota and the global cap
  until their flush. Per bucket that memory is bounded by `quotaBytes / 2` (`K` stripes of at most `quotaBytes / (2K)`
  of payload, plus one operation each), and over every staging bucket by the sum of those halves.
- **Close.** Every close entry (`requestClose()`, `awaitClosed`'s sweep, a `Client` destroyed on a runtime thread, the
  runtime's `stop()`) flushes the stripes while the admission is still open, then closes it: a staged operation is never
  lost, drains like any other after `requestClose()` and is counted in the `CloseReport`. A `post()` that reaches its stripe
  after the seal sees it and is admitted by itself: refused with the close cause once the admission is closed (in the short
  window between the seal and that close it is still accepted, as a `post()` that began before `requestClose()` returned).
- **Order.** Stripes are flushed independently, so the pending queue is not strictly in `post()` order: an operation can be
  admitted up to `min(1 ms, maxAge)` after a later one of another thread, a `submit()` can overtake earlier staged `post()`
  calls of the same thread, and a `post()` staged before a group's `commit()` leaves with `maxAge` rather than with the
  group. The bucket is unordered, so no ordering promise is broken.
- **Bulk settlement.** A bulk's results are settled in chunks of `SETTLE_CHUNK` = 64 operations (= the operations of a full
  stripe), one take of the bucket's mutex each: a chunk holds it about as long as a stripe flush does, so producers flushing
  stripes do not queue behind a settlement (with 512 a chunk held it ~50 µs and convoyed eight producers). The price, one
  take of the mutex and one release to the global cap per 64 operations, is 1/64 of settling operation by operation.

### Scheduler (DRR on loop 0)

One `Scheduler` per runtime, created after the loops exist. All its state (ring, cursor, credits, `maxAge` timers) is touched only
from network loop 0, as the `Prober` does; other threads only append to a notification list and post a pass.

- **Thresholds.** A bucket is eligible when its pending bytes reach `bulk.maxBytes`, its pending operations reach `bulk.maxDocs`
  or its oldest pending operation is `bulk.maxAge` old, or its retry-lane head is due (`Bucket::eligible(now)`; see [the retry lane](#response-classification-and-retry-lane)).
- **Notifications.** `Bucket::admit` (and a group's `enqueueGroup`) tells the scheduler when the bucket goes from empty to non-empty or crosses `maxBytes` or `maxDocs`
  (`>=`), deduplicated by an atomic flag. Notifications posted while a pass is queued coalesce into that pass.
- **`maxAge` timers.** Each bucket has an asio timer armed for its oldest pending operation plus `maxAge`, and re-armed after every
  pass. An expiry already due when the timer would be armed is not armed (it would spin while the sink has no capacity): the pass
  runs once more instead, when the sink has capacity; otherwise `sinkReady()` resumes the scheduler.
- **The DRR loop.** Eligible buckets form a ring with a persistent cursor. On its turn a bucket's `credit` grows by
  `weight x drr_quantum_bytes` and it emits batches while `credit > 0` and `sink.capacity() > 0`. A batch takes whole
  operations from the head, up to `bulk.maxBytes` (and the limiter's `batchLimit()`) and `bulk.maxDocs`, whatever the credit; the
  head always goes, so a document is never split. Each batch takes its bytes from the credit with no floor: the excess is a
  **debt** (a negative credit) that the next turns pay back before the bucket emits again. Admission refuses any document larger
  than `bulk.maxBytes` and a turn emits only with `credit > 0`, so the debt stays above `-bulk.maxBytes` (a batch that reaches it
  is a bug: counted in `SchedulerStats::debtOverruns`, never aborted on). Over many turns each bucket's share of
  the bytes still follows its weight. The turn ends when the credit is `<= 0` (credit kept), when the bucket empties (a debt is
  kept, a positive credit drops to 0), when it falls below every threshold again (its timer brings it back) or, **after
  `weight x DRR_MAX_BATCHES_PER_TURN` (8) batches, when another bucket of the ring is eligible** (scaled by the weight so
  that the shares still follow the weights): the cursor moves on and the leftover credit is kept, capped at
  `weight x drr_quantum_bytes` (the next turn adds its quantum as usual); with no other eligible bucket the turn goes on. If the
  sink's capacity reaches 0 the cursor stays on the bucket and `sinkReady()` resumes the same turn without new credit.
- **One wake per completion.** A bulk completion posts the scheduler **once**: the notify of each of its requeues is deferred to
  the completion's final wake, together with the pinned buckets whose node is usable (`Scheduler::notifyAll(buckets)`, one post). Deferring
  costs nothing: every pass re-arms the timer of every known bucket, a `Backoff` requeue's due included.
- **Fast-forward.** If a complete round emits nothing (every bucket of the ring has `credit <= 0`: a quantum small against the
  documents, or a debt being paid back), the scheduler adds at once the credit of the `k - 1` empty rounds classic DRR would still
  spin through (`k` = fewest rounds after which some bucket has `credit > 0`) instead of looping (`SchedulerStats::fastForwards`).
  Same outcome, no spin on loop 0.

### Internal sink

`detail::write::BatchSink` (`src/write/sink.hpp`) is where batches go: `capacity()` (batches it accepts now; 0 stops the scheduler
until `WritePath::sinkReady()`), `dispatch(Batch)` (on loop 0; each operation must be resolved exactly once through
`WritePath::resolve`, from any thread) and `stop()` (afterwards no batch is accepted; what the sink still holds is resolved by the
shutdown sweep). **Production: the [bulk sender](#bulk-sender)** (`BulkSink`), whose capacity is the free window of the usable
nodes (each one's adaptive window, see [Load control](#load-control)); `batchLimit()` (default 0) is the smallest capped bulk target
among the usable nodes, which the scheduler passes to `Bucket::slice` as `cap`. `WritePath::setSink` stops the sink it replaces; the bulk sender's transfers
in flight are cancelled, and their batches go back to the retry lane with no attempt and wait for the new sink (no sweep follows
outside a runtime stop; a closed bucket hands them back for `Dropped`). The component suites that need a programmable sink install
it through `detail::write::runtimeWritePath()->setSink(...)`; with the production sink and no usable node, batches wait in the
retry lane rather than resolving.

### Resolution

Every operation resolves exactly once: the first of the sink, a close sweep or an eviction wins (`OpState::claimed`), and the
rest are no-ops. The winner releases the payload, counts the status in the bucket and completes the ticket; the callback runs on
the CPU pool (never on a network thread) after the ticket is completed, and the reserve is returned after it. A callback that
throws is swallowed and does not skip the accounting. If the pool no longer accepts tasks (late in shutdown), the completion runs
inline. `Dropped(ClientClosed)` and `Dropped(Shutdown)` are also counted per client for the `CloseReport`; the client is the
bucket's (one bucket belongs to one client), so a submitted, posted or group operation counts alike, and an operation whose bucket
is gone has no client left to count. An operation of `post` (no ticket, no callback, no group) returns its `RESULT_RESERVE` at its
resolution, in the same take of the bucket's mutex that releases its payload (`Bucket::releasePayload`), or to the global cap
when its bucket is gone; one left queued in a dying bucket gets it back from `~Bucket`. An operation still delivered when its
bucket dies (its batch let go unresolved) gets its payload back to the global cap from `~Bucket`, once; its later resolution
returns only what is still its own.

### Close and shutdown

The close of a client and the runtime shutdown are described in [Closing and shutdown](#closing-and-shutdown). `requestClose()` does not drop the pending operations. `submit` and `post` reserve and
queue under one take of the bucket's mutex (`Bucket::admit`), so there is no window between the reservation and the queue:
an operation is queued before the close or refused with its cause. Only a group keeps such a window (it reserves at `add()` and
queues at `commit()`).

### Response classification and retry lane

The bulk sender is built from two pieces: a pure **classifier** of a `_bulk` response and the bucket's **retry
lane**. The [bulk sender](#bulk-sender) is their only production caller (see [Build and tests](#build-and-tests) for
the suites).

**Classifier** (`src/write/response.{hpp,cpp}`). It returns verdicts and applies no policy; it names no bucket type, so the queries reuse
the request classifier. Two steps over one response:

`classifyRequest(HttpResult, batchSize)` returns a `RequestOutcome{verdict, cause, httpStatus, reason, retryAfter, mayHaveSent}`:

| Response | Verdict | Cause / note |
|---|---|---|
| `Timeout`, `Connect`, `SendError`, `RecvError`, `PartialResponse`, `Tls` (node-attributable) | `Failover` | `mayHaveSent` is copied from the `HttpResult`: the sender counts an attempt only when it is set |
| `TlsConfig`, `LocalError` | `Retry` | |
| `Cancelled`, `Shutdown` | `Ignore` | The shutdown sweep resolves the operations |
| 429 | `Throttled` | `Cause::Throttled`; `retryAfter` when the transport parsed one |
| 413 | `Split` (more than one operation) | `Cause::PayloadTooLarge`; with one operation `FailBatch(PayloadTooLarge)` |
| `ResponseTooLarge` | `Split` (more than one operation) | With one operation `FailBatch(ItemPermanent)`, reason `response over maxResponseBytes`; under any size the bucket's [`onAmbiguous5xx`](#ambiguous-5xx) `Fail` turns it into `Failed(Ambiguous)` (the node answered: the bulk may be applied) |
| 408 | `Retry` | `TransportTimeout` |
| 5xx | `Retry` | `Server5xx`; for 500, 502 and 504 the bucket's [`onAmbiguous5xx`](#ambiguous-5xx) may turn it into `Failed(Ambiguous)` |
| 401, 403 | `Retry` | `Client4xx` (see the deviation below) |
| 3xx (curl does not follow redirects) | `FailBatch` | `Client4xx`, reason `unexpected 3xx` |
| any other 4xx, a request-level 409 included | `FailBatch` | `Client4xx` |
| 2xx | `Items` | |
| a status outside the table (1xx, 600 and above) | `Retry` | `Server5xx`, reason `unexpected status`: bounded by `maxAttempts` instead of dropped |

**Deviation from "a 4xx is permanent".** 401 and 403 are **retryable** here, because the node
probe already marks the node `Down` for them and discarding data over credentials would be silent (`CredentialsErrorRetries`).

### Ambiguous 5xx

A `_bulk` answered 500, 502 or 504 may have been **applied** by the indexer (a partial failure behind a gateway or a coordinating node).
Resending it duplicates documents in an index without `_id` (data streams). `BucketSpec::onAmbiguous5xx` (v1 parity: the async
connector never resent these) chooses per bucket:

| Policy | A 500, 502 or 504 on `_bulk` | A `_bulk` response over `max_response_bytes` (`ResponseTooLarge`) |
|---|---|---|
| `AmbiguousPolicy::Retry` (default) | Requeued `{true, Backoff}` like any 5xx; it may duplicate | `Split` like a 413 (the halves are resent; one operation alone ends `Failed(ItemPermanent)`); it may duplicate |
| `AmbiguousPolicy::Fail` | Every operation of the batch resolves `Failed(Ambiguous)` with the HTTP status and reason `ambiguous HTTP <status> (not resent)`; nothing is resent | Every operation of the batch, one alone included, resolves `Failed(Ambiguous)` with the status the node sent in its headers and reason `ambiguous response over maxResponseBytes (not resent)`; never split nor resent |

- A **503** is always retried, under both policies. The classifier is untouched: the sender turns the `Retry` (5xx) or `Split`/`FailBatch`
  (`ResponseTooLarge`) verdict into `FailBatch` with `Cause::Ambiguous` as soon as the completion classifies it (before the node's
  accounting, so no split is counted), so the choice lives in the bucket and not in the response table.
- **A response over the cap is ambiguous too.** The node answered (`ResponseTooLarge` clears the ordered pin like any HTTP response) but the
  client stopped reading the body, so it cannot know which items were applied. Splitting it would resend every operation in halves: harmless
  with an `_id` (`Retry` keeps doing it so that an oversized answer still makes progress), a duplicate without one (`ResponseTooLargeFailPolicyNeverResent`). The WARN then names the cap instead of a status: `... got a response over max_response_bytes for
  a bulk of <n> operations: ...`.
- The operations count in `failed.ambiguous` (`FailCause::Ambiguous`, [Metrics](#metrics)); there is no separate counter. The new `Cause`
  is `ambiguous` (`toString(Cause::Ambiguous)`).
- **One WARN per edge**: the first ambiguous failure of the bucket after a 2xx `_bulk` (or since the bucket was created) logs once; the next
  2xx `_bulk` of the bucket re-arms it ([Logging](#log-lines)). A storm of 502 logs one line, not one per batch. The line's `<n>` is the
  operations the completion resolved `Failed(Ambiguous)` (those another resolution won, e.g. a shutdown sweep, count as late results and not
  here); a bulk whose operations were all late logs nothing.
- **Never resent, even on an internal failure.** The decision is taken before the completion's exception guard, so a completion that throws
  after it (an allocation failure, say) resolves what is still unresolved `Failed(Ambiguous)` instead of the usual requeue with an attempt.
- **Known asymmetry.** The policy covers the status codes only. A transport timeout, a reset or any other failure **after the request was
  sent** (`mayHaveSent`) stays a counted failover (`Retry`, v1 parity) under both policies, so it may still duplicate in buckets without
  `_id`. Buckets whose operations carry an `_id` are idempotent and should keep `Retry`; append-only buckets without `_id` (the engine's `events`
  and `raw`) are the ones that choose `Fail`. An `IndexDataStream` with an `_id` is the conditional exception: its resend is idempotent
  within the backing index and its 409 is counted ([Deduplicated 409](#conflict-policy)).

`classifyItems(std::string& body, expected)` reads a 2xx body item by item and returns one `ItemResult{verdict, outcome, httpStatus,
itemErrorType, reason}` per operation, or `nullopt` when the body is unreadable or does not hold exactly `expected` items (the sender
retries that with an attempt). `"errors":false` is never used to skip anything: **every item is classified**, so a success
is always read from its own status. The position decides the match (item i is operation i); the item's key (`index`, `create`,
`delete` or `update`) only matters for the `delete` rule. An item with no key, more than one key or no `status` is `Permanent` with
reason `malformed item`.

| Item | Verdict | Note |
|---|---|---|
| 2xx | `Ok` | `outcome` from `result`: `created`, `updated`, `noop`, `deleted` |
| `delete`, 404, `result: not_found`, no `error` | `NotFound` | Idempotent success (`ItemOutcome::NotFound`) |
| 404 with `index_not_found_exception`, any other 404 | `Permanent` | |
| 429, 5xx, `cluster_block_exception`, `es_rejected_execution_exception` | `Retry` | |
| 409 with `version_conflict_engine_exception` | `Conflict` | By the op's effective [conflict policy](#conflict-policy): `Success` ⇒ `Ok` keeping the 409 and the error type; `Retry` ⇒ requeued |
| 409 of another type, any other 4xx, a status outside the table | `Permanent` | |

`itemErrorType` is truncated to 64 B and `reason` to 512 B (never inside a UTF-8 sequence); the `caused_by` error is appended to the
`reason` as `; caused by <type>: <reason>`.

**Parser memory.** The parser is simdjson's *ondemand* one (no DOM), one per pool thread, and it is rebuilt after a parse
when its capacity is above **4 MiB**, so a single large response does not pin memory on a pool thread for the runtime's lifetime
(`ParserMemoryBounded`). ondemand needs `SIMDJSON_PADDING` readable bytes after the body: the transport reserves
`RESPONSE_PADDING` (64) bytes once, when a transfer completes and before the body moves into the `HttpResult`
(`src/transport/curlLoop.cpp`), so `classifyItems` normally copies nothing; it only reserves them itself when a body arrives without
(`std::string&` is mutable for that reason; the content never changes). `testing_hooks::parserCapacity()` exists in the test build only.

**Risk.** Only simdjson's stage 2 (the header-side iteration: skipping, unescaping, number parsing) is compiled without
`-march` and runs the scalar `fallback` code; stage 1 (structural indexing and UTF-8 validation) runs the archive's
runtime-dispatched kernel (haswell, icelake, westmere). The 0.3 s per 8 MiB seen so far is a Debug (-O0) figure. Still to do:
measure big responses in Release with `bench --path client` before multiversioning `response.cpp` (which would only speed up
stage 2) or moving to the dispatched DOM with a bounded parser.

**Retry lane** (`src/write/bucket.{hpp,cpp}`). `OpState` gains `firstAttempt` (set by the first `slice`), `notBefore`,
`batchCap` (bytes, 0 = no cap) and the last error (`lastCause`, `lastHttpStatus`, `lastItemErrorType`, `lastReason`).
`Bucket::requeue(ops, RequeueSpec, now)` moves delivered operations back, under one lock per call, and returns a
`RequeueResult{notify, exhausted, closed}`. `RequeueSpec{countAttempt, delay, at, toHead, halve}` is what the [bulk sender](#bulk-sender) passes:

| Use | `RequeueSpec` |
|---|---|
| Failover | `{countAttempt = mayHaveSent, Now}` |
| 429 | `{false, Now}` (the node's `notBefore` keeps the node quiet; the batch may go to another node) |
| Retryable error, unreadable 2xx, item `Retry`, refused submit | `{true, Backoff}` |
| Split (413, `ResponseTooLarge`) | `{false, Now, toHead, halve}` |
| No usable node, or the sender stopped before the submit | `{false, Now}` |

- **Backoff.** `d = min(cap, base * 2^(attempts - 1))` with a bounded exponent (`d = cap` as soon as the exponent would reach it), then
  `notBefore = now + d * (1 + jitter * u)` with `u` uniform in [-1, 1], never above `cap`. The jitter is drawn once per call, so the
  operations of one batch stay together. `base`, `cap` and `jitter` are the bucket's `RetryPolicy`.
- **Exhaustion.** An operation is exhausted when `attempts >= maxAttempts` or `now - firstAttempt >= maxDuration`; an unset bound
  (`nullopt`) never exhausts. `maxDuration` counts from the **first send**, not from the queueing, so time spent waiting in the
  queue is not spent budget (`MaxDurationCountsFromFirstSend`). Exhausted operations are returned in `exhausted` for the caller to
  resolve `Failed(RetryExhausted)` with their last status, error type and reason.
- **`halve` and `batchCap`.** After a 413 or `ResponseTooLarge` the two halves must not merge again: `halve` sets
  `batchCap = ceil(batch bytes / 2)` on the requeued operations, and `slice` stops before exceeding the smallest `batchCap` of what it
  has taken (`SplitHalvesNeverRemerge`).
- **Lane before pending.** The lane is ordered by `notBefore` and goes **before** the pending queue. `eligible(now)` is the
  thresholds or a due lane head; `headBytes(now)` and `slice(now)` take the due lane first and then the pending queue (a
  batch may hold both); `empty()` means no pending operation and an empty lane; `nextDue(now)` is the minimum of the oldest
  pending operation plus `maxAge` and the lane head. A lane that is not yet due makes the bucket neither eligible nor stuck in the
  ring (`LaneBeforePending`, through the real scheduler). The scheduler's `maxAge` timer is armed on `nextDue()`.
- **Close and sweep.** An operation requeued into a closed bucket is returned in `closed` (to resolve `Dropped(closedCause)`);
  `close()` returns the lane and then the pending operations; operations already `claimed` are skipped. The `exhausted` and `closed`
  ones stay in the delivered set until the caller resolves them, so the shutdown sweep still sees them. `notify` is set when the lane
  was empty or its head moved earlier.
- **Quota and overflow.** The charge does not change while an operation sits in the lane, and `DropOldest` evicts only
  pending operations, never one in the lane (`DropOldestSparesRetryLane`).

The scheduler passes its `now` to `eligible`, `headBytes` and `slice`; that is the only change to its code.

### Bulk sender

`detail::write::BulkSink` (`src/write/sender.{hpp,cpp}`) is the production `BatchSink`. `src/write/sender.hpp` is the normative
description; this section is the summary. It owns no thread: it runs on loop 0 (`dispatch`, the timer), on the CPU pool (assembly
and completions) and inside the transport's callbacks, and every task captures the shared state, never `this`.

**Per-node state** (under the sender's mutex, a leaf): `inFlight`, `notBefore`, `pace`, a mirror of the node's `Down` state (every
node starts `Down`, like the `NodeSet`'s view; the `NodeSet::onTransition` hook keeps the mirror current), request and latency
counters and the limiter's state (see [Load control](#load-control)). The window is adaptive: up to `node_window_max` bulk
requests in flight per node (default 4). `capacity()` is the sum over the usable nodes of `⌊window⌋ - inFlight` (1 for a node with
`pace > 0`); it reads only the sender's mutex, so the scheduler can ask it on every pass.

**Lock order.** The `NodeSet` mutex may take the sender's (the filter of `choose`), never the reverse. The sender never calls
`NodeSet`, `Bucket`, `WritePath`, `Scheduler` or `Transport` with its own mutex held.

**Choosing a node.** `dispatch(batch)` on loop 0 calls `NodeSet::choose(filter)`: a usable node (not `Down`, `notBefore` and
`nextSendAt` passed, `inFlight` below `⌊window⌋`); the slot (`inFlight++`) is taken in the same step. With no such node the sender
refreshes its `Down` mirror from the `NodeSet` (the hook may still be on its way; a stale mirror would keep `capacity()` above 0
and the scheduler re-slicing), the batch goes back to the retry lane (`{false, Now}`, no attempt counted, last error
`Unavailable` "no usable node") and a health transition or the timer wakes the scheduler later. A requeue without an error of its
own keeps the operation's previous last error.

**Assembly and send.** On the CPU pool the operations' encoded lines are concatenated, in batch order, into one body and sent as
`POST {host}/_bulk` with `Content-Type: application/json` through `Transport::submit`. Every exit of that task that does not
produce a callback gives the slot back: a refusal because of `Shutdown` (the transport or the pool, after `stop()`) leaves the
operations to the shutdown sweep; any other refusal, an exception, or the test seam `refuseSubmit()` requeues the batch with
`{true, Backoff}`, last error `InvalidState` with the reason, and counts `submitRefused`. An exception after the transport admitted
the transfer leaves the slot to its callback.

**Completion** (CPU pool), in this order: `inFlight--` and the node's 429 state under the mutex, release it, then
`NodeSet::report` / requeue / `resolve`, and finally the completion's single scheduler wake (see **Wake-ups**). An exception in the second part
(after the slot was released) requeues what is still unresolved `{true, Backoff}` with last error `InvalidState`, and
the wake still runs.

| Verdict | What the sender does |
|---|---|
| `Ignore` (`Shutdown`) | Nothing; the sweep resolves |
| `Ignore` (`Cancelled`, the sender already stopped) | Requeue `{false, Now}` with last error `Cancelled`: after a `setSink` the batch waits for the new sink; during a runtime stop the bucket is closed and it ends `Dropped(Shutdown)` |
| `Failover` | `NodeSet::report` (the node goes `Down`) and requeue `{mayHaveSent, Now}`: a failover whose request may not have left costs no attempt |
| `Retry` | Requeue `{true, Backoff}`; a 500, 502 or 504 in a bucket with `onAmbiguous5xx = Fail` is resolved `Failed(Ambiguous)` instead (see [Ambiguous 5xx](#ambiguous-5xx)) |
| `Throttled` (429) | `NodeSet::report` (the node goes `Throttled`), raise the node's `notBefore`, requeue `{false, Now}` (see below) |
| `Split` | Requeue `{false, Now, toHead, halve}`; a `ResponseTooLarge` in a bucket with `onAmbiguous5xx = Fail` is resolved `Failed(Ambiguous)` instead |
| `FailBatch` | Every operation `Failed(cause, httpStatus, reason)` |
| `Items` | `classifyItems`; per item `Ok`/`NotFound` resolve `Ok` with the item's outcome, `Conflict` follows the op's effective [conflict policy](#conflict-policy) (`Success`: `Ok` keeping 409 and the error type; `Retry`: requeue `{true, Backoff}` and, once exhausted, `Failed(RetryExhausted)`), `Retry` requeues `{true, Backoff}` (one call per batch), `Permanent` resolves `Failed(ItemPermanent)` with the item's status, type and reason |

An operation the requeue returns as `exhausted` resolves `Failed(RetryExhausted)` with its last error; one returned as `closed`
resolves `Dropped` with the bucket's close cause (`ClientClosed` or `Shutdown`).

**429 and pacing.** On a request-level 429 the node's `notBefore = max(notBefore, now + max(Retry-After or 0, pace))`: a
`notBefore` in force is never shortened. `pace` starts at 0; a 429 sets it to `pace_initial_ms` and later ones double it, up to
`retry_after_max_ms`, **but only for a 429 whose request left after the node's burst marker** (the last bulk 429 that doubled `pace`
or raised `notBefore`; a park mirrored from a query, PIT or probe 429 never moves it), so one burst of the window doubles it once. A 2xx never shortens a `notBefore` in force; it relaxes `pace` only through the clean-send count described in
[Load control](#load-control). The batch is requeued with no attempt counted and no delay, so it can go to another node while
the throttled one is quiet.

**Wake-ups.** Every completion wakes the scheduler **once**: the buckets its requeues asked for (`notify`) and the pinned buckets
whose node is usable go in one `Scheduler::notifyAll(buckets)` post, which also does the work of `sinkReady()`. The one exception: a completion whose
`NodeSet::report()` transitions the node (a `Throttled` or `Failover` verdict) also runs the `NodeSet` hook, and its `refreshMirror` posts its
own wake (the one a `Down` → usable change needs), so that completion posts twice. The test oracle is `SchedulerStats::posts` (counted before coalescing). `refreshMirror` also mirrors the `NodeSet`'s
[`notBefore`](#node-health) into the node's slot, so a node parked by a 429 from a query or a PIT is quiet for the sender too. A timer on
loop 0, armed at the earliest `notBefore` or `nextSendAt` in force (see [Load control](#load-control)) by a post from a
completion that captures the shared state and checks `stopped` (the `Prober`'s pattern) or directly by `dispatch()` (already on
loop 0), calls `sinkReady()` when it expires, so a node whose `notBefore` passed is used again without another `submit`. The
`NodeSet::onTransition` hook mirrors the node's state and calls `sinkReady()` through a `weak_ptr<WritePath>`. `start()` registers
the hook and the runtime calls it **before** `prober->start()`, so the first probe round cannot be missed; the write path is
created after the prober and started before it (`RuntimeState`, `src/runtime/runtime.cpp`).

**Stop.** `stop()` is idempotent: it sets `stopped`, calls `Transport::cancel` on what is in flight and drops the timer on loop 0
(directly when already on loop 0, otherwise it posts and waits). Results that arrive later are `Ignore` or lose to the sweep
(resolution is first-wins). A batch whose task finds the sender stopped before the submit goes back to the lane with no attempt
(last error `InvalidState` "sender stopped before the submit"):
during a runtime stop its bucket is already closed, so it ends `Dropped(Shutdown)`; after `setSink` it waits for the new sink. The
destructor counts a usage error only if its timer was armed and `stop()` never ran.

**`SenderStats`** (`detail::write::senderStats()`, empty when no runtime runs or a test replaced the sink): `sent`, `failovers`,
`splits`, `throttled` (request-level 429), `retries` (requeues that count an attempt), `submitRefused`, `exhausted`, and per node
`host`, `down`, `inFlight`, `notBefore` (only when in force), `pace`, `requests` and `totalMicros` (HTTP responses only, any status:
their count and the sum of their `timings.total`) and `failures` (completions without a response: timeout, connection, TLS,
cancellation), plus the limiter's fields listed in [Load control](#load-control).

**At-least-once, new against the v1.** The sender never drops an operation silently, and some situations that the v1 treated
as success or failure now retry, so the indexer may see an operation more than once. Resolution is still exactly once.

| Situation | Behaviour |
|---|---|
| A 2xx whose body is unreadable, or holds a different number of items than operations | The whole batch is requeued `{true, Backoff}`; the last error is `Server5xx` with the HTTP status and the parser's reason; when attempts run out it ends `Failed(RetryExhausted)` carrying it (`UnreadableBodyRetries`) |
| `ResponseTooLarge` | Split in halves like a 413; one operation alone ends `Failed(ItemPermanent)`, `response over maxResponseBytes` (`ResponseTooLargeSplits`). In a bucket with `onAmbiguous5xx = Fail` the whole batch ends `Failed(Ambiguous)` after one request (`ResponseTooLargeFailPolicyNeverResent`) |
| Timeout, connection reset or any failover with `mayHaveSent` | The batch goes to another node and the attempt is counted; the first node may have applied it (`FailoverOnTransportError`) |
| A failover with `mayHaveSent` false | Retried with no attempt counted |
| 401, 403 | Retryable, not a failed batch (`CredentialsErrorRetries`) |

### Ordered buckets

`BucketSpec::ordered = true` gives a bucket **send order per key**. The normative text is `src/write/bucket.hpp`
(ORDERED BUCKETS) and `src/write/sender.hpp` (Ordered buckets and cancellation); this section is the summary.

**What is guaranteed, and what is not.** The library orders what it **sends**: an operation is never put on the wire before an
earlier operation of the same key has a final outcome (from the indexer or a local drop) or, in the ambiguous case below, before the pin ended. It does
**not** order how the indexer applies requests: a request that timed out may still be applied later by its node (see the residual risk below). An unordered bucket is unchanged (`UnorderedUnchanged`).

- **The key** is `(index, _id)`: `OpState::keyHash` is a 64-bit FNV-1a hash of `index`, a `\0` byte and `_id` (`orderedKeyHash`), set only
  in an ordered bucket and only for ops with `_id`. A collision can only block too much, never too little. Operations without `_id`
  (`IndexAutoId`, and `IndexDataStream` without an `id`) have no key and are **never blocked**; an `IndexDataStream` with an `id` has one,
  like an `Index` with the same `_id`, and is ordered by it.
- **One bulk in flight.** While any operation of the bucket is delivered to the sink the bucket is not eligible and `nextDue` is empty;
  the completion wakes the scheduler (`sinkReady`). So an ordered bucket never has two `_bulk` requests in flight (the node window of
  the sender still applies across buckets).
- **A key at most once per bulk.** `slice` takes the due retry lane first and then scans the pending queue in order: a pending operation
  whose key is already blocked (a key in the lane, one already taken into the batch or one of an operation skipped earlier in the scan) is
  skipped and keeps its place. The scan is bounded by what it **takes**, not by what it visits: it **stops** once the batch holds
  `bulk.maxDocs` operations, at the first takeable operation that does not fit (`maxBytes`, `batchCap`, the sink's `batchLimit()`; the DRR
  credit never bounds a batch), or at the end of the queue. Skipped operations leave in a later bulk, and one that is alone leaves by `maxAge`.
- **Only the key is blocked.** An operation in the retry lane (item `Retry`, a 409 under a `Retry` policy, backoff) blocks its own
  key and nothing else: operations of other keys keep flowing in the following bulks, and the successors of the key wait until it resolves.
  This holds whatever the number of blocked operations ahead: the eligibility check looks for the first takeable operation in the
  **whole** pending queue (a window of `bulk.maxDocs` entries would hide a key behind that many blocked operations until the blocked keys'
  retries ended, never under unlimited retries; `OrderedBlockedPrefixBeyondMaxDocsDoesNotStallOtherKeys`).
- **Scan cost.** The bucket remembers how many operations at the head of the pending queue were found blocked by a lane key, and the
  eligibility checks and `slice` resume after them, so a scheduler pass that changes nothing costs O(1). A lane key leaving the lane, or any
  change inside that prefix (an eviction, a cancel, the close), resets it; the rescan is O(pending operations), bounded by the bucket's
  quota, once per such event (in practice once per bulk round trip, since an ordered bucket has one bulk in flight).
- **No idle spin.** With nothing takeable `nextDue` is the `notBefore` of the lane head (not `now`), so loop 0 does not run in empty
  (`OrderedNoIdleSpin`).

**Ambiguous state.** A `Failover` with `mayHaveSent` (timeout, reset or TLS failure after the request left, see
[Response classification](#response-classification-and-retry-lane)) means the node may already have applied the bulk. In an
ordered bucket the sender does not fail over at once: it requeues the batch with a **pin** `{node, until = now + ambiguous_retry_window_ms}`
(default 30 s, see [Configuration](#configuration)) and the same pin for every operation of the batch (a batch already pinned keeps its
`until`). The window therefore bounds the time pinned from the **first** ambiguous failure: with `request_timeout_ms >=
ambiguous_retry_window_ms` (the defaults), a second timeout of the retry on its node is an immediate, counted failover.

- While some operation of the lane is pinned, the bucket is eligible only for those operations once due, `slice` takes exactly them and
  `nextDue` is their `notBefore`. The sender admits only the pinned node for that batch; if it is not usable (`Down`, a `notBefore` in
  force or a full window) the batch waits in the lane (`{false, At(pinUntil)}`) and the bucket is recorded in `pinnedWaiting[node]`.
- When the node **comes back** (the `Down` mirror clears, its `notBefore` timer fires or a slot frees) the sender calls
  `Bucket::pinnedNodeUsable(node, now)` and the retry goes **to that node**: if it applied the first request, the item answers as the
  indexer decides (for example a version conflict), and the order is kept.
- When `until` passes, any node may take the batch: the pin is cleared and the **failover is counted** (`orderedAmbiguousFailover`,
  per operation, only when the node is another one).
- Every completion with an HTTP response removes the pin (`ResponseTooLarge` included: the node answered). A failure **before** sending
  (`mayHaveSent` false, for example connection refused) does not pin: failover at once as in an unordered bucket
  (`OrderedFailureBeforeSendFailsOverAtOnce`). Unordered buckets ignore the pin.
- **TLS.** A TLS failure with `mayHaveSent` is a `Failover` and pins like any other: an indexer node with a wrong mTLS setup costs
  one ambiguous window per batch in an ordered bucket before the counted failover. This is the written behaviour; it has no test of its own.
- **Counters** (`BucketStats`): `orderedAmbiguous` counts operations pinned (per operation and per pin), `orderedAmbiguousFailover`
  operations sent to another node once the window ended (counted at dispatch, so a batch the pool task then drops still counts).

**Residual risk.** After the window the batch goes to another node while the first one may still apply the older request later, so
the final state of a key can be an older one. The library cannot close that window; the consumer mitigates it with its own sweep
(inventory sync, with its `sync.agent_delete.sweep.residual` metric), which is outside this library.

### Cancellation

`Writer::cancel(tag)` returns a `CancelTicket` and never blocks (valid from any thread, runtime threads included).
The normative text is `src/write/bucket.hpp` (CANCELLATION) and `src/write/sender.hpp`.

- **Per bucket.** `Op::tag` (for example the agent id) is stored with the operation; `cancel` acts on the **writer's bucket**
  only, not on the whole client. The tag is never part of the wire lines.
- **What it reaches.** Pending operations and the retry lane (removed and resolved `Dropped(Cancelled)` at once, also the ops of a
  **committed** group, which are ordinary pending ones), and operations already **in flight**, which are marked. A group in `Building` is not
  reached (its operations are outside the queue until `commit`).
- **In flight.** A marked operation is never requeued: if its bulk fails or would retry or exhaust, it resolves `Dropped(Cancelled)`
  (the cancellation wins, `RequeueResult::cancelled`); if its bulk **succeeds**, it resolves as the indexer answered, so `Ok` stays `Ok`.
- **0 sends after `cancel`.** Before assembling a body the sender's pool task removes the marked operations from the batch (operations and
  bytes, so item *i* still matches operation *i*) and resolves them `Dropped(Cancelled)`; a batch left empty gives its slot back and sends
  nothing (`CancelSlicedBeforeSubmitNotSent`, through the test seam `beforeAssembly`).
- **The ticket.** `CancelTicket::ready()` is true at once when no operation of the tag was in flight; otherwise it completes (success) when
  the last of those has resolved, counted by `releasePayload`, the single decrement point. `wait` from a runtime thread returns
  `Reentrancy`. A second `cancel` of the same tag registers its own waiter; operations of the tag submitted **after** the cancel are not
  counted. A bucket destroyed with waiters fails them `ClientClosed`.
- **A valid tag** is at most 256 bytes (`MAX_TAG_SIZE`) with no control character (bytes below 0x20 or 0x7f). On `submit` and
  `Group::add` an invalid tag is `InvalidArgument` (`tag: ...`, never echoing the tag); an **empty** tag means "no tag" and is
  accepted there, but `cancel("")` is refused `InvalidArgument` because it would match every untagged operation.
- **Counter.** `BucketStats::cancelled` counts the operations resolved `Dropped(Cancelled)`, and they are also in `resolvedDropped`; the
  invariants of [Groups](#groups) are unchanged. Cancelling an ordered bucket tells the scheduler, because removing lane operations
  can lift a key block or a pin.

## Load control

The [bulk sender](#bulk-sender) limits its own load per node. Two independent mechanisms act on every node: an adaptive
**window and bulk-size target**, and **pacing**. `src/write/sender.hpp` (block "Limiter") is normative; this section is the summary.
All the state is per node, under the sender's mutex. Options: `node_window_max`, `bulk_min_bytes`, `latency_target_ms`,
`pace_initial_ms`, `pace_relax_after`, `retry_after_max_ms` and `drr_quantum_bytes` (see [Configuration](#configuration)).

**A usable node** is one predicate, used by `capacity()`, the filter of `choose` and the wake-up of pinned batches:
`!down and notBefore <= now and nextSendAt <= now and inFlight < floor(window)`.

**Window.** A real number in [1, `node_window_max`] per node (AIMD). It **starts at `node_window_max`** and:

- **halves** (`window = max(1, window / 2)`, once per burst) on a request-level 429, on a p95 of the node's latencies above
  `latency_target_ms`, or when the `NodeSet` moves the node to `Throttled`;
- **grows by `1 / window`** (up to `node_window_max`) on each 2xx whose latency is below `latency_target_ms`;
- is **kept** when the node goes `Down` and comes back `Available`.

A `node_window_max` above 8 per network thread (`CURLMOPT_MAX_HOST_CONNECTIONS`) opens no more connections to a node: the extra
requests wait inside curl for a free connection, while the sender counts them in `inFlight`.

*Once per burst:* a decrease applies only to a request sent after the previous decrease (`sentAt > lastDecreaseAt`), so the
requests of one window that return 429 together halve it once. The `Throttled` transition (hook) decreases only when something was
sent since the last decrease: the bulk 429 that caused the transition already did, a probe or query 429 has not. *Latency:* the
sender keeps the last 32 `timings.total` of the HTTP responses of the node (429 included) whose request was sent after the last
decrease; the p95 is `sorted[ceil(0.95 * n) - 1]` and decides only with `n >= 8`; a decrease for latency empties the ring, and the
requests still in flight when it happened do not refill it, so a latency spike costs one halving. A 2xx raises the window
only if it was sent after the last decrease and no decrease happened in the same completion (the decrease is evaluated first).

**Bulk target.** Per node, in bytes; 0 means uncapped, which is the start.

- A decrease sets `bulkTarget = max(bulk_min_bytes, (bulkTarget ? min(bulkTarget, b) : b) / 2)`, with `b` the bytes of the batch
  whose response caused it (the last batch sent, for the `Throttled` hook).
- Recovery: each qualifying 2xx adds `max(bulk_min_bytes, bulkTarget / 4)` to a capped target; on reaching 64 MiB
  (`BULK_TARGET_UNCAPPED`) it becomes 0 again, so there is no cap above that.
- A **413** splits the batch as before and also sets `bulkTarget = min(bulkTarget or infinity, bytes / 2)`; it does not touch the
  window and is not counted as a decrease.
- **Batch cap.** `BatchSink::batchLimit()` returns the smallest capped target among the usable nodes (0 when none is capped); the
  scheduler passes it to `Bucket::slice` as `cap`, another `min` next to `bulk.maxBytes` and `batchCap`. It is the smallest of the
  usable nodes, not the chosen node's, because the node is chosen after the batch is formed. The **first operation of a batch
  always goes out**, whatever the cap, so a document larger than the target is still sent.

**Pacing.** A minimum interval between sends to a node that does not depend on the window.

- The first request-level 429 (with or without `Retry-After`) sets `pace = pace_initial_ms`; each later burst of 429 doubles it, up
  to `retry_after_max_ms`.
- When a send takes a node's slot with `pace > 0`, `nextSendAt = now + pace`, and the node is not usable until then. `capacity()`
  counts 1 for such a node (one send per interval) and the sender's timer is armed at the earliest `notBefore` or `nextSendAt` in
  force.
- A 2xx of a request sent after the burst marker (the last bulk 429 that doubled `pace` or raised `notBefore`) counts a clean send; every `pace_relax_after` clean sends halve `pace`
  (the count restarts), and a `pace` below `pace_initial_ms` becomes 0. A 429 resets the count.
- `Retry-After` is handled as before: `notBefore = max(notBefore, now + max(Retry-After or 0, pace))`. A 2xx never shortens a
  `notBefore` or a `nextSendAt` in force.

**What never moves the limiter.** Item-level rejections inside a 2xx (including items answered 429) and transport failures
(timeout, connect, TLS, cancellation: those are `Down`, not load).

**Queries**: they never take a window slot, so a full bulk window does not delay a query.

**`senderStats()`.** Per node, besides the fields of the [bulk sender](#bulk-sender): `window` (real), `bulkTarget` (0 =
uncapped), `nextSendAt` (only when in force), `p95` (0 below 8 samples), `decreases429`, `decreasesThrottled`, `decreasesLatency`,
`increases` and `paceRelaxed`. The [metrics](#metrics) publish them (`NodeMetrics`).

## Closing and shutdown

The normative text is the "Close" block of `src/write/writer.hpp`, the admission block of `src/write/bucket.hpp` and the close-order
note of `include/indexer_client/client.hpp`; this section is the summary.

**`requestClose()`** marks the client, wakes its queries and blocked producers (`ClientClosed`) and closes only the **admission**
of its buckets (`Bucket::closeAdmission`): later `submit` calls return `ClientClosed`, `writer()` and `query()` return `nullptr`.
What is already queued is not dropped: `flushSeq = nextSeq - 1` makes every pending operation eligible now, as a `commit()` does, the
scheduler is notified, and the buckets stay in the DRR ring and keep draining. A requeue retries as usual (only `Bucket::close()` hands
operations back as closed). It never blocks and is valid from any thread. A `submit` or `post` racing the close either was queued
before it (and drains) or is refused with `ClientClosed` (nothing charged, no ticket, no callback): `Bucket::admit` reserves and
queues under one take of the bucket's mutex, so every `submit`/`post` that starts after `requestClose()` returns is refused.
A group's `commit()` racing the close is the one window left: with the admission closed `enqueueGroup` takes custody of its
operations without queuing them and the group resolves only those (`Dropped(ClientClosed)`); it never calls `close()`.

**`awaitClosed(D)`** is for consumer threads (from a runtime thread it returns `Reentrancy` without draining). Calls are serialized
per client: a concurrent call waits for the first one; a later one sweeps nothing, waits for the completions until its own `D`, moves
the cutoff to now again and returns the live counters (`callbacksSkipped`, `callbackOverruns` and `drained` may have grown). With
`left = max(0, D - now)` and `callbackBudget` = `callback_budget_ms`:

| `left` | `drainEnd` (end of the drain) | `cutoff` (no callback starts after it) |
|---|---|---|
| `>= 2 * callbackBudget` | `D - 2 * callbackBudget` | `D - callbackBudget` |
| otherwise (short or past deadline) | `now + left / 2` | `now + 3 * left / 4` |

1. **Drain.** It waits until the client's buckets retain nothing (pending, retry lane and delivered all at 0) or `drainEnd`. The drain
   honours the node pace, `notBefore` and the bucket backoff: it sends nothing earlier than a normal send would.
2. **Sweep at `drainEnd`.** The bucket is closed (`close(ClientClosed)`): what is still pending or in the retry lane resolves
   `Dropped(ClientClosed)`, what was delivered to the sink resolves `Dropped(Shutdown)` — except a delivered operation whose answer
   reaches the requeue between the close and the sweep's resolution of it: the bucket hands it back closed and it resolves
   `Dropped(ClientClosed)` (first resolution wins; either way it is counted once). Outside a runtime shutdown the transfers of
   those delivered operations are cancelled (`BatchSink::cancelBucket`); in a runtime shutdown `transport->stop` bounds them.
   The sweep and `cancelBucket` run outside `ClientState::completionsMutex`.
3. **Completions.** It then waits for the client's outstanding completions until `D`, and sets the client's callback cutoff to now.
   A resolution counts in the client (`drained`, `dropped*`) and its completion is outstanding **before** its payload stops being
   retained, so a drain that ends at zero retained never leaves the last completion out of this wait.

**Callback boundary.** `CallbackCompletion::run` takes `ClientState::completionsMutex`, compares now with
`min(client cutoff, WritePath::callbackCutoff())`, marks itself started or skipped and releases the mutex before calling the
callback; `awaitClosed` moves the cutoff under the same mutex before it reads the count of started-and-not-finished callbacks, so no
callback of the client starts after `awaitClosed` returns. Lock order: `completionsMutex`, then the bucket mutex.

Past the cutoff the completion still completes the `Ticket` and counts the result in the bucket, but **the callback is not called**
and `callbacksSkipped` grows. The contract for consumers: a consumer that needs every result at close keeps its `Ticket`, or reads
`callbacksSkipped > 0` as "results unknown".

**`CloseReport`** (counters are read live on each `awaitClosed`):

| Field | Meaning |
|---|---|
| `callbacksInFlight` | Callbacks started and not finished when `awaitClosed` returned |
| `droppedClientClosed`, `droppedShutdown` | Operations of the client resolved `Dropped(ClientClosed)` and `Dropped(Shutdown)` |
| `callbacksSkipped` | Completions past the cutoff: `Ticket` complete, callback not called |
| `callbackOverruns` | Callbacks whose duration exceeded `callbackBudget` |
| `drained` | Operations resolved after `requestClose()` that are not `Dropped(ClientClosed)` or `Dropped(Shutdown)` (those come only from a sweep, a refused group commit or a requeue into a closed bucket), so `drained + droppedClientClosed + droppedShutdown` covers every operation resolved after `requestClose()` |

**Callback duration.** Every callback is timed; one longer than `callbackBudget` adds 1 to `callbackOverruns` and updates
`ClientState::callbackMaxDurationMicros`. `callbackOverruns` is in the `CloseReport`; the maximum is only in `ClientState` (no
`CloseReport` field, the metrics publish both ([metrics](#metrics) and the [overrun summary](#log-lines)). `Dropped(QueueFull)` has no field of its own.

**Destructor.** `~Client` on a consumer thread is `requestClose()` plus `awaitClosed()` with the shutdown deadline (or the default).
On a runtime thread (also move-assignment over a live `Client` there) it does not wait: `requestClose()` plus the
immediate sweep (`closeClient(client, true)`: `close(ClientClosed)` and pending and lane operations resolved `Dropped(ClientClosed)`;
delivered ones keep their course), counted as a usage error, so a usage error never loses a result.

**Runtime shutdown.** `RuntimeOwner::shutdown()` reaches `WritePath::stop(callbackCutoff)`: the runtime-wide callback cutoff
(`stopDeadline - callbackBudget`) is set first, so the completions the pool still runs afterwards only complete tickets once past it,
the common boundary above. During `stop()` every resolution is `Dropped(Shutdown)`: every bucket closes, the sweep of pending, lane
and delivered operations and the requeues of a bucket that was draining all use `Bucket::sweepCause()`; the admission cause stays
`ClientClosed` for `submit`. The order of the rest of the shutdown is unchanged (scheduler, `sink.stop()`, prober, transport, loops,
CPU pool).

**Close order of a process** (note in `client.hpp`), all on the owner thread:

```text
RuntimeOwner::beginShutdown(deadline)
  each consumer's stop: Client::requestClose()   admission closed, the queue keeps draining
                        join the consumer's own threads
                        Client::awaitClosed(RuntimeRef::shutdownDeadline())
RuntimeOwner::shutdown()
```

What is queued drains until `awaitClosed`'s deadline minus twice `callbackBudget`; past it the rest is dropped and no callback starts
(the `CloseReport` tells how many were skipped).

## Queries

`Client::query()` returns the `IQuery` of the client: `search`, `searchAfter`, `deleteByQuery`, `updateByQuery` and `indexExists`
and `pit()` (see [Point in time](#point-in-time)). The contract is the header `src/query/query.hpp` (normative); the pure response classifiers are in
`src/query/queryResponse.hpp`. Nothing there is public API.

### Execution model

Every operation runs **synchronously on the calling consumer thread**. No runtime thread runs a query and no task is posted for it,
so a query never blocks the IoLoops or the CPU pool. In order:

1. Called from a runtime thread (`onRuntimeThread()`): `Reentrancy`, before anything else.
2. Validation, without a request: `InvalidArgument` with the field first in `reason`.
3. The client closed: `ClientClosed`; its runtime gone or of another epoch: `Shutdown`.

The `IQuery` belongs to its `Client`: destroying the `Client` closes it (`~Client` = `requestClose()` + `awaitClosed()`), and every later
call on a query obtained from it returns `ClientClosed`. Keep the `Client` alive for as long as its queries are used.

### Clocks

| Clock | Bounds | Notes |
|---|---|---|
| `Deadline` | The whole call | Never an HTTP timeout. When it expires with an attempt in flight the engine cancels the transfer (`Cancelled`, never attributed to a node) and returns `Unavailable` with reason `deadline expired, last cause: ...` |
| `QueryOptions.pageDeadline` | Each page (one search, one DBQ, ...) from its first attempt, waits included | The clock starts when the page's first attempt is submitted; a wait for a usable node before it counts only against the `Deadline`. Expiry returns `Unavailable` with reason `page deadline expired, ...` |
| HTTP timeout | One attempt | `min(RuntimeConfig.requestTimeout, what is left of the page)` |

The consumer's `Deadline` **never marks a node `Down`**. A `Timeout` reaches `NodeSet::report` (the node goes `Down` and the next
attempt fails over) only when the attempt had the whole per-attempt budget `min(requestTimeout, pageDeadline)`: the page's first
attempt always has it, and so has a later one while at least `requestTimeout` of the page is left. A `Timeout` of an attempt whose
budget the page cut short is the page's own clock: it is not reported and the call returns `Unavailable` `page deadline expired`.
An attempt with the whole budget waits `TIMEOUT_GRACE` (1 s) past the page for curl's own `Timeout`, never past the `Deadline`: with
the defaults (`pageDeadline` 30 s < `requestTimeout` 60 s) a hung node is reported `Down` by the query that hit it, which then returns
`Unavailable` (its page is spent); the next query chooses another node.

### One attempt

The engine takes the transport and the `NodeSet` of the client's epoch (a null one is `Shutdown`; neither is held past the attempt),
calls `NodeSet::choose()` and submits `HttpRequest{url = host + route, timeout}`. It then waits on the runtime's `QueryGate` (one
mutex and condition variable shared by the runtime and all its clients; the transport callback captures the attempt state by
`shared_ptr`, so it may land after the engine returned). The result is reported to the `NodeSet` (passive signals, see
[Node health](#node-health)) and classified by `classifyRequest(result, 1)` and then by the operation's classifier.

**One attempt, one transmission.** A `deleteByQuery` or `updateByQuery` with `retry.maxAttempts == 1` submits every
request with `freshConnection` ([Transport](#transport-internal)): libcurl's own resend of a request whose reused
connection died without an answer happens inside one submission, out of reach of `maxAttempts`, `maxDuration` and
`conflictAttempts`, and would deliver the same mutation twice; on a fresh connection it never happens. Each request
costs one TCP/TLS handshake (the inventory sync sweep sends at most `2 * ceil(n / 10 000)` per pass). Reads (search,
count, PIT) and any other `maxAttempts` keep connection reuse and curl's resend, which is harmless for them.

With **no node to choose**, the engine waits `max(50 ms, min(retry.base, probeInterval))` and chooses again, without spending an
attempt; when the not-`Down` nodes are all parked by a 429 `Retry-After` ([Node health](#node-health)), the wait ends at the first `notBefore` if that is sooner, so the read waits for that node within its deadline instead of `Unavailable`. It ends by `Deadline` (once the page has made its first attempt, also by the page deadline, or by `retry.maxDuration` with
`RetryExhausted`), never by a busy wait.

### Retry

| Verdict | Action |
|---|---|
| Failover | Another attempt at once; counted only when the request may have been sent |
| Throttled (429) | Waits `max(Retry-After, backoffDelay(retry, ++throttles))` without an attempt; `throttles` grows the exponent, so a storm of 429 without `Retry-After` backs off |
| Retry (408, 5xx, 401, 403, TLS configuration, local error, `timed_out`) | An attempt, then `backoffDelay(retry, attempts)` (`src/runtime/backoff.hpp`) |
| `maxAttempts` or `maxDuration` (from the page's first attempt) exhausted | `Failed(RetryExhausted)`, the last cause in `reason`. `maxDuration` is checked **before** every wait and every send: a backoff (Retry or Throttled) that would end at or past `first attempt + maxDuration` is not slept, the call ends `RetryExhausted` at once (as the 5.0 connector did), and no attempt starts past that point, also after a wait for a usable node |
| Fail | Its own cause (see [Causes](#causes-of-a-query)) |
| Conflict (DBQ/UBQ) | Its own budget, below |

### Conflicts of `deleteByQuery` and `updateByQuery`

A 2xx whose `failures` are all `version_conflict_engine_exception` / 409, or with `version_conflicts > 0`, is a conflict. The budget is
`QueryOptions.conflictAttempts` attempts (default `CONFLICT_ATTEMPTS = 3`, must be > 0; `1` never resends a by-query on a conflict)
with a wait of `CONFLICT_BASE = 3 s`, doubled up to `CONFLICT_CAP = 15 s`. Each conflict retry opens
a **fresh retry series** (independent clocks). Exhausted: `Failed(VersionConflict)` with the counts in `reason`. Any other `failures`
entry is `Failed(ItemPermanent)` with the first one in `reason`; `timed_out` is a Retry under the retry rules.

### Routes

`QueryOptions.expandWildcardsAll` adds `expand_wildcards=all` to every route below, `HEAD` included. `DbqOptions.proceedOnConflicts`
(default `true`) controls `conflicts=proceed` in `deleteByQuery`.

| Operation | Method and route | Body | Success | 404 |
|---|---|---|---|---|
| `search(index, body)` | `POST /<index>/_search` | `body` | The whole response (`Outcome<json>`) | `index_not_found_exception`: `NotFound`; any other: `Client4xx` |
| `searchAfter(index, body, page)` | `POST /<index>/_search`, one per page | `body` with `search_after` | `Ok` when it stops (below) | As `search` |
| `deleteByQuery(indices, query, dbq)` | `POST /<i1,i2>/_delete_by_query[?conflicts=proceed]` | `query` | The response | `index_not_found_exception`: `Ok({})`; any other: `Client4xx` |
| `updateByQuery(indices, query)` | `POST /<i1,i2>/_update_by_query?conflicts=proceed` | `query` | The response | `index_not_found_exception`: `NotFound`; any other: `Client4xx` |
| `indexExists(index)` | `HEAD /<index>` | none | `200`: `true` | `false` |
| `pit(indices, pitOptions)` | `POST /<i1,i2>/_search/point_in_time?keep_alive=<ms>ms` | none | A `Pit` handle | `index_not_found_exception`: `NotFound` (see [Point in time](#point-in-time)) |

### `searchAfter`

`body.sort` must be a non-empty array and `body.size` an integer greater than 0, otherwise `InvalidArgument` without a request. The
callback `page(response)` runs on the consumer thread for **every** page, the empty one included; an exception from it propagates and
leaves no request pending. Pagination stops when:

- `page` returns `false` (result `Ok`);
- a page has no hits;
- a page has fewer hits than `size`;
- the last hit has no `sort`.

Otherwise the next page is the same body with `search_after` set to the `sort` of the last hit. A page that fails returns its cause.

### `indexExists`

`HEAD /<index>`: `200` is `true` and `404` is `false`; every other answer follows the retry table. An outage is **never** `false`: it
ends in `Unavailable` or `RetryExhausted`.

### Response cap

A 2xx body with `body.size() * QUERY_DOM_FACTOR > maxResponseBytes` is `Failed(ItemPermanent)`, reason `response too large for a query`,
**without parsing it**: parsing builds a DOM several times larger than the wire body. The effective wire cap of a query is therefore
`maxResponseBytes / QUERY_DOM_FACTOR`, that is 8 MiB with the default 64 MiB: `QUERY_DOM_FACTOR = 8` is `ceil(6.19 × 1.25)`, the worst
DOM-to-wire ratio `QueryDomFactorMeasured` found (glibc heap in use: inventory-sync checksum page 6.19, vulnerability-scanner packages page
5.74, delete/update-by-query responses 3.5–5.2). An unparsable 2xx body is also `ItemPermanent`. The reason of a 4xx is the OpenSearch error type
plus at most `REASON_BODY_BYTES = 256` bytes of the body, within `OpResult::MAX_REASON`.

A failure for size — this cap, or a body over `maxResponseBytes` on the wire (`ResponseTooLarge`, one op ⇒ `FailBatch(ItemPermanent)`,
reason `response over maxResponseBytes`) — also sets `Outcome::responseTooLarge`, through every query that returns one (`search`,
`searchAfter`, `Pit::search`, `PitSession::next`). The cause stays `ItemPermanent` and the library never retries it; the flag only lets a caller
tell it from the other `ItemPermanent` failures without parsing the reason (the content manager's paginator halves its page on it). An
unparsable body leaves it false.

**Whole cap for a PIT.** A PIT opened with `PitOptions::wholeResponseCap` checks its pages (`Pit::search`, `PitSession::next`)
against `maxResponseBytes` itself, not `maxResponseBytes / QUERY_DOM_FACTOR` (`classifyPitSearch(..., wholeResponseCap)`); since the
transport already stops reading at `maxResponseBytes`, the 2xx check never trips there and a page over it fails on the wire as above. Only
the content manager asks for it, for the CTI content pages (one CVE5 document reaches ~17 MB); every other query keeps the standard cap. A page near the
cap parses into a DOM up to `QUERY_DOM_FACTOR` times its size (the `responseBytesInFlight` gauge shows the wire bytes).

### Close and shutdown

Every wait (result, backoff, no node) sleeps on the `QueryGate`. The transport callback, `Client::requestClose()` and
`RuntimeState::stopAndJoin()` (before the write path stops; it also sets `stopping`) notify it. Woken by a close, the engine cancels
the attempt in flight and returns `ClientClosed` (`Shutdown` when the gate is stopping). There is no busy wait.

### Index validation

Every index must be non-empty, made only of `[A-Za-z0-9_.*-]`, not made only of dots (libcurl collapses `.` and `..` path segments,
so `..` would reach `/_delete_by_query` of every index) and not start with `_` (`_all`, an endpoint); the list of a DBQ/UBQ must not be
empty. Also validated, with the same rules as a bucket's `RetryPolicy`: `retry.base > 0`, `retry.cap >= retry.base`,
`retry.jitter` in `[0, 1]` (NaN refused), `retry.maxAttempts > 0` or unset, `retry.maxDuration > 0` or unset, `pageDeadline > 0`, `conflictAttempts > 0`. Failures are `InvalidArgument` with the field first in `reason`, and no
request is made.

### Causes of a query

| Situation | `Cause` |
|---|---|
| Deadline or page deadline expired, no usable node until then | `Unavailable` |
| The transport refused to admit the request (reason `the transport refused the request`) | The transport's admission cause (`InvalidArgument`, `InvalidState`) |
| `maxAttempts` or `maxDuration` exhausted (503, 429 storm, timeouts) | `RetryExhausted` |
| `search`/`updateByQuery` on a missing index (`index_not_found_exception`) | `NotFound` |
| Any other 4xx (400, any other 404, ...) | `Client4xx` |
| Unparsable 2xx, response over the cap, DBQ/UBQ `failures` that are not conflicts | `ItemPermanent` |
| DBQ/UBQ conflicts after the budget | `VersionConflict` |
| Unsafe or empty index, empty list, invalid `retry` or `pageDeadline`, `searchAfter` without `sort` or `size`, `searchAfter` with an empty `page` (`page: must be callable`) | `InvalidArgument` |
| Called from a runtime thread | `Reentrancy` |
| The client closed (`requestClose()` or `awaitClosed()`), during or before the call | `ClientClosed` |
| The runtime shut down or of another epoch | `Shutdown` |

### `queryStats()`

`detail::query::queryStats()` returns process-wide counters since the process started, never reset (they survive `shutdown()` +
`start()`): `requests`, `failovers`, `throttles`, `unavailable`, `tooLarge` (responses the classifier refused for size) and
`conflictRetries`. They are published as `indexer_client.query.*` ([metrics](#metrics)); they are process-wide and never reset.

## Point in time

`IQuery::pit(indices, PitOptions, QueryOptions, deadline)` creates a managed PIT and returns a `Pit` handle; `Pit::cursor` and
`Pit::search` read through it, and the library deletes it when the last handle goes. The contract is the header `src/query/pit.hpp`
(normative); every PIT request runs through the same attempt loop as the queries (`execute()` in `src/query/engine.hpp`) with the
`QueryOptions` given to `pit()`: the same [clocks, retry verdicts and wake-ups](#queries). Nothing there is public API.

### Creation

`pit()` runs on the calling consumer thread. Order: `Reentrancy` from a runtime thread; validation without a request
(`InvalidArgument` with the field first: the indices as in [Index validation](#index-validation), `keepAlive > 0`, the `QueryOptions`
checks); then

`POST /<i1,i2>/_search/point_in_time?keep_alive=<ms>ms&allow_partial_pit_creation=false[&expand_wildcards=all]`, no body.

`PitOptions.keepAlive` (default 300000 ms) is sent in milliseconds. `allow_partial_pit_creation=false` is always sent: OpenSearch
defaults it to `true` and would create a PIT missing an unavailable shard, whose pages then miss that shard's documents with no shard
failure to show it (the pages' `allow_partial_search_results=false` only covers the shards the PIT holds). `expand_wildcards=all` is added when `PitOptions.expandWildcardsAll`
or `QueryOptions.expandWildcardsAll` is set. `PitOptions.wholeResponseCap` (default false) is not sent: it sets the
[response cap](#response-cap) of the PIT's pages. A 2xx needs a non-empty string `pit_id`, otherwise `Failed(ItemPermanent)`; a 404
`index_not_found_exception` is `NotFound`; the rest follows the [retry table](#retry). A 2xx whose `_shards.failed` is
above 0 (a partial PIT the indexer created anyway) is never accepted: it is a **retry** under the same budget (reason
`<status> partial PIT: <n> shards failed`), because an unavailable shard (a relocation, a restarting node) is usually transient, and
the PIT it names exists, so the registry deletes it like a released one (below).

### Slots and the cap

`max_open_pits` (default 64, see [Configuration](#configuration)) bounds, per runtime, the PITs open **plus** the reservations below.
Before **every attempt** of a creation the engine takes one slot from the registry; with none free the call ends `QueueFull`
(reason `too many open PITs (N)`, N = open + reserved + slots held by creations in flight) without a request, counted in `refusedFull`. The slot of each attempt is settled when the attempt ends:

| How the attempt ended | The slot |
|---|---|
| 2xx with a `pit_id`, accepted | Becomes the PIT's (open) |
| 2xx with a `pit_id`, refused (partial) | Becomes an open PIT (`created` + 1) whose DELETE is queued at once (`PitRegistry::discard`); freed when the delete is confirmed or expires |
| Any other 2xx (over the [response cap](#response-cap), unparsable, without a usable `pit_id`) | **Reserved** until `now + keepAlive`, like an unknown outcome: the indexer created a PIT the library cannot address (an orphan until its `keep_alive`), so it keeps counting against the cap. With a tiny `max_response_bytes` every creation ends here, and the cap still bounds the orphans |
| Any other HTTP answer (404, a 4xx or 5xx) | Released |
| Transport failure with `mayHaveSent`, or abandoned (deadline, close, shutdown) | **Reserved** until `now + keepAlive`: the PIT may exist on the indexer (an orphan until its `keep_alive` frees it), so it keeps counting against the cap |
| Transport failure without `mayHaveSent` | Released |

A result that arrives late (after the engine stopped waiting) changes nothing: the reservation stays until it lapses. Lapsed
reservations are purged on every acquisition and on every statistics read. A wait for a usable node is not an attempt: the creation
keeps its slot through it (up to its deadline), whereas a backoff after a settled attempt (429, 5xx) holds none and the next attempt
acquires again.

### Shared state and threads

`Pit` is copyable and `Pit`, its copies and every `PitSession` share one internal state: the current `pit_id`, `keepAlive`, the
`generation` (a process-wide counter, `Pit::generation()`), the expired flag, the time of the last request, the `QueryOptions` of `pit()` and
the indices. `cursor()`, `next()` and `search()` are safe from different threads (a consumer may page up to 32 slices at once, one cursor each).
**One `next()` at a time per cursor**: a `PitSession` and its copies are one sequence of pages, each continuing from the previous page's
`search_after`, so a `next()` called while another one is in progress on the same cursor fails at once with `InvalidState` (`another
next() is in progress on this cursor`) and sends nothing; it does not wait for the other page, which could outlast its `Deadline`.
Different cursors never wait on each other. The state holds the
`Client`, so **the consumer name stays reserved while any `Pit` or `PitSession` is alive**: a new `RuntimeRef::client` with that name is
`InvalidArgument` (`already has a live client`). A default-constructed `Pit` or `PitSession` answers `InvalidState` on `cursor()`/`next()`/`search()`, never a crash.

### Cursors

`Pit::cursor(CursorQuery, std::optional<Slice>)` returns a `PitSession`; each `next(deadline)` is one request:

`POST /_search?allow_partial_search_results=false`

with the body:

| Member | Value |
|---|---|
| `size` | `CursorQuery.pageSize` |
| `query` | `CursorQuery.query`; defaults to `{"match_all":{}}` (an empty query is a 400 in OpenSearch 3.6) |
| `sort` | `CursorQuery.sort`; empty means `[{"_shard_doc":"asc"}]` |
| `_source` | `CursorQuery.source`, only when not null |
| `slice` | `{id, max}` when a `Slice` was given |
| `pit` | `{id, keep_alive: "<ms>ms"}` on every request, which renews the PIT |
| `search_after` | The `sort` of the previous page's last hit; absent on the cursor's first page, which sets `track_total_hits: true` instead |

- **Tiebreaker.** The default `_shard_doc` is unique within a PIT. A `sort` of the consumer gets **no tiebreaker added**: if it is not
  unique, hits that tie can be skipped or repeated across pages, and adding `_shard_doc` last is the consumer's job.
- **`PitPage`.** `generation` (the PIT's, unique per process), `hits` (the `hits.hits` array), `last` and `total`. `total` is `hits.total.value` and is set
  **only on the cursor's first page**; later pages leave it empty.
- **`last`** is true when the page has fewer hits than `pageSize`. `next()` after `last` returns `Ok` with an empty page, `last` set, and
  **sends nothing**; `exhausted()` tells it.
- **Retries.** The body of a page is built once: a retried page repeats the same `pit` id and the same `search_after`.
- **Invalid cursor.** `slice.max < 2`, `slice.id >= slice.max` or `pageSize == 0` are not refused by `cursor()`: the first `next()`
  returns `InvalidArgument` with the field (`slice.max: must be >= 2`, ...), without a request.

`Pit::search(body, deadline)` sends the consumer's body to the same route with its `pit` member **overwritten** by `{id, keep_alive}`;
nothing else is touched. It returns the whole response.

### `pit_id` renewal

A 2xx whose `pit_id` differs from the current one replaces it (the last arrival wins: every id of the same PIT addresses the same
contexts). The delete uses the id that is current when the last handle goes.

### Expiry

A PIT is expired when a search answers

- a 404 whose `error.type` or any `error.root_cause[].type` is `search_context_missing_exception`, or
- a 2xx with `_shards.failed > 0` and that type in `_shards.failures` (with `allow_partial_search_results=false` the indexer may answer
  this way); a 2xx with a shard failure of **any other type** is a retry, not an expiry.

The state is marked expired once and **every** handle gets `PitExpired`: the failing call, a call that was asleep in a backoff (the
engine checks before each attempt), and every later `next()` or `search()`, which return without a request. A 2xx that lands after the
PIT was marked expired is discarded: `PitExpired`, counted in `stale`. **The library never recreates a PIT**; the consumer restarts its
whole query with a new `pit()`.

### Lifetime and delete

The registry keeps the PIT while any handle lives. When the last `Pit` or `PitSession` goes (on any thread, never blocking) the
registry receives `{id, keepAlive, lastUse}` and sends

`DELETE /_search/point_in_time` with `{"pit_id": "<id>"}`

through the transport (`NodeSet::choose()`, callback on the CPU pool). `lastUse` is the time the last request was **observed sent**,
so it is an upper bound of the real last use. Classification is `classifyRequest(result, 1)`:

| Result | Action |
|---|---|
| 2xx whose `pits` entry for the id (or, when no entry names it, any entry) has `successful: false` | **Not** confirmed: OpenSearch reports a failed delete that way (partial failures are failures) and the context may still be open. Retries after `backoffDelay` like a failover (`deleteRetries`), until `lastUse + keepAlive` at most |
| Any other 2xx (a body without a readable `pits` array included, so a change of shape never turns deletes into retries), or 404 | Confirmed (`deletesConfirmed`); the slot is freed |
| 429 | Waits `max(Retry-After, backoff)` and retries |
| Failover or retry verdict | Retries after `backoffDelay` (1 s base, 15 s cap, `deleteRetries`) |
| No usable node | Waits `min(backoff, probe_interval_ms)`, without counting a retry; shortened to the first parked node's `notBefore` when every not-`Down` node is parked |
| Any other final answer (another 4xx, a response too large) | Gives up at once: the `keep_alive` frees the PIT (`deletesExpired`); the slot is freed |
| `lastUse + keepAlive` passed | Gives up: the indexer frees the PIT by itself (`deletesExpired`); the slot is freed |

What OpenSearch answers to the `DELETE` of a PIT that is already gone (expired or deleted: a 404, or a 2xx with `successful: false`)
has **not** been measured against a real node. If it is a 2xx with `successful: false`, such a delete is retried until
`lastUse + keepAlive` and then counted expired: bounded, and never a delete wrongly counted as confirmed.

Each `DELETE` is sent with timeout `min(request_timeout_ms, lastUse + keepAlive − now)` (the sum saturates: `keepAlive` has no upper
bound), so a hung one never holds the slot past the PIT's own expiry.
Retries run on a timer of network loop 0, and `release` is idempotent per id. While a delete waits to be confirmed or to expire, its slot
still counts against `max_open_pits`. A runtime that is gone does nothing: a `PitState` whose registry has died leaves the PIT to its
`keep_alive`.

### Shutdown

`RuntimeState::stopAndJoin` calls `drain(shutdownDeadline − min(DRAIN_STOP_MARGIN, (shutdownDeadline − now) / 2))` (the margin is
1 s, or half of what is left when the deadline is closer: a short `drain_ms` still sends the deletes) after the write path stops and
before `transport->stop()`. The drain sends **every pending delete at once** with timeout `min(request_timeout_ms, drainEnd − now)`
and waits for them; at `drainEnd` the rest are cancelled and counted `deletesExpired`. During the drain there are **no retries**: a
delete that fails is not repeated. PITs whose handles are still alive are deleted too (the registry keeps a weak reference to each open
PIT); their state is marked drained, so the later hand-over of their last handle does nothing and any later request on them returns
`Shutdown`. A creation that completes after the drain started is marked drained the same way: its delete joins the drain if it is
still before `drainEnd`, otherwise it counts as expired without a request. A PIT released after the drain is treated as expired
without a request.

### `pitStats()`

`detail::query::pitStats()` returns process-wide counters, never reset (they survive `shutdown()` + `start()`), except the gauges, which
read the live registry:

| Field | Kind | Meaning |
|---|---|---|
| `open` | gauge | PITs holding a slot |
| `reserved` | gauge | Reservations of creations of unknown result |
| `deletesPending` | gauge | Deletes not yet confirmed or expired |
| `created`, `deletesConfirmed`, `deletesExpired`, `deleteRetries` | counters | Registry events |
| `expired`, `stale` | counters | PITs marked expired; results discarded after it |
| `refusedFull` | counter | Creations refused by the cap |

They are for the tests; the metrics publish `pit.open`, `pit.delete.pending`, `pit.delete.retries` and `pit.expired`.

### Causes of a PIT

| Situation | `Cause` |
|---|---|
| Called from a runtime thread | `Reentrancy` |
| Invalid index, `keepAlive == 0`, invalid `retry`/`pageDeadline`, invalid cursor or `slice` | `InvalidArgument` |
| A default-constructed `Pit` or `PitSession`; a `next()` while another is in progress on the same cursor | `InvalidState` |
| No free slot (`max_open_pits`, reservations included) | `QueueFull` |
| Missing index on creation (`index_not_found_exception`) | `NotFound` |
| 2xx without a string `pit_id`; unparsable 2xx; response over the cap | `ItemPermanent` |
| The PIT expired (404 or 2xx with `search_context_missing_exception`), on the failing call and on every later one | `PitExpired` |
| Deadline or page deadline expired, no usable node until then | `Unavailable` |
| `maxAttempts` or `maxDuration` exhausted | `RetryExhausted` |
| Any other 4xx | `Client4xx` |
| The client closed, during or before the call | `ClientClosed` |
| The runtime shut down or drained the PIT | `Shutdown` |

## Logging

The library logs through `loggerHelper.h` with the tag `indexer-client`. The process gives it its log function, the same one it
gave the v1 connector library:

```cpp
using LogFunction = std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;
void setLogFunction(LogFunction logFunction);
```

- It **replaces** the previous function (a plain assignment, unlike the first-wins `assignLogFunction`); an empty function silences
  the library.
- It is valid only while no runtime is running (before `RuntimeOwner::start()` or after `shutdown()`), because runtime threads read
  the sink without synchronization; the check runs under the lock that serializes `start()` and `shutdown()`. With a runtime
  running (or from a runtime thread) the call is ignored and counted as a usage error.
- The sink (`Log::GLOBAL_LOG_FUNCTION`) is defined in `src/log.cpp`, one per shared object. `runtime.hpp` does not include
  `loggerHelper.h`.

The health code logs **only on a change** (an edge), never once per round. The first round always logs: a node's previous state is
unknown, so its first state is reported. Lines emitted by `src/health/nodeSet.cpp`:

| Level | Text | When |
|---|---|---|
| INFO | `Indexer node '<host>' is available.` | The node's logged state becomes Available |
| INFO | `Indexer node '<host>' is throttled (HTTP 429).` | The logged state becomes Throttled |
| WARN | `Indexer node '<host>' is no longer available. Reason: <reason>` | The logged state becomes Down, or a Down node's reason changes (once per distinct reason, e.g. connect refused, then 401) |
| WARN | `Indexer node '<host>' has reported a PERMANENT circuit breaker on 3 consecutive health checks: heap usage stays above the breaker limit; check the indexer heap sizing.` | The node's own probe answered a `PERMANENT` breaker on 3 consecutive rounds; once per streak (any other probe answer ends it; a passive 429 never counts) |
| ERROR | `Indexer cluster health is red: every node is marked down.` | A round turns red |
| INFO | `Indexer cluster is no longer red.` | The first round that is not red |
| ERROR | `Indexer client local fault: <reason>` | `localFault` appears |
| INFO | `Indexer client local fault cleared.` | `localFault` disappears |
| WARN | `Every indexer node rejects the TLS handshake with the configured CA (curl <code>): if the indexer CA was rotated, update <indexer><ssl> and restart the manager.` | Every node is Down with cause `Tls`; once per episode |

## Metrics

The library publishes its counters as typed snapshots plus a **catalog** of canonical names; it registers nothing in `wazuh_metrics` or
fastmetrics (the adapters live in the consumers). The contract is `include/indexer_client/metrics.hpp`.

**Scope**. Neither call blocks the hot path: they read, with no I/O, under the leaf mutexes the counters already live under.

| Call | Returns | Holds |
|---|---|---|
| `Client::metrics()` (also `IClient::metrics()`, mocked) | `ClientMetrics` | `consumer`, the `BucketMetrics` of **that consumer's** buckets, `callbacksSkipped`, `callbackOverruns`, `callbackMaxDurationMs`. A default-constructed or moved-from `Client` returns an empty `ClientMetrics` |
| `RuntimeRef::snapshot()` | `MetricsSnapshot` | `networkThreads`, `cpuThreads`, `clients`, `globalCharge`, `globalQuotaBytes`, `retainedBytes`, `queries` (`QueryMetrics`), `pit` (`PitMetrics`), `nodes[]` (`NodeMetrics`), `usageErrors`, `requestTimeout` (the runtime's `request_timeout_ms`, not a metric); **no bucket** |

**Lifetimes.** Buckets and nodes belong to the runtime: they start at 0 with each `start()`. `QueryMetrics`, `PitMetrics` and `usageErrors`
are process-wide and never reset (they survive `shutdown()` + `start()`; one runtime per process in production).

**Closed sets.** Each per-cause array is indexed by its enum and `forEachMetric` emits every member, zeros included.

| Set | Members |
|---|---|
| `RejectCause` | `queue_full`, `client_closed`, `shutdown`, `submit_timeout`, `reentrancy`, `payload_too_large`, `group_too_large`, `invalid_argument` (refusals of `submit` and of `Group::add`) |
| `DropCause` | `queue_full` (`DropNewest` and `DropOldest` together), `client_closed`, `shutdown`, `cancelled` |
| `FailCause` | `item_permanent`, `retry_exhausted`, `client_4xx`, `server_5xx`, `unavailable`, `invalid_state`, `ambiguous` (a `_bulk` answered 500/502/504, or whose response went over `max_response_bytes`, in a bucket with `onAmbiguous5xx = Fail`) |
| `RetryCause` | `item_retryable`, `version_conflict`, `server_5xx`, `transport`, `other`: operations requeued with a counted attempt, counted per operation in `Bucket::requeue` from its last error |

`toString(RejectCause | DropCause | FailCause | RetryCause)` gives these names.

**Latency**. `LatencyHistogram` has 17 per-bucket counts (`counts[i]` counts samples whose milliseconds, rounded up, are `<= LATENCY_BOUNDS_MS[i]`
and above the previous bound; bounds 1, 2, 4 … 32768 ms; `counts[16]` is the rest), `sumMicros` and `count`. `forEachMetric` publishes it
**cumulative**: `latency.le_1` … `latency.le_32768`, `latency.le_inf`, `latency.sum_micros`, `latency.count`. A bucket's sample is
`HttpResult.timings.total` of a bulk response that carried an HTTP answer.

**`lateResults`.** Operations of a completion **with an HTTP answer** (`Items` or `FailBatch` verdict) whose resolution lost first-wins
(`WritePath::resolve` returned false) or came back closed from `Bucket::requeue`. `Ignore` verdicts (`Cancelled`, `Shutdown`) never count.

**`responseBytesInFlight`**. The sum of the body bytes of query `HttpResult`s delivered to the query engine and not yet returned to the
consumer (classification plus DOM); `peakResponseBytesInFlight` is its process-wide maximum. There is **no global charge** for query
responses: the gauge makes the question observable instead of adding a cap.

**Names.** Lowercase, dotted, no labels (`.claude/docs/metrics.md`). `<consumer>` and `<bucket>` are sanitized: lowercased, every character outside
`[a-z0-9_]` becomes `_`, and a result that is empty or only `_` becomes `_` (`VD-Scanner` / `states.v2` give `vd_scanner` / `states_v2`; `---` gives `_`;
`sanitizeMetricName()` is public). `<i>` of a node is its position in `<indexer><hosts>`; the host is in `NodeMetrics::host`.
`RuntimeRef::client()` refuses with `InvalidArgument`, naming the field, a consumer whose sanitized name equals another live consumer's and two
buckets of one client whose sanitized names are equal. The set of names is therefore **fixed for the life of the runtime** (buckets from
`RuntimeRef::client()`, nodes from `start()`) and an adapter registers its pull metrics once. All values are doubles; byte counters are cast from `uint64`.
`forEachMetric(ClientMetrics, visitor)` and `forEachMetric(MetricsSnapshot, visitor)` call `visitor(name, MetricKind {Counter, Gauge}, value)` once per metric.

### Catalog

Counts per prefix: bucket 52, client 3, runtime 7, query 8, PIT 10, node 31. Source = the field of the snapshot type.

**Bucket**, prefix `indexer_client.bucket.<consumer>.<bucket>.` (`BucketMetrics`):

| Name | Kind | Source |
|---|---|---|
| `accepted` | counter | `accepted` |
| `rejected.<cause>` (8) | counter | `rejected[RejectCause]` |
| `dropped.<cause>` (4) | counter | `dropped[DropCause]` |
| `ok` | counter | `ok` |
| `deduplicated` | counter | `deduplicated` |
| `failed.<cause>` (7) | counter | `failed[FailCause]` |
| `retries.<cause>` (5) | counter | `retries[RetryCause]` |
| `late_results` | counter | `lateResults` |
| `retained_bytes` | gauge | `retainedBytes`: payload charged (pending + retry lane + delivered); what the consumers map to `indexer.queue.size` |
| `charge_bytes` | gauge | `charge`: everything charged (payload, result reserves, building groups) |
| `quota_bytes` | gauge | `quotaBytes` |
| `bulk_requests` | counter | `bulkRequests` |
| `bulk_bytes` | counter | `bulkBytes`: the bytes handed to the sender, per completion; a resend (retry, failover) and each half of a 413 `Split` count again |
| `latency.le_1` … `latency.le_32768` (16), `latency.le_inf` | counter | `latency.counts`, cumulative |
| `latency.sum_micros`, `latency.count` | counter | `latency.sumMicros`, `latency.count` |

**Client**, prefix `indexer_client.client.<consumer>.` (`ClientMetrics`):

| Name | Kind | Source |
|---|---|---|
| `callbacks_skipped` | counter | `callbacksSkipped` |
| `callback_overruns` | counter | `callbackOverruns` |
| `callback_max_duration_ms` | gauge | `callbackMaxDurationMs` |

**Runtime**, prefix `indexer_client.runtime.` (`MetricsSnapshot`):

| Name | Kind | Source |
|---|---|---|
| `network_threads`, `cpu_threads` | gauge | `networkThreads`, `cpuThreads` |
| `clients` | gauge | `clients` |
| `global_charge_bytes` | gauge | `globalCharge` |
| `global_quota_bytes` | gauge | `globalQuotaBytes` |
| `retained_bytes` | gauge | `retainedBytes` |
| `usage_errors` | counter | `usageErrors` |

**Queries**, prefix `indexer_client.query.` (`QueryMetrics`, process-wide):

| Name | Kind | Source |
|---|---|---|
| `requests` | counter | `requests` (attempts sent, as `queryStats()`) |
| `failovers`, `throttles`, `unavailable` | counter | `failovers`, `throttles`, `unavailable` |
| `too_large` | counter | `tooLarge` |
| `conflict_retries` | counter | `conflictRetries` |
| `response_bytes_in_flight` | gauge | `responseBytesInFlight` |
| `peak_response_bytes_in_flight` | gauge | `peakResponseBytesInFlight` |

**PIT**, prefix `indexer_client.pit.` (`PitMetrics`, process-wide):

| Name | Kind | Source |
|---|---|---|
| `open`, `reserved`, `deletes_pending` | gauge | `open`, `reserved`, `deletesPending` |
| `created` | counter | `created` |
| `deletes_confirmed`, `deletes_expired`, `delete_retries` | counter | `deletesConfirmed`, `deletesExpired`, `deleteRetries` |
| `expired`, `stale`, `refused_full` | counter | `expired`, `stale`, `refusedFull` |

**Node**, prefix `indexer_client.node.<i>.` (`NodeMetrics`):

| Name | Kind | Source |
|---|---|---|
| `state` | gauge | `state`: 0 = Available, 1 = Throttled, 2 = Down |
| `transitions` | counter | `transitions` |
| `window` | gauge | `window` |
| `bulk_target_bytes` | gauge | `bulkTarget` |
| `pace_ms` | gauge | `paceMs` |
| `requests`, `throttled`, `server_5xx`, `failures` | counter | `requests`, `throttled`, `server5xx`, `failures` |
| `decreases.429`, `decreases.throttled`, `decreases.latency` | counter | `decreases429`, `decreasesThrottled`, `decreasesLatency` |
| `latency.le_1` … `latency.le_32768` (16), `latency.le_inf`, `latency.sum_micros`, `latency.count` | counter | `latency`, as the bucket's |

**Accepted deviations:**

- A request-level 413 of a single operation resolves `Failed(PayloadTooLarge)` and counts in `failed.client_4xx`; a cause outside `FailCause`
  counts in `failed.invalid_state`.
- The operations of an abandoned group (never committed) leave no slot in `dropped[]`.
- `lateResults` also counts operations that the requeue skips because a sweep already resolved them.
- `bulk_requests` counts every bulk completion, whatever its outcome.
- `failed.server_5xx` and `failed.invalid_state` are part of the closed set but no production path resolves an operation with those causes today (a 5xx is retried and ends `retry_exhausted`); only the component suite moves them, through its test sink.

## Log lines

The log is meant to be useful and bounded. Every line below is decided under the mutex that owns its state and **emitted after that mutex
is dropped** (the `NodeSet` `pending.lines` pattern), never under a bucket mutex or inside `GlobalBudget::tryReserve`. The quota-edge lines are
written **by the submitting thread that crossed the edge**, once per crossing, when it leaves `Bucket::reserve()`/`reserveForGroup()` with no
mutex held (the engine's submit thread included). A staged `post()` ([Staged admission of `post`](#staged-admission-of-post)) crosses
no edge itself: its edges are crossed when its stripe is flushed, and the thread that flushed it writes them once the stripe's and the bucket's
mutexes are dropped: the posting thread that filled the stripe (64 operations or its byte limit), loop 0 for a deadline flush, or the closing
thread for the seal. The summary's timer drains what is still pending, e.g. what a `Block` left behind. The **ambiguous** line is the exception: it is written by the **completion thread** (CPU pool) of the `_bulk`, once the bucket mutex is dropped. A throwing
log sink never takes a producer or a runtime thread down. The node-health lines are in [Logging](#logging).

**Quota edges**, per bucket and for the global cap. Each edge logs once and is re-armed only when the charge crosses **70 % downwards**
(an edge, not a level: a storm of `QueueFull` at a low charge logs a single WARN). The global flags are atomics: the thread whose
compare-and-swap crossed the threshold claims the line with an `exchange`, so a crossing logs exactly once under concurrency.

| Level | Text | When |
|---|---|---|
| WARN | `Indexer client bucket '<consumer>/<bucket>' reached 80% of its quota (<charge> of <quota> bytes charged).` | The bucket's charge crosses 0.8 × quota upwards |
| WARN | `Indexer client bucket '<consumer>/<bucket>' has no room for new operations (<charge> of <quota> bytes charged): its overflow policy '<policy>' applies.` | The first admission **the bucket's own quota** refuses and resolves by overflow: a `QueueFull` refusal, `DropNewest`, a `DropOldest` eviction or a `Block` that has to wait. A refusal of the global cap logs the global line below, never this one |
| WARN | `Indexer client global quota reached 80% (<charge> of <cap> bytes charged).` | The global charge crosses 0.8 × `global_quota_bytes` upwards |
| WARN | `Indexer client global quota is full (<charge> of <cap> bytes charged): every bucket applies its overflow policy.` | The first admission the global cap refuses |
| WARN | `Indexer client bucket '<consumer>/<bucket>' got an ambiguous HTTP <status> for a bulk of <n> operations: they failed without being resent (onAmbiguous5xx = fail); the indexer may have applied them.` — or, for a response over the cap, `... got a response over max_response_bytes for a bulk of <n> operations: ...` (same tail) | The first `Failed(Ambiguous)` of the bucket after a 2xx `_bulk` (or since its creation); re-armed by the next 2xx `_bulk`. See [Ambiguous 5xx](#ambiguous-5xx) |
| WARN | `Indexer client bucket '<consumer>/<bucket>': the indexer already had <n> document(s) of a resent bulk (an earlier attempt was applied after a timeout or connection loss); they were not indexed twice.` | A response with 409 `version_conflict_engine_exception` items of `IndexDataStream` ops with an `_id` resolved `Ok`; `<n>` is that response's count. Logs again after at least `log_summary_interval_ms` since the last response that had such items (also after an idle spell); a trickle of 409 denser than the interval logs once, so the sustained signal is the `deduplicated` counter. A clean `_bulk` does not re-arm it |

**Periodic summary**. A timer on network loop 0 fires every `log_summary_interval_ms` (1000 – 3600000, default 60000). `<n>` is the
elapsed seconds since the previous summary, rounded up and never below 1. A bucket with no activity in the interval logs nothing; every bucket
with activity logs its INFO line every interval (one line per minute per active bucket with the default).

| Level | Text | When |
|---|---|---|
| WARN | `Indexer client bucket '<consumer>/<bucket>' unsuccessful operations in the last <n> s: <key>=<count>, ..., other=<count>.` | The bucket had failed or dropped operations. At most **one** line per bucket and interval, with at most `K = 8` keys `<cause>[/<itemErrorType>]` (first come; `Cause` names, e.g. `item_permanent/mapper_parsing_exception`) and `other=` with the rest. Both `Failed` and `Dropped` count in the keys; the line is not emitted when nothing failed or was dropped; a control byte of an `itemErrorType` is shown as `?` |
| INFO | `Indexer client bucket '<consumer>/<bucket>' in the last <n> s: <a> accepted, <o> ok, <f> failed, <d> dropped.` | The bucket had activity |
| DEBUG | `Indexer client bucket '<consumer>/<bucket>' sample reason (<key>): <reason>` | One sample per bucket and interval, the `reason` truncated to 256 bytes and then its control bytes escaped (`\n`, `\r`, `\t`, else `\xNN`): an indexer `error.reason` may quote the field's value, newlines included, and cannot break the line or forge another (so the logged text can reach 4 × 256 bytes) |
| WARN | `Indexer client consumer '<consumer>': <k> callbacks exceeded the callback budget of <b> ms in the last <n> s (the slowest took <m> ms).` | The client's `callbackOverruns` grew in the interval (delta and interval maximum) |
| WARN | `Indexer client gave up <k> PIT delete(s) in the last <n> s (first PIT id '<id>...'): the indexer frees them when their keep_alive lapses.` | A PIT delete expired in the interval; `<id>` is the first 16 bytes of the first id |

The counting happens in `Bucket::countResolved` under the bucket mutex; the timer swaps the interval out. The timer is weak-captured (it never
keeps the summary alive) and the body releases its client references before it emits. The runtime's stop (`stopAndJoin`) disarms the summary
and stops the timer **before** `writePath->stop()`, and emits the **last summary synchronously after** `writePath->stop()` and the PIT drain: the
shutdown sweep's `Dropped(Shutdown)` and the PIT deletes the drain gives up are in it, for the buckets of every Client still registered then
and of every Client closed **during the stop**. The close order (`client.hpp`) has each consumer run `awaitClosed`, which releases its
name, before `RuntimeOwner::shutdown()`; modulesd's VD and Inventory Sync Server then drop their Client. So a Client whose name is released
once the stop began (`beginShutdown` fixed the deadline, or `stopAndJoin` closed the admission) is kept by the runtime — its `ClientState` and
buckets only; `awaitClosed` already fixed its callback cutoff — and summarized like a live one: its last lines carry what that close dropped
(`shutdown=<n>`, `client_closed=<n>`, `<n> dropped`). `stopAndJoin` drops it right after the last summary. A Client closed before the stop
began is not kept: its activity since the previous summary is not logged. The engine shuts the runtime down before it closes its Client
(`EngineIndexerRuntime::finishStop()`), so its Client is still registered then. The summary body has its own mutex, so a timer run still in
progress and the final one may overlap. Limiter changes (window, target, pace) stay at DEBUG.

**What is never logged at INFO or above:** a document body, a `reason`, an id or a URL, except the 16-byte prefix of a PIT id in the PIT WARN. The summary's only free text from
the indexer is the `itemErrorType` token, with control bytes replaced.

**Deviations accepted:**

- `Reentrancy` refusals do not fire the «no room» edge.
- The «no room» line of a `Block` comes out when that `submit` returns.

**Seam.** `detail::testing::flushLogSummary()` (`runtime.hpp`) runs the summary body now on loop 0 and returns when its lines are emitted. It returns
`false`, without waiting, when no runtime runs, it stopped accepting work, or the caller is a runtime thread.

## Consumer helpers: `chunking.hpp` and `metricsSlot.hpp`

Two header-only helpers in `include/indexer_client/` that the consumers share (inventory sync and the vulnerability scanner). Nothing in
them is exported by the library (`INDEXER_CLIENT_API` is not applied): each consumer compiles its own copy.

**`chunking.hpp`** holds the arithmetic a consumer needs to cut a write into [Groups](#groups) that fit
the bucket's quota; the staging machines (barriers, deadlines) stay in the consumers.

| Symbol | Meaning |
|---|---|
| `chunkCap(quotaBytes, lanes)` | Per-worker chunk cap, `0.8 * quota / (2 * lanes)` (never below 1; `lanes` 0 counts as 1): every lane can hold an open and a pending chunk. The reserve is a parameter of the caller, not a constant here. |
| `estimateCharge(op, resultReserve)` | What the library will charge for the op (payload plus the per-op result reserve, `RESULT_RESERVE_BYTES`), never less. `Delete`: the action line alone; `IndexVersionedScript`: the document twice plus the script; any other kind: action line + body + `'\n'` + the body's heap slack (its whole capacity). |
| `escapedSizeBound(id)` | Upper bound of the `_id` once [escaped](#encoding-per-kind): 2 bytes for `"` and `\`, at most 6 for any other control character. |
| `CHUNK_ACTION_FRAME_BYTES` (64), `CHUNK_VERSIONED_FRAME_BYTES` (512) | Upper bounds of the fixed bytes of an action line and of an `IndexVersionedScript` head (`src/write/encoding.cpp`); if the encoder grows past them, `estimateCharge` under-reports. |

**`metricsSlot.hpp`** is the pull-metrics source of a consumer: `MetricsSlot(maxAge, prefixes)` holds its `Client`
**weakly** (a scrape never keeps a closed `Client` alive; without a live one the bucket values read 0) and, optionally, the process's
`RuntimeRef` (whose values do not depend on a `Client`). One refresh serves every read within `maxAge`, so one scrape of N metrics
costs one `metrics()` and one `snapshot()`; `repoint()` aims the slot at a new `Client` after a restart; `value(name)` and
`read(fn)` return the metric (0 when absent or filtered out by `prefixes`). It has its own mutex, so a scrape never contends with the
consumer's lifecycle; share it (`shared_ptr`) between the consumer and every getter it registers.

## Benchmark

`bench/` measures whether the v2 [transport](#transport-internal) is at least as fast as the v1 bulk
path. It compares two executables over **the same in-process fake indexer** (`bench/benchFake.hpp`, cpp-httplib; it counts bytes,
requests and connections and keeps no bodies) and **the same `libwazuhext.so`**, both in Release:

- `indexer_client_bench_v1`: `HTTPRequest::post` (`SINGLE`), as the v1 bulk does, in a closed loop on the calling thread;
- `indexer_client_bench_v2`: the production objects (no test seams), `RuntimeOwner::start` with K = 1 and the default M = 2,
  `c` chains each keeping one `POST /_bulk` in flight; each result callback (on the CPU pool) submits the chain's next request.

The load is one precomputed 4 MiB body, `POST /_bulk`, 60 s timeout. The normative comparison puts **identical headers on the
wire**: the v1 sends the v2's set (`Content-Type: application/json`, `Accept-Encoding: gzip`, the same Basic auth) and both let
curl add `Expect: 100-continue` ([finding below](#finding-expect-100-continue)). Both versions therefore send
`Accept-Encoding: gzip` (the fake does not compress); `run.sh --selfcheck` requires it and verifies the headers on the wire. The v1 **as shipped**
(`DEFAULT_HEADERS`) is informative only.

**Build.** The target is off by default (the `INDEXER_CLIENT_BENCH` option of the library's `CMakeLists.txt`); CI only compiles it (job `indexerclient-bench-build`, Release, `-DINDEXER_CLIENT_BENCH=ON`; see [Tests and CI](#tests-and-ci)). Build it in a
**separate checkout or worktree**, never the development checkout: `wazuhext` is always written to `<checkout>/src/build/lib`
whatever the build tree, and both binaries load it from there through their RPATH:

```bash
cmake -S <checkout>/src -B <checkout>/src/build-rel -DTARGET=manager -DCMAKE_BUILD_TYPE=Release -DINDEXER_CLIENT_BENCH=ON
cmake --build <checkout>/src/build-rel -j"$(nproc)" --target indexer_client_bench_v1 indexer_client_bench_v2
```

**Run.** `bench/run.sh` never builds anything:

```bash
bench/run.sh --v1 <bench_v1> --v2 <bench_v2> --cpus 0,2,4,6 --out <prefix> [--selfcheck] [--fake-status N] [--wazuhext-sha256 SHA]
```

| Option | Meaning |
|---|---|
| `--cpus LIST\|none` | CPU set for v1, v2 and the fake together (`taskset`); `none` disables pinning |
| `--out PREFIX` | Writes `PREFIX.csv`, `PREFIX-summary.txt` and `PREFIX.log` (provenance and each binary's output) |
| `--selfcheck` | 2 s per side and mode, plus the header check on the wire; exit 0 only when every sample is valid and the headers match |
| `--fake-status N` | The fake answers `/_bulk` with status N (a sample then is invalid; used to test the harness) |
| `--wazuhext-sha256 SHA` | Refuse to measure when a binary maps another `libwazuhext` |

Each binary takes `--mode plain|tls`, `--secs`, `--warmup`, `--pair`, `--fake-status`, `--print-headers` and `--csv-header`; the v1
also `--headers normative|shipped`, the v2 `--c 1|2|4|8`, `--path transport|client` (`client`: [below](#client-path-and-submit-microbenchmark)) and
`--probe [--rounds N]`. Exit codes of `run.sh`: 0 ok, 1 an invalid informative row, a failed probe or a failed selfcheck (an invalid normative
sample annuls its pair and counts through the reliability rule), 2 usage, 3 another `libwazuhext` loaded,
4 host load never fell to load1 <= 2, 5 a mode stayed unreliable after its repetition, 6 a gate of `--suite submit` failed or had no valid pair.

**Method.**

- Per mode (plain, TLS): **5 alternated pairs** v1/v2 at c = 1 (which side goes first alternates), 3 s warm-up and a 20 s window;
  the ratio is the **median of the valid pairs' v2/v1 ratios** (at least 4 valid pairs).
- A sample is invalid on any `Shutdown`/`Cancelled` result, any error, or server bytes different from client bytes; its pair is
  annulled.
- Reliability: it does not start while load1 > 2; the run is **unreliable** when the v1 throughput varies more than 3 % between
  its pairs (max/min) or the IQR of the ratios exceeds 0.04 (or fewer than 4 valid pairs). It is repeated once; if it stays
  unreliable, `run.sh` exits 5.
- **Grey zone**: a median in [0.94, 0.96) is re-measured with 7 pairs of 30 s before deciding.
- Affinity: v1, v2 and the fake share one fixed set of four physical P cores (one sibling each); every CSV row records the
  `cpus` and the `libwazuhext` sha256.
- **Informative** runs, after the normative ones: v2 at c = 2, 4, 8 and the v1 as shipped, 20 s each, per mode.
- The probe (`--probe`): 50 consecutive probe rounds on a live TLS runtime, counting the connections they cost.

**Output.** The CSV has one row per run (`mode,headers,side,c,pair,requests,bytes,secs,mib_s,req_ms_mean,xfer_ms_mean,
connect_ms_sum,appconnect_ms_sum,thread_cpu,proc_cpu,cpus,wazuhext_sha256,errors,server_bytes,valid`). The summary has one
`NORMATIVE` line per mode (median, valid pairs, v1 spread, IQR, `reliable`, `grey`), the `INFO` lines and the `PROBE` line.

**Result.** The gate is a median v2/v1 ratio >= 0.95 at c = 1 in plain and TLS (the two normative rows of the summary); the rows at c = 2, 4, 8 and the v1 as shipped are informative. The numbers depend on the machine (CPU model, governor, pinned CPUs) and are not kept here: rerun the harness (`run.sh`, below) on the machine that matters.

**Probe cost.** With `CAINFO_BLOB` curl re-parses the CA bundle on every new TLS connection; the probe does not pay it
repeatedly: `PROBE,connections=1,failures=0,appconnect_nonzero=0,rounds=50,applied=50,...`: 50 rounds over the one connection the
runtime's start round opened (so even round 1 does no handshake; `connections` is the oracle). The rounds run back to back over a
warm connection: the 10 s interval against an indexer that closes idle connections is not covered here.

### Client path and submit microbenchmark

- **`indexer_client_bench_v2 --path client --c N`** measures the whole `Client`/bucket write path (buckets, DRR, limiter): one bucket
  (4 MiB bulks, 256 MiB quota, `Reject`) kept at N x 4 MiB of 1.5 KiB documents, refilled from the result callbacks. The fake runs in
  **items mode** (one `201` item per action line, so the classifier sees a complete answer). The row is valid when the bucket's
  delta of `bulkBytes` equals the bytes the fake received; `NOTE bulk_mean=` is the mean bulk size the fake saw.
- **`indexer_client_bench_submit`** times what a producer pays per event: `IWriter::post` (`--api post`, the default, on a
  bucket with `trustedBodies` as the engine uses it; it requires `--cb none`, otherwise exit 2) or `IWriter::submit` (`--api submit`)
  of an `IndexDataStream` op with its body moved in. P producers fire bursts of B = 1000 ops behind a barrier; between bursts one
  coordinator waits, off the clock, until the backlog (the bucket's `charge`) is below W = 16 MiB. The first 5 bursts are discarded.
  Row: `SUBMIT,api,producers,cb,handover,pair,events,ns_per_op,cpu_ns_per_op,proc_cpu_ns_per_op,B,W,quota,backlog_max,accepted,
  server_docs,indices,valid`; valid when every op was accepted, the fake received `events x P` documents and no watermark wait
  timed out. It has no v1 side any more (the executable no longer links the v1 library or `keystore`).
- **`run.sh --suite submit --submit PATH --out PREFIX [--cpus L] [--cpus-p8 L] [--selfcheck]`**: `api=post` at P = 1/4/8 (no
  callback, `handover=move`), `api=submit` at P = 1/4/8 without callback, P = 1 with a no-op callback and P = 1 with
  `handover=view`, and `api=post` with `--indices 2` at P = 1 and 8; 5 runs each, reported as the median and the IQR of `ns_per_op`
  and the median of `cpu_ns_per_op` (a row with IQR > 4 % of the median or fewer than 4 valid runs is repeated once; exit code 5 if it
  stays unreliable). There is no gate. `--selfcheck` runs one run per row.

### Finding: `Expect: 100-continue`

The v2 used to suppress `Expect:`; the v1 as shipped let curl send `100-continue` on bodies over 1 MiB, and over TLS the v1 was faster than the v2. The cause was `Expect: 100-continue` (gzip did not matter), so the v2 now leaves `Expect` to curl, which also lets a node reject (401/413/429) before the body. This was measured against the in-process fake only; a real indexer and network RTT may differ (one RTT per bulk). Reproduce with the transport benchmark (`run.sh`, above).

## Linking

simdjson (the bulk-response classifier) is linked **statically** into the `.so` and into `indexer_client_testing`, from the
prebuilt archive `src/external/simdjson/build/libsimdjson.a` that the v1 also links (see the `indexer_client` target in the library's `CMakeLists.txt`). `--exclude-libs,ALL`
keeps its symbols local: `nm -D` of the `.so` shows no `simdjson::`.

curl and OpenSSL come **only** through `libwazuhext.so` (`target_link_libraries(indexer_client
PRIVATE wazuhext …)`). The library never links `ext_curl`, the static archive: the process holds a
single curl and OpenSSL. Only curl's headers are taken from `src/external/curl/include`. The `.so`
has `BUILD_RPATH $ORIGIN/../lib` so it finds `libwazuhext.so` in `${CMAKE_BINARY_DIR}/lib`.

## Build and tests

The sources are compiled twice (the `indexer_client_objects` and `indexer_client_objects_testing` object libraries):

| Target | Kind | Seams | Linked by |
|---|---|---|---|
| `indexer_client` | SHARED, from `indexer_client_objects` | none (production) | consumers and `indexer_client_utest` |
| `indexer_client_testing` | STATIC, from `indexer_client_objects_testing`, `INDEXER_CLIENT_TESTING` (adds `src/testing/seams.cpp`, `src/testing/registry.cpp`) | `detail::seams::*` | only `indexer_client_component_test` |

So no executable holds two copies of the runtime. Output goes to `${CMAKE_BINARY_DIR}/lib`, as every shared
module. The `.so` links `wazuhext`, `ext_asio` and `Threads::Threads` privately; there
is no `manager_config`.

```bash
cmake --build $WAZUH_REPO/src/build -j"$(nproc)" --target indexer_client
```

Unit tests need `-DUNIT_TEST=ON`. Prefer reconfiguring the tree with
`cmake -S $WAZUH_REPO/src -B $WAZUH_REPO/src/build -DUNIT_TEST=ON`: `make … TEST=yes` also sets it
but forces ASAN on the engine (see `.claude/docs/testing.md`). There are two suites, each with its
own executable, ctest name and ctest label (`tests/CMakeLists.txt`); both compile at C++17, so a
C++20-ism in a public header fails there first:

| Suite | Target / ctest label | Covers |
|---|---|---|
| Unit | `indexer_client_utest` (`tests/unit/*.cpp`) | Config, key-value source, mocks, fake indexer, the query response classifiers (`queryResponse_test.cpp`), the public library (`VisibilityTest.SetLogFunctionRoutesLogs` covers the log setter) |
| Component | `indexer_client_component_test` (`tests/component/*.cpp`) | The transport and the fake over real sockets, with the seams; `HealthTest` (probe, states, logs, stop order) and `FakeHealthTest` (the fake's `/_cluster/health` rules); `WriteTest` (the [write path](#write-path), below); the [queries](#queries) (`query_test.cpp`, `queryByQuery_test.cpp`, `queryDomFactor_test.cpp`); the [PIT](#point-in-time) (`pit_test.cpp`, `pitRegistry_test.cpp`) |

```bash
cmake --build $WAZUH_REPO/src/build -j"$(nproc)" --target indexer_client_utest indexer_client_component_test
ctest --test-dir $WAZUH_REPO/src/build -L indexer_client_utest
ctest --test-dir $WAZUH_REPO/src/build -L indexer_client_component_test
```

**`WriteTest` suites** (`tests/component/write*_test.cpp`, shared fixture `writeFixture.hpp`: a runtime, a programmable sink
installed through `WritePath::setSink`, a callback result log). Every case ends with the charge and the retained operations at 0.

| File | Cases |
|---|---|
| `writeEncoding_test.cpp` | `EncodingPerKind`, `EncodingRejectsInvalid`, `EncodingConflictRetryLine`, `EncodingPreservingShapes` (the frozen byte vectors), `EncodingPreservingRejects`, `SubmitCarriesReason`, `WriteInternalErrorTest.EncodeSizeMismatchRefusedNotAborted` |
| `writeAdmission_test.cpp` | `ChargeIsWireBytesPlusReserve`, `GlobalCapAcrossBuckets`, `OverflowReject`, `OverflowBlockTimeout`, `OverflowDropNewest`, `OverflowDropOldest`, `OverflowBlockWakes`, `BlockedProducerWakesOnClose`, `NoDropWithoutCounter`, `BlockFromRuntimeThreadIsReentrancy`, `PayloadTooLargeAtSubmit`, `WriteInternalErrorTest.BucketDestroyedWithQueuedOpsCompletesThem` and `WriteInternalErrorTest.ForeignBucketResolutionLoggedNotAborted` |
| `writeScheduler_test.cpp` | `ThresholdsFormBatches`, `DrrNoStarvation`, `DrrShareByWeight`, `DocumentNeverSplitDebtCarries`, `ThreadsStayKPlusMWithBuckets`, `DrrTinyQuantumFastForwards`, `MaxAgeExpiringDuringAPassIsServed`, `DrrDebtBulkReachesMaxBytes`, `DrrDebtShareByWeight`, `DrrDebtKeptWhenEmpty` |
| `writeClose_test.cpp` | `SubmitRacesClose`, `CloseAndShutdownResolveRetained`, `ShutdownWithHeldBatch`, `DefaultSinkIsTheBulkSender` |
| `writeReserve_test.cpp` | `ResultReserveMeasured` (allocation counter, five phases; skipped under ASAN/TSAN) |

**Classifier and retry lane suites** (component, `tests/component/`; neither needs a real indexer):

| File | Cases |
|---|---|
| `responseClassify_test.cpp` | `ClassifyRequestMatrix`, `ClassifyItemsMatrix`, `ClassifyDeleteNotFound`, `ClassifyConflict`, `ClassifyUnreadableOrMismatch`, `ClassifyReasonBounded`, `ParserMemoryBounded`, `TransportBodyPadded` |
| `writeRetryLane_test.cpp` | `RequeueBackoffAndExhaust`, `MaxDurationCountsFromFirstSend`, `RequeueWithoutErrorKeepsLastError`, `RequeueSpecs`, `SplitHalvesNeverRemerge`, `CloseReturnsLaneAndPending`, `RequeueOnClosedBucket`, `DropOldestSparesRetryLane`, `NextDueAndEmpty`, `LaneBeforePending`, `RetryLaneInvariantsUnderRace` |

**Fake `_bulk` responder.** `tests/fake/bulkResponder.hpp` (a dynamic `Rule`, `Rule::dynamic` in `fakeIndexer.hpp`) answers `POST /_bulk`
with **one item per operation received**, driven by a script by position (status, key, `result`, `error.type` and `reason`,
`caused_by`), with `errors` kept coherent. It can also serve an unreadable body, one item too many or too few, or a whole-request
answer (413, 429 with `Retry-After`, 5xx, 401), queue scripts, and hold an answer until released. Its own tests are in
`tests/unit/fakeBulk_test.cpp` (`FakeBulkResponder.*`, `FakeBulkResponderRules.CoexistsWithStaticRules`,
`FakeBulkResponderRender.ItemsWithoutHttp`).

The unit suite also covers the registration rule (`BucketSpecTest.InvalidBulkMaxBytesPlusReserveAboveQuota`), the former refusal of
`ordered = true` (`BucketSpecTest.OrderedRegisters` checks that `ordered` registers and that the other rules still apply; `BucketSpecTest.RetryConflictPolicyRegisters` and
`BucketSpecTest.InvalidZeroRetryOnConflict` cover the `Retry` policy, which registers) and the production sink through the public API
(`BucketSpecTest.WriterSubmitResolvesThroughTheSender`).

**Bulk sender suites** (component, `tests/component/`; the real transport against in-process fake nodes). They use the fixture
`BulkTest` (`bulkFixture.hpp`, derived from `WriteTest`): one `Node` per host (a fake indexer with its `/_cluster/health` and a
`BulkResponder` for `/_bulk`), `startOn(hosts, probeInterval, extra)` to start a runtime on them, `probeNow()`-based helpers to move
a node's health on demand; `BulkScript::tooLargeAbove(k)` (`tests/fake/bulkResponder.hpp`) answers 413 above `k` operations. 

| File | Cases |
|---|---|
| `bulkVerdicts_test.cpp` | `BulkBodyIsTheEncodedLines`, `ErrorsFalseStillPerItem`, `DeleteNotFoundIsOk`, `IndexNotFoundIsPermanent`, `MixedItems`, `EveryOpOneResult`, `LimitedRetryExhausts`, `UnlimitedSurvives5xx`, `PoisonDoesNotBlock`, `Split413`, `ResponseTooLargeSplits`, `Request429HonorsRetryAfterPerNode`, `Request429Paces`, `NotBeforeNeverShortenedBy2xx`, `Client4xxFailsBatch`, `CredentialsErrorRetries`, `UnreadableBodyRetries`, `PassiveReport429Throttled` |
| `bulkWakeups_test.cpp` | `FailoverOnTransportError`, `WindowPerNode`, `SubmitRefusedRequeues`, `CompletionFreesWindow`, `NotBeforeExpiryWakesScheduler`, `NoUsableNodeWaitsThenSends`, `CloseClientWhileInFlightRetry`, `RetryLaneBeforePendingE2E`, `BackoffIsPerBucket`, `ShutdownCancelsInFlight`, `ShutdownRacesRequeue`, `StaleDownMirrorDoesNotSpin`, `SetSinkRequeuesCancelledInFlight`, `CompletionExceptionRequeues` |

**Conflict policy and preservation suites** (component; the conflict and preservation cases use the fake `_bulk` responder, which does not run Painless).

| File | Cases |
|---|---|
| `bulkConflict_test.cpp` | `ConflictRetryThenOk`, `ConflictSuccessKeeps409`, `ConflictRetryExhausts`, `BucketRetryOnWire`, `BucketRetryPolicyRegisters`, `PreservingOutcomes` |
| `writeGroup_test.cpp` | `GroupHundredOneRejected`, `TwoBuildingGroupsDoNotBlock`, `GroupAddWaitsForCommittedRoom`, `GroupAddTimesOut`, `AbandonedGroupReleases`, `GroupTooLarge`, `CommitFlushesNow`, `GroupItemRetryCompletesOnce`, `GroupAcrossSplit413`, `GroupDropPoliciesRejectLikeReject`, `GroupAfterCloseAndShutdown`, `GroupOutlivesRuntime`, `GroupReservesReturnedWhenBucketDies`, `EmptyCommit`, `GroupStatsInvariant`, `GroupLastAddReason` |
| `writeReentrancy_test.cpp` | `CallbackBlockingCallsAreReentrancy` (`submit`, `Ticket::wait`, `GroupTicket::wait` and `Group::add` from a callback), `CallbackRequestCloseAndClientDestroy` |

**Ordered bucket and cancellation suites** (component).

| File | Cases |
|---|---|
| `bulkOrdered_test.cpp` | `OrderedOneBulkInFlight`, `OrderedKeyOncePerBulk`, `OrderedItemRetryBlocksOnlyItsKey`, `OrderedBlockedPrefixBeyondMaxDocsDoesNotStallOtherKeys`, `OrderedTimeoutAfterApplyKeepsOrder`, `OrderedAmbiguousFailoverAfterWindow`, `OrderedFailureBeforeSendFailsOverAtOnce`, `OrderedNoIdleSpin`, `UnorderedUnchanged` |
| `writeCancel_test.cpp` | `CancelPendingAndInFlight503`, `CancelInFlightOkStaysOk`, `CancelSlicedBeforeSubmitNotSent`, `CancelOtherTagsUntouched`, `CancelCommittedGroupOps`, `CancelIgnoresBuildingGroup`, `CancelTicketWaitsInFlightOnly`, `CancelFromCallbackReentrancy`, `TagValidation`, `CancelTwiceSameTag`, `CancelAfterTagReenqueued`, `CancelWakesOrderedBucket` |
| `bulkFairness_test.cpp` | `ItemRejectionsDoNotStarveOtherBucket` (about 21 s, about three times that under TSAN) |

**Metrics and logging suites** ([Metrics](#metrics), [Logging](#log-lines)).

| File | Covers |
|---|---|
| `tests/component/metrics_test.cpp` (`metrics_test`) | The snapshot and the catalog over the real transport and the fake |
| `tests/component/logSummary_test.cpp` (`logSummary_test`) | The quota edges and the periodic summary, through `flushLogSummary()` |
| `tests/unit/metricsCatalog_test.cpp` (`metricsCatalog_test`) | `LatencyHistogram`, name sanitizing and the catalog |

**Ambiguous 5xx, parking and wake-up suites** (component; [Ambiguous 5xx](#ambiguous-5xx), [parking a node](#node-health), one wake per completion).

| File | Covers |
|---|---|
| `bulkAmbiguous_test.cpp` | `onAmbiguous5xx`: `Fail` on 500, 502 and 504 (one send, `failed.ambiguous`, one WARN), 503 still retried, `Retry` unchanged, the WARN re-armed by a 2xx, a throwing completion that still never resends, a response over `max_response_bytes` (`Fail`: one send, never split; `Retry`: split as before) |
| `nodeRetryAfter_test.cpp` | A `Retry-After` from a query, a bulk, a PIT or the probe parks the node; the sender neither spins nor loses the wake; reads wait for the first parked node; `notBefore` set in any state; a mirrored park keeps one pace doubling per 429 burst (`MirroredParkKeepsOnePaceDoublingPerBurst`). The PIT registry's DELETE waiting for a parked node is `pitRegistry_test.cpp` `DeleteWaitsForParkedNode` |
| `errorMatrix_test.cpp` | The status matrix, one parameterized row per case: `_bulk` statuses (500, 502, 503, 504 among them), items and transport failures, and the same for queries and PIT creation |
| `bulkWakeups_test.cpp` | Also `OneWakePerCompletion` (`SchedulerStats::posts`) |
| `tests/unit/metricsCatalog_test.cpp` | `ReadmeMatchesCatalog` parses the per-prefix counts and the `failed.<cause>` row of this README |

**Closing and shutdown suite** (component, [Closing and shutdown](#closing-and-shutdown)).

| File | Cases |
|---|---|
| `closeDrain_test.cpp` | `RequestCloseDrainsPending`, `CloseDrainRetriesDuringDrain`, `SubmitRacesCloseKeepsDrain`, `RuntimeThreadDestroyResolvesAll`, `AwaitClosedSweepsAtDrainEnd`, `CloseWithBackoffBeyondDrainEnd`, `StormWithSlowCallbackAtDeadline`, `ResolutionOutstandingBeforeReleased`, `CutoffGateHoldsAwaitClosed`, `AwaitClosedDeadlinePast`, `ShortDeadlineHalves`, `CallbackOverrunCounted`, `OneBeginShutdownThreeConsumersHealthy` (sized from the measured rate; about 7 s), `OneBeginShutdownThreeConsumersDown`, `SignalDuringActivityOwnerThread`, `BlockedProducerAndQueryUnblock`, `CallbackCloseAndDestroyK1`, `ShutdownCutsCallbacksOfLiveClients` |

`ResultReserveMeasured` is re-run with `key`, `tag` and the pin in `OpState`; `RESULT_RESERVE` is raised if the measure x 1.25 exceeds it.

The conflict, preservation and `Submit::reason` cases of `writeEncoding_test.cpp` are listed above.
The wake-up cases use `bulk.maxAge >= 30 s` and `probe_interval_ms >= 30 s`, with `probeNow()` for the transition they want, so
no other wake-up can rescue the one under test.

**Seam `refuseSubmit`.** `detail::seams::refuseSubmit()` (`src/transport/seams.hpp`) is read by the sender's CPU-pool task just
before it builds the request; `testing_hooks::setRefuseSubmit(hook)` installs a hook that makes it answer true, which `SubmitRefusedRequeues` uses to
exercise the refused-submit path. The production build compiles it to `false`.

**Seam `beforeAssembly`** (`src/transport/seams.hpp`). It runs in the sender's CPU-pool task just before the cancelled operations
are removed from the batch and the body is assembled (`testing_hooks::setBeforeAssembly`); a test calls `cancel(tag)` inside it to prove
that nothing of the tag reaches the wire. The production build compiles it to nothing.

**Seams `beforeCompletion` and `beforeSenderMirror`** (`src/transport/seams.hpp`). The first runs in every bulk
completion after its slot was released (`testing_hooks::setBeforeCompletion`; a throwing hook exercises the completion's fallback,
`CompletionExceptionRequeues`); the second runs in the sender's `NodeSet` hook before it refreshes the `Down` mirror
(`testing_hooks::setBeforeSenderMirror`; a blocking hook reproduces the mirror lag, `StaleDownMirrorDoesNotSpin`). The production
build compiles both to nothing.

**Seams `afterPayloadReleased` and `inCallbackGate`** (`src/transport/seams.hpp`). The first runs in
`WritePath::resolve` right after the operation's payload was released (`testing_hooks::setAfterPayloadReleased`; parking it proves
the completion is already outstanding, `ResolutionOutstandingBeforeReleased`); the second runs in `CallbackCompletion::run` under
`completionsMutex`, between the cutoff comparison and the started/skipped mark (`testing_hooks::setInCallbackGate`; parking it proves
`awaitClosed` waits for the gate, `CutoffGateHoldsAwaitClosed`). The production build compiles both to nothing.

The runtime starts the probe on its own. The test hook `testing_hooks::setProbeAutoStart(false)`
(`src/testing/hooks.hpp`, test build only) creates the `NodeSet` and `Prober` without a first round or a timer, and `probeNow()`
still arms a single round; the transport suites use it so the probe does not add traffic to what they count. It is read once per
`start()` and `resetAll()` restores `true`.

Check each binary's mtime before trusting a PASSED. The component executable links with `-rdynamic`
(it interposes `getaddrinfo` for the hung-resolver case) and writes a link map,
`indexer_client_component_test.map`, that shows no static curl or OpenSSL entered it.

**Sanitizers.** Both suites run in a **sibling worktree**, not in the main tree (`$WAZUH_REPO/src/build`): the sanitizer flags
rewrite `CMAKE_CXX_FLAGS_DEBUG` tree-wide and `libwazuhext.so` is written to `src/build/lib`, which
would be clobbered. Configure it outside the main tree with `-DCMAKE_BUILD_TYPE=Debug`
and, for TSAN, `-DTSANITIZE=ON`; for ASAN, the CI mechanism
(`-DCMAKE_C_FLAGS`/`-DCMAKE_CXX_FLAGS="-g -fsanitize=address -fsanitize=undefined -fsanitize=leak"`,
`.github/actions/build_target_cpp/action.yml`). Rebuild `wazuhext` there before each sanitized run, check
with `readelf -d` that it needs `libasan` only in the ASAN tree, and prove the instrumentation with
`nm -C <test binary> | grep -c __tsan` (or `__asan`). The CI jobs are described in [Tests and CI](#tests-and-ci).

Layout of `tests/`: `unit/` (config schema, key-value source, mocks, fake indexer), `component/`
(transport over real sockets), `mocks/` (gmock mocks of the public interfaces), `fake/`
(in-process fake indexer; `fake/pitResponder.hpp` is the programmable PIT responder of the PIT suites;
`fake/dropOnReuseServer.hpp` is a keep-alive server that closes a connection without answering, the case where curl
resends a request by itself, see `freshConnection` in [Transport](#transport-internal)). 

## Tests and CI

**Workflows.** `.github/workflows/5_testunit_indexer_client.yml` (its path filter includes `src/deps.lock.mk`):

| Job | What it does |
|---|---|
| `indexerclient-modules` | unit + component suites in the coverage build. CI compiles Release `-O3 -s`, because `build_target_cpp` passes no build type (`src/CMakeLists.txt`) |
| `indexerclient-asan` | ASAN + UBSAN + LSan, component suite without `*Long` |
| `indexerclient-tsan` | Debug, `-fsanitize=thread`, `sudo sysctl -w vm.mmap_rnd_bits=28`, `TSAN_OPTIONS=halt_on_error=1 second_deadlock_stack=1`, component suite without `*Long` |
| `indexerclient-bench-build` | only compiles `indexer_client_bench` in Release with `-DINDEXER_CLIENT_BENCH=ON` |

The three test jobs set `INDEXER_CLIENT_TEST_TIME_SCALE: "2"`.

`.github/workflows/5_testintegration_indexer_client.yml`: job `indexerclient-opensearch`, with a `services.opensearch` container
`opensearchproject/opensearch:3.6.0` (single node, security off, `search.keep_alive_interval=1s`, `point_in_time.init.keep_alive=1s` — static: with
its 30 s default a PIT requested at 1 s would live 30 s — and no disk threshold). It runs
`ctest -L indexer_client_opensearch_test` with `INDEXER_CLIENT_OPENSEARCH_URL=http://localhost:9200`. A second service,
`opensearch-small` (`localhost:9202`), is the same node with `http.max_content_length: 16kb` for the 413 case
(`INDEXER_CLIENT_OPENSEARCH_SMALL_URL`), and `INDEXER_CLIENT_OPENSEARCH_CONTAINER=${{ job.services.opensearch.id }}` lets the
outage case stop and start the first one with the runner's `docker`.

**Time scale.** `tests/fake/testTimeScale.hpp`: `INDEXER_CLIENT_TEST_TIME_SCALE` is an integer 1-20 (empty means 1; an invalid value aborts), multiplied
by 3 under TSAN; the variable is read on the first call. `scaled()` covers the limits that proved host-sensitive: the margins of the transport
suites, the latency cases of `bulkLimiter_test.cpp` (the fake's latency and `latency_target_ms` scaled together), the query and close suites
(`queryFixture.hpp`) and the windows the local CI reproduction caught (`LeastLoadedLoopWinsOverRoundRobin`, `SubmitRacesClose`). The other
literal durations were not reviewed one by one: most are generous waits, and a few are race windows (`health_test.cpp`, `bulkOrdered_test.cpp`,
`transportShutdown_test.cpp`) that passed every local run of the three jobs at 2 CPUs; a CI flake on any of them is scaled the same way.

**Real-OpenSearch suite** (`tests/opensearch/`, `indexer_client_opensearch_test`; links the public `.so` and cpp-httplib for raw requests). Without
a URL the suite SKIPs, except under `GITHUB_ACTIONS`, where it FAILs; a URL that does not answer within `scaled(120 s)` FAILs, once per run (later cases fail at once). Its indices are `ic-ostest-<case>-<pid>`; the global
setup **deletes every `ic-ostest-*` index** left by an earlier run, so never point it at a cluster where another run of the suite is active.
Its suites:

| Suite | Covers |
|---|---|
| `OpenSearchPreserve.*` | the real Painless of `ReplacePreserving`: nested paths, `noop` by version, `"upsert":{}` creates the same document as `"upsert":<doc>`, two conflicting clients with `Retry` without loss or duplicates |
| `OpenSearchBulk.*` | per-item results with `errors:false`, deletes |
| `OpenSearchPit.*` | real expiry yields `PitExpired` on a 404 `search_context_missing_exception`, confirmed delete, slices with the same id |
| `OpenSearchSizes.*`, `OpenSearchLoad.*` | informative measurements |
| `OpenSearchHealth.RequireClusterFailsFast` | the require-cluster case fails fast |
| `OpenSearchFailures.*`, `OpenSearchSettingGuard.*` | a document the strict mapping refuses, the shard limit, a missing index without auto-creation; the cluster settings they change are restored |
| `OpenSearchPayloadLimit.BulkOverTheLimitIsSplitUntilEverythingLands` | on the `INDEXER_CLIENT_OPENSEARCH_SMALL_URL` node: a group three times its `http.max_content_length` is split after the 413 until every operation is `Ok` (one document per operation, more than one bulk); one document over the limit ends `Failed(PayloadTooLarge)` with 413 and is not indexed |
| `OpenSearchOutage.StoppedNodeLosesNothingAndDuplicatesNothing` | `docker stop` of the `INDEXER_CLIENT_OPENSEARCH_CONTAINER` node. While it is down a submit returns at once and nothing resolves; a client closed then ends every operation `Dropped(ClientClosed)` without the node; after `docker start` the queued operations land, the documents indexed before are there, and resending every id leaves one document per id. The node is started again whatever the case does |

The 413 and outage cases have their own variables, gated like the URL (SKIP locally without them, FAIL under `GITHUB_ACTIONS`):
`INDEXER_CLIENT_OPENSEARCH_SMALL_URL` is a second node started with a low `http.max_content_length` (a static node setting: it
cannot be lowered through `_cluster/settings`), and `INDEXER_CLIENT_OPENSEARCH_CONTAINER` is the docker container of the
`INDEXER_CLIENT_OPENSEARCH_URL` node, which the outage case stops and starts (a name or id; `wazuh-indexer` is refused).
Locally: start both containers with those settings, for example

```bash
node=(--memory=2g -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true -e DISABLE_INSTALL_DEMO_CONFIG=true
      -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" -e search.keep_alive_interval=1s -e point_in_time.init.keep_alive=1s
      -e cluster.routing.allocation.disk.threshold_enabled=false)
docker run -d --name ic-os-suite -p 9211:9200 "${node[@]}" opensearchproject/opensearch:3.6.0
docker run -d --name ic-os-small -p 9212:9200 "${node[@]}" -e http.max_content_length=16kb opensearchproject/opensearch:3.6.0
INDEXER_CLIENT_OPENSEARCH_URL=http://localhost:9211 INDEXER_CLIENT_OPENSEARCH_SMALL_URL=http://localhost:9212 \
  INDEXER_CLIENT_OPENSEARCH_CONTAINER=ic-os-suite ctest --test-dir src/build -V -L indexer_client_opensearch_test
```

**Latency target.** `latency_target_ms` stays at 2 s: against a real OpenSearch the bulks showed no latency-driven window reduction. The figures are not kept here; the `OpenSearchSizes.*` and `OpenSearchLoad.*` suites print them.

## Known limits

- The library records no benchmark figures; the harnesses under `tests/` and the benchmark sections above reproduce them.
- The [ordered ambiguous window](#ordered-buckets) cannot be closed by the library: the consumer's own sweep does (inventory sync, delete by query).
- A `CursorQuery` left at its default `{}` gets a 400 from OpenSearch 3.6; an average bulk of about 1 MiB with `bulk.maxBytes` at 4 MiB is a known inefficiency against a real OpenSearch.

Nothing public calls the transport directly. Traffic is the health probe, the bulk sender's `POST /_bulk` and the queries.
