# indexer_client — process-wide client for the Wazuh indexer

## Purpose

`indexer_client` is the shared library that replaces `indexer_connector` (epic
[wazuh/wazuh#39933](https://github.com/wazuh/wazuh/issues/39933)). It is built to serve the four
consumers of the indexer, one consumer at a time, with:

- one **runtime per process**, owned by a single `RuntimeOwner`;
- **buckets** declared by each consumer (a queue with its own quota, retry, overflow, bulk and
  conflict policies);
- a **final result per operation** (`OpResult`) and a single failure classification (`Cause`);
- three-state node health (`Available`, `Throttled`, `Down`);
- a managed point in time (PIT) for queries;
- metrics exposed as a snapshot;
- typed configuration validated from one `IConfigSource`.

The design is in `planes/18-indexer_connector_v2/03-diseno.md` §1–§4 (outside the repository).

**Status: E3a — write admission, buckets and scheduling on top of the internal transport; nothing is sent to the indexer yet, no public query API.** The public headers, the
configuration schema, the runtime lifecycle (threads, owner thread, shutdown deadline), the test
helpers, the internal curl [Transport](#transport-internal-e2a-1-and-e2a-2) (HTTP, HTTPS, credentials), the
[node health probe](#node-health-e2b) and the [write path](#write-path-e3a) (encoding, quota charge, overflow policies, DRR scheduler,
resolution) exist, and the transport has been [benchmarked against the v1](#benchmark). `Writer::submit` admits and schedules
writes but no bulk is sent: the production sink resolves every operation `Failed(Unavailable)`. The query interface still
sends nothing; see [What is not implemented yet](#what-is-not-implemented-yet).
`indexer_connector` keeps working untouched until each consumer migrates.

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
| | `Outcome<T>` | Value or failure: `cause`, `httpStatus`, `reason`; `ok()` is `cause == Cause::None` |
| | `OpResult` | Final result of one write; `itemErrorType` truncated to 64 B, `reason` to 512 B |
| | `RetryPolicy`, `Overflow`, `BulkThresholds`, `ConflictPolicy`, `WriteMode` | Per-bucket / per-query policies |
| | `Op`, `Callback` | One write (`Index`, `IndexAutoId`, `IndexDataStream`, `Delete`, `IndexVersionedScript`); completion callback that runs on the CPU pool |
| | `BucketSpec` | A consumer-declared queue: name, weight, quota, retry, overflow, bulk, conflict policy, `ordered` |
| | `Slice`, `CursorQuery`, `PitOptions`, `DbqOptions`, `QueryOptions`, `PitPage` | Query and PIT parameters and page |
| | `HealthView` | `nodes[]` (`url`, `state`, `reason`), `clusterRed`, `localFault`, `anyAvailable()`, `anyUsable()`; returned by `Client::health()` (see [Node health](#node-health-e2b)) |
| | `CloseReport`, `MetricsSnapshot` | Close accounting; runtime counters (only the thread layout and client count so far) |
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
| | `Submit` | Result of `submit`: `accepted`, `cause`, `ticket` (no `reason`) |
| | `Group` | Atomic group of writes: `add(Op)` then `commit()`; dropped without commit it releases its reservation (stub until E3c) |
| | `Pit`, `PitSession` | Shared PIT handle and its cursors (`next`, `exhausted`) |

**Write handles in E3a.** `Writer::submit` is real: it validates, encodes, charges and queues the operation (see
[Write path](#write-path-e3a)). `Writer::group()` and `Writer::cancel(tag)` are still stubs until E3c (`cancel` answers
`Unavailable`; a `Group` cannot be committed into anything). `Client::writer(bucket)` returns the writer bound to that bucket of
the client; once the runtime is gone it returns the E1 stub writer, which answers `Unavailable`.

`CloseReport` (from `Client::awaitClosed`) fills all three fields:

| Field | Meaning |
|---|---|
| `callbacksInFlight` | Completions of this client (ticket completion plus callback) still outstanding when the deadline passed |
| `droppedClientClosed` | Operations of this client resolved `Dropped(ClientClosed)` |
| `droppedShutdown` | Operations of this client resolved `Dropped(Shutdown)` |

Operations dropped by an overflow policy (`Dropped(QueueFull)`) are not part of the report; they are in the per-bucket counters.

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
  static destruction, at `exit()`. In E1 its threads always leave, but from E2 on a thread blocked
  in I/O or in a long callback can hang that `exit()`: the owner must call `shutdown()` before the
  process exits.
- **`requestClose()` / `awaitClosed(deadline)`.** `Client::requestClose()` never blocks and is
  valid from any thread. `Client::awaitClosed()` blocks and is for consumer threads only. The
  `Client` destructor is `requestClose()` plus `awaitClosed()` with the shutdown deadline (or the
  default). After `requestClose()`, `writer()` and `query()` return `nullptr`: a closing client
  hands out no new handles. Destroying a `Client` from a runtime thread is a usage error: it is
  logged to stderr, counted (`detail::testing::usageErrors()`) and turned into a non-blocking
  `requestClose()`; it never aborts, not even in debug builds.
- **Reentrancy.** Every wait in the library (`Ticket::wait`, `GroupTicket::wait`,
  `CancelTicket::wait`, `PitSession::next`, blocking queries, `awaitClosed`) is the library's own
  and returns `Cause::Reentrancy` when called from a runtime thread. From a callback a consumer
  may only request (a non-blocking `submit`, `requestClose()`), never wait.
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
internal-options file: E7 (modulesd) passes exactly `etc/wazuh-manager-internal-options.conf`
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
`hosts` and, optionally, `ssl`; any other member is rejected. The engine's current
`wiconnector::Config::toJson()` is **not** valid input: it appends `max_queue_bytes` and
`max_retry_delay_seconds` (`src/engine/source/wiconnector/src/windexerconnector.cpp`), and the
standalone path in the engine's `main.cpp` injects `/max_queue_bytes` too.

| Path | Type | Rule |
|---|---|---|
| `hosts` | array of strings | Required, at least one entry, each non-empty |
| `ssl.certificate_authorities` | array of strings | Optional, entries non-empty |
| `ssl.certificate` | string | Optional |
| `ssl.key` | string | Optional |

**Internal options.** Full key = prefix + name. The prefix is `analysisd.indexer_client_` for
`ProcessId::Analysisd` and `ProcessId::Standalone`, and `wazuh_modules.indexer_client_` for
`ProcessId::Modulesd`. The table is the `kSchema` of `src/config/runtimeConfig.cpp` (the single
source; every minimum is 1 and bounds are inclusive):

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

A change to `kSchema` must change this table, the `RuntimeConfig` initializers (checked by the
`DefaultsWhenUnset` test) and the tests together. In E1 these options are not yet registered in
`etc/wazuh-manager-internal-options.conf`, and there is no `docs/ref` page for the library.

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

## Transport (internal, E2a-1 and E2a-2)

`detail::Transport` (`src/transport/transport.hpp`) is the HTTP layer the probe (E2b), the bulk
path (E3b) and the queries (E4) build on. It is **not public API**: no installed header names it and
neither asio nor curl types appear in it. `RuntimeOwner::start` creates it after the runtime threads
exist; internal users reach it through `detail::runtimeTransport()`, a weak view that never keeps
the runtime alive. The normative contract is `planes/18-indexer_connector_v2/anexos/e2a-1/contrato-transport.md`
(outside the repository).

- **Loops.** Each of the K network threads runs one libcurl multi on its `io_context`
  (`src/transport/curlLoop.cpp`). Under the admission mutex a request goes to the loop with the
  fewest admitted-and-unresolved transfers, ties broken round-robin (`pickLoop`,
  `src/transport/transport.cpp:220`).
- **Admission.** `submit(HttpRequest, ResultCallback)` is synchronous and returns
  `Admission{admitted, cause, id}`. `id` is monotonic per runtime and never reused. Only `GET`,
  `HEAD`, `POST`, `PUT`, `DELETE` and the schemes `http` and `https` are admitted (`https` only when some CA is configured, see [TLS](#tls-and-credentials));
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
| 56, 52 | `RecvError` | yes |
| 18 | `PartialResponse` | yes |
| 23 with the response cap tripped | `ResponseTooLarge` | no |
| 2, 27, a `curl_multi_socket_action` error, 23 without the cap flag, any other | `LocalError` | no |
| `cancel` won the race | `Cancelled` | no |
| resolved by `stop` | `Shutdown` | no |

- **`mayHaveSent`** is set when `CURLOPT_PREREQFUNCTION` ran: the connection was ready and the
  request was about to be written. It is conservative (true against a server that accepts and stays
  silent) and is reset on every use of an easy handle. `HttpResult.uploadedBytes` carries
  `CURLINFO_SIZE_UPLOAD_T`.
- **Response cap.** `max_response_bytes` is enforced only in the write callback
  (`curlLoop.cpp:772`), which sets the cap flag and fails the transfer; `HttpResult.body` is never
  larger than the cap. `CURLOPT_MAXFILESIZE_LARGE` is not used and `CURLOPT_ACCEPT_ENCODING` is not
  enabled (if it ever is, the cap must count decoded bytes).
- **`Retry-After`** is parsed byte by byte (`src/transport/retryAfter.cpp`): no locale, no
  `strptime`/`mktime`, so neither the global locale nor `TZ` changes the result. The value is
  capped at `retry_after_max_ms` and parsed on the CPU pool.
- **Fixed options.** Per easy: `CURLOPT_PROTOCOLS_STR "http,https"`, `CURLOPT_NOSIGNAL`,
  `CURLOPT_PROXY ""` (never a proxy from the environment); `Expect` is left to curl (100-continue on bodies over 1 MiB,
  as the v1). Per multi:
  `CURLMOPT_MAX_HOST_CONNECTIONS` = 8 (a constant of E2a-1; the real window is E5's) and
  `CURLMOPT_QUICK_EXIT`. `curl_global_init` runs once (`std::call_once`).
- **Timings.** `HttpResult.timings` (`TransferTimings`: `total`, `connect`, `appConnect`) is in
  **microseconds**, and is also filled for `Cancelled` and `Shutdown` results. `appConnect` is 0 in clear text.
- **TLS and credentials** are described in [TLS and credentials](#tls-and-credentials); they add `Tls`
  and `TlsConfig` to `TransportCause`.

### TLS and credentials

**TLS material (I48).** `RuntimeOwner::start` calls `loadTlsMaterial` (`src/transport/tlsMaterial.cpp`)
before creating any thread, and does so **whenever the material is configured, whatever the hosts'
scheme**: a typo in a path fails at start, not on the day `https` is used. A failure is
`Cause::InvalidConfig`, names the path or the host, and creates no thread. What is required:

- every host is `http` or `https` (case-insensitive); some `https` host with no CA configured fails;
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
and no CA directory (`CAPATH` is null). Verification is always on (`VERIFYPEER` 1, `VERIFYHOST` 2),
the minimum protocol is TLS 1.2 and there is no insecure mode. `https` is admitted only when a CA is
configured. The material is read only at start: **rotating a CA, certificate or key requires a
restart**.

**TLS causes (I54).** Added to the classification table:

| curl code | `TransportCause` | `nodeAttributable` | Meaning |
|---|---|---|---|
| 35 (handshake), 60 (verification: CA, hostname), 98 (the node wants a client certificate) | `Tls` | yes | A fault of the node or of what it presents |
| 58 (our certificate or pair), 77 (our CA bundle) | `TlsConfig` | no | curl rejected bytes our validation accepted: local |
| 53, 54, 59, 66, 82, 83, 90, 91 | `TlsConfig` | no | Listed for completeness; unreachable with our options (no `SSLENGINE`, cipher list, `CRLFILE`, `ISSUERCERT`, pinned public key nor `VERIFYSTATUS`) |
| 43 | `LocalError` | no | Stays generic |

**Credentials (I55, I42).** `IConfigSource::credentials()` returns the `Credentials`; the process
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

## Node health (E2b)

The runtime knows at every moment which indexer nodes it can use. Each node is in one of three states
(`HealthView::NodeState`): `Available`, `Throttled` (the node answered 429) or `Down`. In `view()` every node starts `Down`
until the first probe round says otherwise. The state lives in an internal `NodeSet` (`src/health/nodeSet.{hpp,cpp}`) fed by the
`Prober` (`src/health/prober.{hpp,cpp}`) and, later, by the data path.

**The probe.** The `Prober` sends one `GET {host}/_cluster/health?local=true` per configured node through the
[Transport](#transport-internal-e2a-1-and-e2a-2), with `request.timeout` = `probe_timeout_ms`. It works in **rounds**:

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
| 2xx, `status` `red` | Down, **every** node | The round is red: `clusterRed` is set, every node's reason is `cluster health is red (reported by '<host>')` (a node already Down by its own result keeps its own reason) and no node returns to Available while a round holds `red` |
| 2xx, `status` missing, not a string, any other value, or body not JSON | Down | `invalid _cluster/health body` |
| 429 | Throttled | `error.durability` or `error.root_cause[0].durability` equal to `PERMANENT` marks the throttle as permanent; anything else, or an unreadable body, is transient |
| 401, 403 | Down | `HTTP <status>: check indexer credentials / permissions` |
| any other HTTP status | Down | `HTTP <status>` |
| transport cause with `nodeAttributable` (`Timeout`, `Connect`, `SendError`, `RecvError`, `PartialResponse`, `Tls`) | Down | `<cause> (curl <code>)` |
| `TlsConfig`, `LocalError`, `ResponseTooLarge` | Down **and** `localFault` | `<cause> (curl <code>)`; a probe the transport did not admit reports `probe not admitted: <cause>` |
| `Cancelled`, `Shutdown` | ignored | The whole round is discarded: no transition, no log |

`localFault` is set while the last complete round had a local result (the runtime, not the node, is at fault) and is cleared by
the first complete round without one.

**Passive signals.** `NodeSet::report(index, HttpResult)` is for the data path (E3b, E4; nothing calls it yet). It applies at once,
outside the rounds, and can only degrade: a node-attributable failure sets `Down`; a 429 sets `Throttled` from `Available`. A
passive success never promotes, and `Retry-After` is ignored.

**Selector.** `NodeSet::choose()` is round-robin among the `Available` nodes; a `Throttled` node is chosen only when none is
`Available`; it returns nothing when every node is `Down`.

**`HealthView`** (`Client::health()`, a copy taken under the mutex; empty when the runtime is gone):

| Member | Meaning |
|---|---|
| `nodes[]` | In the order of `hosts`: `url`, `state`, `reason` (why it is `Down`, empty otherwise) |
| `clusterRed` | The last complete round contained a `red` cluster; every node is `Down` |
| `localFault` | The local reason of the last complete round, when there is one |
| `anyAvailable()` | At least one node `Available`; the strict aggregate, for the vulnerability scanner |
| `anyUsable()` | At least one node not `Down`; the lenient aggregate, for inventory sync |

**For the next stages.** `NodeSet` also exposes `generation()` (+1 per node transition), `transitions(index)` and
`onTransition(hook)`, called after each transition outside the mutex; `Prober::stats()` reports `rounds`, `roundsApplied`,
`roundsDiscarded`, `roundsSkipped`, `submitsRefused` and `resultsAfterStop`. They are internal.

**Stop order.** `RuntimeState::stopAndJoin` stops the [write path](#close-and-shutdown) first, then the prober, then the transport, then the loops, then the CPU pool.
`Prober::stop()` sets a flag, posts the timer cancellation to loop 0 and waits for it, so no round is armed and no probe is
submitted after it returns.

## Write path (E3a)

`Writer::submit` validates and encodes the operation, charges its memory against the bucket's quota and the global cap, applies
the bucket's overflow policy when there is no room, and queues it. A DRR scheduler on network loop 0 forms batches from the
queues and hands them to an internal sink. In E3a the production sink sends nothing: every operation resolves
`Failed(Unavailable)` (the bulk sender is E3b). The code is in `src/write/` (`encoding`, `bucket`, `budget`, `scheduler`, `sink`,
`writer`); none of it is public API. Counters are reachable only through `detail::writeStats()`.

### Encoding per kind

`encode(Op&&)` (`src/write/encoding.hpp`) runs in `submit`, on the producer's thread, once. The result is the operation's NDJSON
lines (each ends in `\n`); their size is exactly what goes on the wire, and E3b re-sends them without re-encoding. The body is
moved into the lines: on success `op.body` is left empty with its memory freed. The shapes are byte-for-byte the v1's
(`indexer_connector/src/indexerConnectorSyncImpl.hpp`):

| Kind | Lines |
|---|---|
| `Index` | `{"index":{"_index":"<i>","_id":"<id>"}}` + body |
| `IndexAutoId` | `{"index":{"_index":"<i>"}}` + body |
| `IndexDataStream` | `{"create":{"_index":"<i>"}}` + body |
| `Delete` | `{"delete":{"_index":"<i>","_id":"<id>"}}` (one line, no body) |
| `IndexVersionedScript` | `{"update":{"_index":"<i>","_id":"<id>"}}` + `{"script":{...,"params":{"doc_version":<version>,"doc":<body>}},"upsert":<body>,"scripted_upsert":true}`; the Painless source keeps the document unless `document_version` is older, then sets `ctx.op = 'none'`; the document travels twice |

Validation failures are `Cause::InvalidArgument`, counted in the bucket (`invalidArgument`), and the op is not charged. The
field is first in the internal reason (`index: ...`, `id: ...`, `version: ...`, `body: ...`, `mode: ...`), but `Submit` carries
no `reason`: the consumer sees only the cause.

| Field | Rule |
|---|---|
| `index` | Non-empty and only `[a-zA-Z0-9._*-]` (the v1 allowlist, `isSafeIndexName`) |
| `id` | Required for `Index`, `Delete` and `IndexVersionedScript`; must be empty for `IndexAutoId` and `IndexDataStream`. Escaped as the v1 does: `"`, `\`, the short escapes and any other control character below 0x20 as `\u00XX` |
| `version` | Only for `IndexVersionedScript`, where it must be a canonical integer in [0, `INT64_MAX`] (digits only, no leading zero); empty for every other kind |
| `body` | Required and free of `\n` for every kind but `Delete`; must be empty for `Delete` |
| `mode` | `WriteMode::ReplacePreserving` is `InvalidArgument` until E3c |

### Charge and quota

Every accepted operation is charged `encoded bytes + RESULT_RESERVE` (`RESULT_RESERVE` = 1664, `src/write/bucket.hpp`) against its
bucket's `quotaBytes` and against the runtime-wide `global_quota_bytes`.

- **Wire bytes** (the payload) are what the operation holds in the queue and in a batch. They are released once, when the
  operation resolves (or at once when `DropOldest` evicts it).
- **`RESULT_RESERVE`** covers what the operation keeps after its lines are gone: its internal state, the ticket state, the callback
  slot and an `OpResult` with its strings at their caps. It is released after the callback has run (also when the callback throws)
  and, for an operation without a callback, when the last `Ticket` is destroyed. `Ticket::wait()` does not consume it.
- **How the constant was measured.** `ResultReserveMeasured` replaces the global `operator new` of the test executable with an
  allocation counter (usable size of every block) and measures the heap an accepted operation keeps besides its lines in four
  phases: retained with a callback; resolved with its completion queued behind a busy pool and its batch still held (the worst
  one, 1308.5 B per operation); callback run with the `Ticket` alive; resolved without a callback. 1308.5 B x 1.25 = 1636, rounded
  up to a multiple of 64 gives 1664. The case is a regression guard, skipped under ASAN/TSAN (they own `operator new`), and the
  constant is re-measured in E3b when the internal state grows.
- **What it does not cover.** Only the library's state: a callback whose captures exceed `std::function`'s small buffer (the
  measurement uses an 8-byte capture) allocates consumer memory that is not charged. `IWriter::submit(Op op, ...)` takes the
  operation by value: `submit(std::move(op))` avoids a copy of the body before the encoding moves it. `maxAge` counts from the
  moment `submit` was called, so time blocked in `Block` counts toward it.
- **Global cap.** `GlobalBudget` reserves with a lock-free compare-and-swap loop (never add-then-roll-back, which would refuse
  other buckets spuriously). Buckets whose quotas add up to more than the cap compete for it, and the one that does not fit
  applies its overflow policy as if its own quota were full.
- **Too large.** `Submit{false, PayloadTooLarge}` when the encoded size is above `bulk.maxBytes`, or the charge is above the
  bucket's `quotaBytes` or above the global cap. It is counted (`payloadTooLarge`).
- **Registration rule.** `RuntimeRef::client` rejects a bucket (`InvalidArgument`, field named in `reason`) unless
  `bulk.maxBytes + RESULT_RESERVE <= quotaBytes` (`validateBucket`, `src/runtime/runtime.cpp`), together with the older
  `bulk.maxBytes <= quotaBytes <= global_quota_bytes`. So the largest admissible operation always fits an empty bucket.

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
  `payloadTooLarge`, `invalidArgument`, `droppedNewest`, `droppedOldest`, `resolvedOk`, `resolvedFailed`, `resolvedDropped`,
  `retained`, `charge` and `peakCharge` (`BucketStats`; `WriteStats` adds `globalCharge` and `globalCap`). Invariants:
  `submitted = accepted + rejectedQueueFull + rejectedClosed + submitTimeout + reentrancy + payloadTooLarge + invalidArgument`
  and `accepted = resolved + retained`. A drop is never silent: every `DropNewest` and each `DropOldest` eviction is counted and
  resolved.
- **Locks.** A bucket's mutex is a leaf: it is never held while posting, running a callback or destroying a ticket state, and
  the only other lock taken under it is the waiter registry's (itself a leaf).

### Scheduler (DRR on loop 0)

One `Scheduler` per runtime, created after the loops exist. All its state (ring, cursor, credits, `maxAge` timers) is touched only
from network loop 0, as the `Prober` does; other threads only append to a notification list and post a pass.

- **Thresholds.** A bucket is eligible when its pending bytes reach `bulk.maxBytes`, its pending operations reach `bulk.maxDocs`
  or its oldest pending operation is `bulk.maxAge` old (`Bucket::eligible`; E3b will add backoff and the retry lane).
- **Notifications.** `enqueue` tells the scheduler when the bucket goes from empty to non-empty or crosses `maxBytes` or `maxDocs`
  (`>=`), deduplicated by an atomic flag. Notifications posted while a pass is queued coalesce into that pass.
- **`maxAge` timers.** Each bucket has an asio timer armed for its oldest pending operation plus `maxAge`, and re-armed after every
  pass. An expiry already due when the timer would be armed is not armed (it would spin while the sink has no capacity): the pass
  runs once more instead, when the sink has capacity; otherwise `sinkReady()` resumes the scheduler.
- **The DRR loop.** Eligible buckets form a ring with a persistent cursor. On its turn a bucket's `credit` grows by
  `weight x drr_quantum_bytes` and it emits batches while `credit >= bytes of its head operation` and `sink.capacity() > 0`. A batch
  takes whole operations from the head, at most `bulk.maxBytes` and `bulk.maxDocs`, within the credit; the head goes alone
  whenever the credit covers it, so a document is never split. The turn ends when the credit does not cover the head (credit kept),
  when the bucket empties (credit reset to 0) or when it falls below every threshold again (its timer brings it back). If the sink's
  capacity reaches 0 the cursor stays on the bucket and `sinkReady()` resumes the same turn without new credit.
- **Fast-forward.** If a complete round emits nothing because the quantum is small against the documents, the scheduler adds at once
  the credit of the `k - 1` empty rounds classic DRR would still spin through (`k` = fewest rounds after which some bucket covers
  its head) instead of looping (`SchedulerStats::fastForwards`). Same outcome, no spin on loop 0.

### Internal sink

`detail::write::BatchSink` (`src/write/sink.hpp`) is where batches go: `capacity()` (batches it accepts now; 0 stops the scheduler
until `WritePath::sinkReady()`), `dispatch(Batch)` (on loop 0; each operation must be resolved exactly once through
`WritePath::resolve`, from any thread) and `stop()` (afterwards no batch is accepted; what the sink still holds is resolved by the
shutdown sweep). **Production: `Failed(Unavailable)`** with the reason `no bulk sender yet (E3b)`, unbounded capacity: what the
stub writer of E1 answered. E3b replaces it with the bulk sender and E5's limiter becomes its capacity. The component suites
install a programmable sink through `detail::write::runtimeWritePath()->setSink(...)`.

### Resolution

Every operation resolves exactly once: the first of the sink, a close sweep or an eviction wins (`OpState::claimed`), and the
rest are no-ops. The winner releases the payload, counts the status in the bucket and completes the ticket; the callback runs on
the CPU pool (never on a network thread) after the ticket is completed, and the reserve is returned after it. A callback that
throws is swallowed and does not skip the accounting. If the pool no longer accepts tasks (late in shutdown), the completion runs
inline. `Dropped(ClientClosed)` and `Dropped(Shutdown)` are also counted per client for the `CloseReport`.

### Close and shutdown

- **`requestClose()`** closes the client's buckets with `ClientClosed`: blocked producers wake and return `ClientClosed`, later
  `submit` calls return `ClientClosed`, and the operations still pending resolve `Dropped(ClientClosed)`. Operations already
  delivered to the sink keep their course. **Provisional (E3a):** the design (`requestClose()` stops admission and *starts
  draining*) keeps the pending operations for E5's drain up to the `awaitClosed` deadline; dropping them here is E3a's stand-in
  while there is no real sender (D43).
- **`awaitClosed(deadline)`** does `requestClose()`, resolves what the client still retains in the sink `Dropped(ClientClosed)`
  (E5 adds the drain up to the deadline before this point), then waits for the client's outstanding completions until the
  deadline; whatever is left is `CloseReport.callbacksInFlight`. It returns the `CloseReport` described in [Public API](#public-api).
- **Submit racing a close.** `submit` reserves, then enqueues. A close that swept the bucket between the two did not see the
  operation, so after enqueuing the writer checks the bucket's close cause and, if closed, takes the operation back and resolves it
  `Dropped`. Everything accepted is resolved once and nothing refused has a callback (`SubmitRacesClose`, using the seam
  `afterAdmission`).
- **Shutdown order** (`RuntimeState::stopAndJoin`): stop accepting clients, then `WritePath::stop()`: every bucket closes with
  `Shutdown` (blocked producers wake) and its pending operations resolve `Dropped(Shutdown)` -> the scheduler stops (no pass,
  batch or timer afterwards) -> `sink.stop()` -> every operation still unresolved, pending or delivered, resolves
  `Dropped(Shutdown)` while the pool still accepts tasks. Only then the node-health prober, the transport, the loops and the
  CPU pool stop, as described in [Node health](#node-health-e2b).

## Logging

The library logs through `loggerHelper.h` with the tag `indexer-client`. The process gives it its log function, the same one it
gives `indexer_connector`:

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
| WARN | `Indexer node '<host>' is throttled with durability PERMANENT: it will not recover without operator action.` | A permanent throttle starts, also from a transient one |
| ERROR | `Indexer cluster health is red: every node is marked down.` | A round turns red |
| INFO | `Indexer cluster is no longer red.` | The first round that is not red |
| ERROR | `Indexer client local fault: <reason>` | `localFault` appears |
| INFO | `Indexer client local fault cleared.` | `localFault` disappears |
| WARN | `Every indexer node rejects the TLS handshake with the configured CA (curl <code>): if the indexer CA was rotated, update <indexer><ssl> and restart the manager.` | Every node is Down with cause `Tls`; once per episode |

## Benchmark

`bench/` (stage E2c) measures whether the v2 [transport](#transport-internal-e2a-1-and-e2a-2) is at least as fast as the v1 bulk
path. It compares two executables over **the same in-process fake indexer** (`bench/benchFake.hpp`, cpp-httplib; it counts bytes,
requests and connections and keeps no bodies) and **the same `libwazuhext.so`**, both in Release:

- `indexer_client_bench_v1`: `HTTPRequest::post` (`SINGLE`), as the v1 bulk does, in a closed loop on the calling thread;
- `indexer_client_bench_v2`: the production objects (no test seams), `RuntimeOwner::start` with K = 1 and the default M = 2,
  `c` chains each keeping one `POST /_bulk` in flight; each result callback (on the CPU pool) submits the chain's next request.

The load is one precomputed 4 MiB body, `POST /_bulk`, 60 s timeout. The normative comparison puts **identical headers on the
wire**: the v1 sends the v2's set (`Content-Type: application/json`, an empty `Accept-Encoding:`, the same Basic auth) and both let
curl add `Expect: 100-continue` ([finding below](#finding-expect-100-continue)). The v1 **as shipped** (`DEFAULT_HEADERS`,
`Accept-Encoding: gzip`) is informative only. `--selfcheck` verifies the headers on the wire.

**Build.** The target is off by default (`INDEXER_CLIENT_BENCH`, `CMakeLists.txt:90`); CI does not compile it yet. Build it in a
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
also `--headers normative|shipped`, the v2 `--c 1|2|4|8`, `--path transport|client` (`client` is reserved for E5) and
`--probe [--rounds N]`. Exit codes of `run.sh`: 0 ok, 1 an invalid informative row, a failed probe or a failed selfcheck (an invalid normative
sample annuls its pair and counts through the reliability rule), 2 usage, 3 another `libwazuhext` loaded,
4 host load never fell to load1 <= 2, 5 a mode stayed unreliable after its repetition.

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
- The D37 probe (`--probe`): 50 consecutive probe rounds on a live TLS runtime, counting the connections they cost.

**Output.** The CSV has one row per run (`mode,headers,side,c,pair,requests,bytes,secs,mib_s,req_ms_mean,xfer_ms_mean,
connect_ms_sum,appconnect_ms_sum,thread_cpu,proc_cpu,cpus,wazuhext_sha256,errors,server_bytes,valid`). The summary has one
`NORMATIVE` line per mode (median, valid pairs, v1 spread, IQR, `reliable`, `grey`), the `INFO` lines and the `PROBE` line.

**Result of E2c** (2026-10-20, Intel Core i9-14900HX, governor `powersave`, CPUs 0,2,4,6, Release, 4 MiB bulk body; MiB/s):

| Run | Plain | TLS |
|---|---|---|
| Normative c = 1, median v2/v1 (5 of 5 valid pairs, reliable, not grey) | **0.992** | **1.003** |
| v1 spread / IQR of the ratios | 0.025 / 0.006 | 0.014 / 0.005 |
| v2 c = 2 (informative) | 5422.7 | 1890.7 |
| v2 c = 4 (informative) | 5223.9 | 1878.6 |
| v2 c = 8 (informative) | 5139.8 | 1928.2 |
| v1 as shipped (informative) | 5286.1 | 1958.1 |

The gate is a median >= 0.95 at c = 1 in plain and TLS (the two normative rows); the other rows are informative. The
informative rows are bounded by the single network thread (K = 1, ~82 % busy in TLS) and by the in-process fake sharing the four
cores: they are not a concurrency ceiling (E5 sizes the windows with K and against the real indexer). The machine class of CI is
not measured (E6).

**D37 (probe cost).** With `CAINFO_BLOB` curl re-parses the CA bundle on every new TLS connection; the probe does not pay it
repeatedly: `PROBE,connections=1,failures=0,appconnect_nonzero=0,rounds=50,applied=50,...`: 50 rounds over the one connection the
runtime's start round opened (so even round 1 does no handshake; `connections` is the oracle). The rounds run back to back over a
warm connection: the 10 s interval against an indexer that closes idle connections is E6's.

### Finding: `Expect: 100-continue`

The v2 used to suppress `Expect:`; the v1 as shipped let curl send `100-continue` on bodies over 1 MiB, and over TLS the v1 as
shipped was faster than the v2 (about 1922 against 1675 MiB/s). The diagnosis (`anexos/e2c/diagnostico-expect.md`, outside the
repository) showed that the whole difference was `Expect: 100-continue` (gzip did not matter); the v2 now leaves `Expect` to
curl (I60), which also lets a node reject (401/413/429) before the body. Measured on the fake only: about +18 % TLS and +5 % plain;
a real indexer and network RTT may differ (one RTT per bulk), so E6 confirms it against the real indexer.

## Linking

curl and OpenSSL come **only** through `libwazuhext.so` (`target_link_libraries(indexer_client
PRIVATE wazuhext …)`). The library never links `ext_curl`, the static archive: the process holds a
single curl and OpenSSL. Only curl's headers are taken from `src/external/curl/include`. The `.so`
has `BUILD_RPATH $ORIGIN/../lib` so it finds `libwazuhext.so` in `${CMAKE_BINARY_DIR}/lib`.

## Build and tests

The sources are compiled twice (I45b, `CMakeLists.txt:35-61`):

| Target | Kind | Seams | Linked by |
|---|---|---|---|
| `indexer_client` | SHARED, from `indexer_client_objects` | none (production) | consumers and `indexer_client_utest` |
| `indexer_client_testing` | STATIC, from `indexer_client_objects_testing`, `INDEXER_CLIENT_TESTING` (adds `src/testing/seams.cpp`, `src/testing/registry.cpp`) | `detail::seams::*` | only `indexer_client_component_test` |

So no executable holds two copies of the runtime. Output goes to `${CMAKE_BINARY_DIR}/lib`, like
`indexer_connector`. The `.so` links `wazuhext`, `ext_asio` and `Threads::Threads` privately; there
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
| Unit | `indexer_client_utest` (`tests/unit/*.cpp`) | Config, key-value source, mocks, fake indexer, the public library (`VisibilityTest.SetLogFunctionRoutesLogs` covers the log setter) |
| Component | `indexer_client_component_test` (`tests/component/*.cpp`) | The transport and the fake over real sockets, with the seams; `HealthTest` (probe, states, logs, stop order) and `FakeHealthTest` (the fake's `/_cluster/health` rules); `WriteTest` (the [write path](#write-path-e3a), below) |

```bash
cmake --build $WAZUH_REPO/src/build -j"$(nproc)" --target indexer_client_utest indexer_client_component_test
ctest --test-dir $WAZUH_REPO/src/build -L indexer_client_utest
ctest --test-dir $WAZUH_REPO/src/build -L indexer_client_component_test
```

**`WriteTest` suites** (E3a, `tests/component/write*_test.cpp`, shared fixture `writeFixture.hpp`: a runtime, a programmable sink
installed through `WritePath::setSink`, a callback result log). Every case ends with the charge and the retained operations at 0.

| File | Cases |
|---|---|
| `writeEncoding_test.cpp` | `EncodingPerKind`, `EncodingRejectsInvalid` |
| `writeAdmission_test.cpp` | `ChargeIsWireBytesPlusReserve`, `GlobalCapAcrossBuckets`, `OverflowReject`, `OverflowBlockTimeout`, `OverflowDropNewest`, `OverflowDropOldest`, `OverflowBlockWakes`, `BlockedProducerWakesOnClose`, `NoDropWithoutCounter`, `BlockFromRuntimeThreadIsReentrancy`, `PayloadTooLargeAtSubmit` |
| `writeScheduler_test.cpp` | `ThresholdsFormBatches`, `DrrNoStarvation`, `DrrShareByWeight`, `DocumentNeverSplitCreditCarries`, `ThreadsStayKPlusMWithBuckets`, `DrrTinyQuantumFastForwards`, `MaxAgeExpiringDuringAPassIsServed` |
| `writeClose_test.cpp` | `SubmitRacesClose`, `CloseAndShutdownResolveRetained`, `ShutdownWithHeldBatch`, `DefaultSinkUnavailable` |
| `writeReserve_test.cpp` | `ResultReserveMeasured` (allocation counter; skipped under ASAN/TSAN) |

The unit suite also covers the registration rule (`BucketSpecTest.InvalidBulkMaxBytesPlusReserveAboveQuota`) and the production
sink through the public API (`BucketSpecTest.WriterSubmitResolvesUnavailable`).

**Seam `afterAdmission`.** `detail::seams::afterAdmission()` (`src/transport/seams.hpp`) runs in `Writer::submit` between the bucket
reservation and the enqueue; in the test build `testing_hooks::setAfterAdmission(hook)` installs the hook (`resetAll()` clears it).
`SubmitRacesClose` uses it to close the client or shut the runtime down exactly in that window; the production build compiles it
to nothing.

The runtime starts the probe on its own. The test hook `testing_hooks::setProbeAutoStart(false)`
(`src/testing/hooks.hpp`, test build only) creates the `NodeSet` and `Prober` without a first round or a timer, and `probeNow()`
still arms a single round; the transport suites use it so the probe does not add traffic to what they count. It is read once per
`start()` and `resetAll()` restores `true`.

Check each binary's mtime before trusting a PASSED. The component executable links with `-rdynamic`
(it interposes `getaddrinfo` for the hung-resolver case) and writes a link map,
`indexer_client_component_test.map`, that shows no static curl or OpenSSL entered it.

**Sanitizers.** Both suites run in a **sibling worktree**, not in `src/build`: the sanitizer flags
rewrite `CMAKE_CXX_FLAGS_DEBUG` tree-wide and `libwazuhext.so` is written to `src/build/lib`, which
would be clobbered (I47b). Configure it outside `src/build` with `-DCMAKE_BUILD_TYPE=Debug`
and, for TSAN, `-DTSANITIZE=ON`; for ASAN, the CI mechanism
(`-DCMAKE_C_FLAGS`/`-DCMAKE_CXX_FLAGS="-g -fsanitize=address -fsanitize=undefined -fsanitize=leak"`,
`.github/actions/build_target_cpp/action.yml`). Rebuild `wazuhext` there before each sanitized run, check
with `readelf -d` that it needs `libasan` only in the ASAN tree, and prove the instrumentation with
`nm -C <test binary> | grep -c __tsan` (or `__asan`). The CI workflow
(`.github/workflows/5_testunit_indexer_client.yml`) builds and runs both suites in the normal job and
in the ASAN job.

Layout of `tests/`: `unit/` (config schema, key-value source, mocks, fake indexer), `component/`
(transport over real sockets), `mocks/` (gmock mocks of the public interfaces), `fake/`
(in-process fake indexer). `spike/` holds the E0 measurement code and is not part of the targets.

## What is not implemented yet

E1 delivered the skeleton, E2a-1 the internal `http` transport, E2a-2 TLS and credentials, E2b node health and logging, E2c the
transport [benchmark](#benchmark) (done; the `--path client` benchmark of the whole client arrives with E5) and E3a the
[write path](#write-path-e3a) up to the sink. Not implemented, by stage:

| Area | Stage |
|---|---|
| Bulk building and sending, per-item classification, retry lane and backoff, HTTP 413 handling, failover to another node, the wait of an ambiguous `ordered` bucket (they will use `generation()` and `onTransition`) | E3b |
| `Group` (atomic groups), `ordered` buckets, `cancel(tag)`, `WriteMode::ReplacePreserving` | E3c |
| Reads answering `Unavailable` when no node is usable | E4 |
| Queries: `search`, `searchAfter`, PIT, `deleteByQuery`, `updateByQuery`, `indexExists` | E4 |
| Limiter, AIMD window and pacing, drain up to the shutdown deadline, public metrics (write counters, health metrics, `Retry-After` in passive signals) | E5 |
| Benchmark of the whole client (`--path client`) | E5 |
| Metrics beyond the thread layout in `MetricsSnapshot` | E5 |
| Migration of the four consumers off `indexer_connector` | later stages |

Until then no write reaches an indexer: `submit` admits, charges and schedules, and the production sink resolves every operation
`Failed(Unavailable)`. `group()`, `cancel()` and the query interface are stubs. The only traffic is the health probe; nothing public
calls the transport yet.
