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

**Status: E2a-1 — internal HTTP transport, no public network API.** The public headers, the
configuration schema, the runtime lifecycle (threads, owner thread, shutdown deadline), the test
helpers and the internal curl [Transport](#transport-internal-e2a-1) exist. The public write and
query interfaces still send nothing to an indexer; see
[What is not implemented yet](#what-is-not-implemented-yet).
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
| | `HealthView`, `CloseReport`, `MetricsSnapshot` | Node states and `clusterRed`; close accounting; runtime counters (E1 reports only the thread layout and client count) |
| `iConfigSource.hpp` | `IConfigSource` | The only way configuration reaches the library |
| `keyValueConfigSource.hpp` | `KeyValueConfigSource` | `IConfigSource` over `key=value` text plus an `<indexer>` JSON string |
| `runtimeConfig.hpp` | `SslConfig`, `RuntimeConfig` | Typed, validated configuration; `prefixFor()` and `from()` |
| `runtime.hpp` | `RuntimeOwner` | Single owner of the process runtime: `start`, `beginShutdown`, `shutdown`, `running` |
| | `RuntimeRef` | Non-owning reference: `client()`, `snapshot()`, `shutdownDeadline()`, `valid()` |
| | `detail::testing::*` | Test seams: `postToPool`, `postToIoLoop`, `onRuntimeThread`, `usageErrors` |
| `client.hpp` | `Client` | A consumer's handle on the runtime; implements `IClient` |
| | `IClient`, `IWriter`, `IQuery` | Abstract interfaces for consumers' mocks |
| | `Ticket`, `GroupTicket`, `CancelTicket` | Handles on a pending write, a group of writes and a cancel; `ready()` and `wait(Deadline)` |
| | `Submit` | Result of `submit`: `accepted`, `cause`, `ticket` |
| | `Group` | Atomic group of writes: `add(Op)` then `commit()`; dropped without commit it releases its reservation |
| | `Pit`, `PitSession` | Shared PIT handle and its cursors (`next`, `exhausted`) |

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

`KeyValueConfigSource::parse(text, indexerSectionJson)` is the stock implementation: `key=value`
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

## Transport (internal, E2a-1)

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
  `HEAD`, `POST`, `PUT`, `DELETE` and the scheme `http` are admitted (until E2a-2 adds `https`);
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
- **Fixed options.** Per easy: `CURLOPT_PROTOCOLS_STR "http"` (E2a-2 widens it), `CURLOPT_NOSIGNAL`,
  `CURLOPT_PROXY ""` (never a proxy from the environment), `Expect:` suppressed. Per multi:
  `CURLMOPT_MAX_HOST_CONNECTIONS` = 8 (a constant of E2a-1; the real window is E5's) and
  `CURLMOPT_QUICK_EXIT`. `curl_global_init` runs once (`std::call_once`).
- **TLS** is not available until E2a-2, which adds `Tls` and `TlsConfig` to `TransportCause`.

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
| Unit | `indexer_client_utest` (`tests/unit/*.cpp`) | Config, key-value source, mocks, fake indexer, the public library |
| Component | `indexer_client_component_test` (`tests/component/*.cpp`) | The transport and the fake over real sockets, with the seams |

```bash
cmake --build $WAZUH_REPO/src/build -j"$(nproc)" --target indexer_client_utest indexer_client_component_test
ctest --test-dir $WAZUH_REPO/src/build -L indexer_client_utest
ctest --test-dir $WAZUH_REPO/src/build -L indexer_client_component_test
```

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

E1 delivered the skeleton and E2a-1 the internal `http` transport. Not implemented, by stage:

| Area | Stage |
|---|---|
| Transport: TLS and credentials | E2a-2 |
| Node probes and health states; transport performance | E2b, E2c |
| Writes: bucket queues, bulk building, scheduling, retries, overflow, tickets and groups | E2–E5 |
| Queries: `search`, `searchAfter`, PIT, `deleteByQuery`, `updateByQuery`, `indexExists` | E2–E5 |
| Metrics beyond the thread layout in `MetricsSnapshot` | E2–E5 |
| Migration of the four consumers off `indexer_connector` | later stages |

Until then `submit`, `group`, the query interface and `health` have no network behavior behind
them: the transport is internal and nothing public calls it yet.
