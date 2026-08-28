# remoted module (C++ worker bridge)

A self-contained C++17 module that `remoted` launches in its own thread, receiving a
configuration struct to initialize itself. It mirrors the pattern `modulesd` uses for
`inventory_sync_server` / `vulnerability_scanner`, but integrates via **direct link**
instead of `dlopen`, and passes configuration as a **typed C struct** instead of
a serialized `cJSON`.

This is the isolation boundary between remoted's C code and C++: everything under this
directory is C++, and the only file remoted's C sources include is
[`include/remoted_module.h`](include/remoted_module.h).

## Layout

```
remoted_module/
├── include/                        # public surface (the only C↔C++ contact)
│   ├── remoted_module.h            # C-ABI: config struct + start/stop
│   └── remotedModule.hpp           # public C++ Singleton facade
├── src/
│   ├── remotedModule.cpp           # extern "C" shims + facade delegation + log sink definition
│   ├── remotedModuleFacade.hpp     # worker thread + lifecycle; owns the HTTP server + auth + endpoints
│   ├── auth/                       # ns remoted::auth — framework-agnostic JWT bearer auth (see below)
│   │   └── passwordKeySource.hpp/.cpp  # etc/authd.pass -> HKDF key of wazuh-enroll+jwt, see Agent enrollment below
│   ├── common/                     # ns remoted::common — leaf utilities with no layer of their own:
│   │                               #   logThrottle.hpp (rate-limited logging), zstdDecoder.hpp/.cpp,
│   │                               #   vdClient.hpp/.cpp (cached VD feed-offset UDS client, see below),
│   │                               #   requestOutcomeMetrics.hpp (per-endpoint responses.* + latency)
│   ├── decoding/                   # ns remoted::decoding — Content-Encoding policy (see below)
│   ├── http_server/                # ns remoted::http — transport-agnostic HTTP(S) sub-layer (see below)
│   ├── endpoints/                  # ns remoted::endpoints — endpoint contract + auth gateway (see below);
│   │   │                           #   endpoint.hpp also carries the remoted.auth.reject.* catalog
│   │   ├── controlEndpoint.hpp/.cpp    # POST /control JSON dispatch (see below)
│   │   ├── downloadMetrics.hpp         # remoted.download.* catalog (POST /download)
│   │   └── scanVdEndpoint.hpp/.cpp     # POST /scan/vd JSON dispatch (see below)
│   ├── control/                    # ns remoted::control — 5.x agent control messages (/control);
│   │                               #   metrics.hpp = remoted.control.* catalog
│   ├── scanvd/                     # ns remoted::scanvd — on-demand VD re-scan passthrough (/scan/vd,
│   │                               #   see below); scanVdMetrics.hpp = remoted.scanvd.* catalog
│   ├── enrollment/                 # ns remoted::enrollment — POST /enroll, bridges to authd (see below)
│   └── downstream/                 # ns remoted::downstream — async UDS forwarding + limiter (see below);
│                                   #   forwarderMetrics.hpp = remoted.forwarder.* failure catalog
├── test/unit/                      # GoogleTest tests (C-ABI black-box + HTTP server + auth + gateway)
└── tools/
    ├── send_stateless.py           # CLI to sign + POST /stateless for manual/E2E testing (see below)
    ├── send_agent_json.py          # CLI to sign + POST /stats and /config, and check the answer
    │                               #   (the deletion has no remoted route: see
    │                               #    inventory_sync_server/tools/send_delete_agent.py)
    ├── send_control.py             # CLI to sign + POST /control (startup/notify/shutdown scenarios)
    └── send_scan_vd.py             # CLI to sign + POST /scan/vd, incl. offset match/mismatch (see below)
```

Each internal concern is a folder under `src/` (namespaced, PRIVATE, reachable by prefix —
`"auth/...`", `"decoding/...`", `"http_server/...`", `"endpoints/...`", `"control/...`",
`"downstream/...`", and `"enrollment/...`" — since `src/` is on the include path). New
endpoints get their own folder under `src/endpoints/<name>/`.

## HTTP(S) server sub-layer (`src/http_server/`)

Transport only. The module exposes an HTTPS endpoint behind a **transport-agnostic interface** so
the underlying library (today RESTinio, likely `Boost.Beast + Boost.Asio` later) can be swapped
without touching any registered endpoint.

Metrics: the transport's backpressure state is published as the `remoted.server.budget.*` pulls
(via `IHttpServer::diagnostics()`) — see the [Metrics catalog](#metrics-catalog).

```
src/http_server/
├── IHttpServer.hpp          # neutral interface + types (Method/HttpRequest/HttpResponse/
│                            #   IHttpResponder/HttpServerConfig). No transport types leak here.
├── inFlightBudget.hpp       # global in-flight byte budget + RAII Reservation (backpressure/503)
├── httpServerConfig.hpp/.cpp# buildHttpServerConfig(): C-ABI struct -> HttpServerConfig (+ fallbacks)
├── httpServerFactory.hpp    # makeHttpServer() -> the single transport swap point
└── RestinioHttpServer.hpp/.cpp # RESTinio + OpenSSL implementation (PImpl hides RESTinio in the .cpp)
```

- **Endpoint registration:** `addRoute(Method, path, handler)` before `start()`. Paths are
  **logical**: the transport serves every route under `HttpServerConfig::globalPrefix`
  (`<remote><https><global_prefix>`; `""` == `/` == no prefix). With a prefix in effect the
  unprefixed paths answer `404`, and the health route `"/"` is registered as the bare prefix so
  `GET /<prefix>` and `GET /<prefix>/` both answer. `request.target` is **never rewritten** — the
  router matches the raw (prefixed) target, so agents send the full prefixed path and proxies must
  forward it untouched (the bearer token does not bind it: a mismatch is a `404`). Canonicalization lives in one place
  (`normalizeGlobalPrefix()`, called by `RestinioHttpServer::start()`; invalid values throw like
  a missing certificate). Public HTTPS listener only — the local admin socket is not prefixed.
- **Two-phase shutdown:** `stopAccepting()` closes the acceptor and drains the handler worker pool
  while deliberately leaving the I/O runtime alive (so an in-flight deferred reply can still be
  delivered); `stop()` calls `stopAccepting()` first, then releases the I/O runtime. See *Deferred
  forwarding*'s Lifecycle note below for why the order matters.
- **Async handlers (non-blocking I/O threads):** a raw handler is
  `void(std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)`. Each request is
  dispatched to a bounded worker pool with a **deferred response**, so RESTinio's I/O threads never
  block on slow handler work (disk, calls to other APIs). A handler may respond inline or capture the
  request and responder, offload the blocking work, and call `responder->send(...)` later from any
  thread. The request is a `shared_ptr<const>` so it can travel across deferred pipeline stages;
  keeping it alive keeps its in-flight byte reservation charged (see below).
- **Memory management (layered):** the worker-pool queue is unbounded on its own, so four layers
  bound memory:
    1. **In-flight byte budget** — the transport reserves each request's payload (`body + a small
       per-request overhead`) against a global budget *before* handing it to the worker pool. When
       the budget is exhausted the request is shed with a plain **`503 Service Unavailable`**
       (server-capacity load-shedding, not per-client rate-limiting; no `Retry-After` — the agent
       runs its own retry/backoff) instead of queueing, giving the backpressure the raw asio pool lacks. The reservation is an RAII token living in the request's
       shared context alongside the single payload copy; it is released the instant the context's
       last owner drops it. The **handler controls that**: dropping the request shared_ptr (or calling
       `AuthenticatedRequest::payload.release()`) frees the payload buffer AND the reservation together
       — even while a deferred reply is still outstanding, since the responder no longer co-owns the
       buffer (see *Single-copy payload*). Configured via remoted (`max_inflight_bytes`). Routes
       registered with `countAgainstBudget=false` (the liveness `GET /`) are **exempt**, so the probe
       stays `200` under memory pressure instead of being shed (which would make an LB pull the node).
       The same budget also backs **body decoding** (`decoding/bodyDecoder.hpp`): a
       `Content-Encoding: zstd` request additionally reserves the decoder's own buffers (briefly) and
       its decompressed output (for as long as the payload lives), via
       `IHttpServer::tryReserveInFlightBytes()` and `Reservation::grow()`. So a compressed request
       holds up to three concurrent reservations — wire body, decoder buffers, decoded output — which
       is correct: all three are genuinely in memory at that moment. Exhausting the budget there
       answers **`413`** (the request is too big for the capacity free *right now*), not `503`.
       Only the *admission* reservation carries the request-level accounting: decoder reservations
       are uncounted (`InFlightBudget::tryReserveUncounted()` — bytes only, and their refusal is
       not a shed), and when the wire buffer is dropped in favor of the decoded body, the output
       reservation is promoted (`Reservation::promoteToRequest()`) to inherit the request's
       identity. That keeps `budget.inflight.requests` at exactly one per admitted request and
       `budget.rejected.total` moving only on admission sheds — the decoder's `413` is counted in
       `remoted.auth.reject.body_too_large` instead.
    2. **`maxBodySize`** — per-request read-phase cap (RESTinio rejects an oversized `Content-Length`
       early by closing the connection). *Note:* RESTinio 0.7.9 has no dynamic pre-body hook, so the
       budget is charged once the body is already buffered; `maxBodySize` is what bounds a single
       request's peak.
    3. **`maxParallelConnections`** — bounds simultaneous connections, so the read-phase peak (bodies
       still arriving, before they reach the budget) is bounded by `maxParallelConnections *
       maxBodySize`.
    4. **Deferred-work limiter** (`max_deferred_requests`) — a **count**-based sibling of the byte
       budget (`downstream/deferredWorkLimiter.hpp`) that bounds how many requests are **parked
       awaiting a downstream service**. A `Slot` is acquired before forwarding and held (RAII) until
       the reply is sent; when full, the forwarder sheds with the same plain **`503`**. This is the
       second phase of a two-phase backpressure: the byte budget covers *receive + send* (and is
       released once the payload has been sent), the deferred limiter covers *the wait*.
- **Single-copy payload + early release:** the payload is copied exactly **once** — into the shared
  `RequestContext`. RESTinio's original buffer is freed on the I/O thread right after (the responder
  is a pre-created `response_builder` that no longer holds the request handle), the auth middleware
  authenticates from the headers alone (the body is not part of the token), and `AuthenticatedRequest::payload` is a
  zero-copy `string_view` into that single copy (kept alive by a keep-alive to the context). A
  handler can therefore **forward the payload, release it + its budget, and still reply later**:
  `payload.release()` (or dropping the request) drops the buffer + reservation while the responder
  survives to answer the agent when a downstream service responds. The small identity fields
  (`agentId`, `method`, `requestTarget`) are owned, so they outlive an early release.
  > Because the byte budget is released at forward, a request *parked waiting on a downstream service*
  > no longer counts against `max_inflight_bytes` — the **deferred-work limiter** (above) is what
  > bounds that phase.
- **Configuration** (via the C-ABI struct; no environment-variable fallback anywhere anymore).
  Four groups of fields, each field falling back to a built-in default when `<=0`/empty:
    1. RESTinio tuning: `io_threads`, `http_worker_threads`, `http_read_timeout`,
       `http_write_timeout`, `http_request_timeout`, `http_max_url_size`,
       `http_max_header_name_size`, `http_max_header_value_size`, `http_max_header_count`,
       `http_max_pipelined_requests`, `http_concurrent_accepts`, `http_buffer_size` -- `remoted`
       populates these from the `remoted.http_*` internal options in `secure.c` (already
       range-validated there). `io_threads`/`http_worker_threads` are thread-count fields: a
       `<=0` value resolves via `cpp_get_nproc()` (`shared_modules/utils/proc.hpp`, cgroup-aware
       on Linux) in `httpServerConfig.cpp::resolveThreadCount()` -- see *Request lifecycle
       example* below for the exact multiplier per pool.
    2. `<remote><https>` settings, wired from the parsed config in `secure.c`'s
       `w_remoted_build_module_config()`: `port`, `bind_address`, `global_prefix`,
       `http_max_body_size`, `ca_path`, `ciphers`, `verification_mode`, `dual_stack`.
       `certificate_path`/`private_key_path` are file paths (not PEM content) opened by the
       module itself, after `remoted` has already dropped root privileges (`Privsep_SetUser()`)
       -- so both files (and `ca_path`, when configured) must be readable by the unprivileged
       user `remoted` runs as.
    3. Memory-management: `max_inflight_bytes` (bytes; default 256 MiB),
       `max_parallel_connections` (default 512) and `max_deferred_requests` (default 256) --
       populated from the `remoted.max_inflight_bytes`/`remoted.max_parallel_connections`/
       `remoted.max_deferred_requests` internal options in `secure.c` (same pattern as group 1).
       The transport still clamps the in-flight budget up to at least one max-size request at
       start(), so a too-small value can't reject everything.
    4. Downstream client + auth middleware tuning: `downstream_connect_timeout`,
       `downstream_write_timeout`, `downstream_response_timeout`, `downstream_io_threads`,
       `downstream_post_process_threads`, `downstream_max_response_body_size`,
       `jwt_max_age`, `jwt_clock_skew`, `auth_max_body_size` -- populated from the
       `remoted.downstream_*`/`remoted.jwt_*`/`remoted.auth_*` internal options in `secure.c` and translated by
       `remoted::downstream::buildDownstreamConfig()` (`downstream/downstreamConfig.cpp`) and
       `remoted::auth::buildAuthConfig()` (`auth/authTypes.cpp`) respectively; the facade calls
       both in `startHttpServer()` instead of default-constructing `DownstreamConfig{}`/
       `AuthConfig{}`. The first three are seconds in the C-ABI struct, converted to milliseconds
       internally. `downstream_io_threads`/`downstream_post_process_threads` are thread-count
       fields (`cpp_get_nproc()` on `<=0`, same as group 1). See *Deferred forwarding* and
       *Agent<->manager auth middleware* below.
  See [HTTPS Agent API](../../../docs/ref/modules/remoted/https-events-api.md#configuration) for
  the full reference (defaults, allowed ranges).
- **Restart-friendly bind:** the RESTinio acceptor sets `SO_REUSEADDR`
  (`acceptor_options_setter`), so a manager restart rebinds the port immediately instead of
  failing with `EADDRINUSE` while the previous socket lingers in `TIME_WAIT`.
- **Swapping the library:** implement a new `IHttpServer` and return it from `makeHttpServer()`;
  nothing else changes.

## Endpoints (`src/endpoints/`)

Ties the transport and the auth layer together and defines the endpoint contract; future endpoints
each get a folder here.

```
src/endpoints/
├── endpoint.hpp/.cpp        # shared contract: type aliases (Method/HttpResponse/IHttpResponder/
│                            #   AuthenticatedRequest) + the async AuthenticatedHandler typedef,
│                            #   plus errorResponseFor(AuthError) (the {"error","code"} response shape)
├── authGateway.hpp/.cpp     # runs the auth middleware, then hands the verified request + responder
│                            #   to the endpoint handler. Authentication only — body decoding is an
│                            #   injected IBodyDecoder it knows nothing about
├── statelessEndpoint.hpp/.cpp # /stateless policy: identity check + downstream target + post-processing
├── statefulEndpoint.hpp/.cpp # /stateful policy: opaque inventory-sync sessions, contract passthrough
├── statsEndpoint.hpp/.cpp    # /stats policy: forwards to modulesd's inventory sync server
└── configEndpoint.hpp/.cpp  # /config policy: near-duplicate of statsEndpoint, on purpose
└── downloadEndpoint.hpp/.cpp  # /download policy: request grammar + resource resolution + file streaming
```

- **Endpoint handler (async):**
  `using AuthenticatedHandler = std::function<void(std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder>)>;`
  It runs on the worker pool after auth succeeds and **owns delivering the response** — inline or
  later (async), by calling `responder->send(...)` exactly once. The verified request is a
  `shared_ptr<const>` so the handler can retain it across deferred stages; its body is a zero-copy
  `payload.bytes()` view, and `payload.release()` frees the body + byte budget early (keeping the
  responder) once it has been forwarded — see *Single-copy payload* above.
- **`AuthGateway`** owns one `AuthMiddleware` and exposes
  `addAuthenticatedRoute(IHttpServer&, Method, path, AuthenticatedHandler)`. It registers a raw
  async route whose worker-thread body runs the full validation (`AuthMiddleware::authenticate()`,
  always synchronous — HMAC over CPU, off the I/O threads), maps any `AuthError` through
  `errorResponseFor()` (which wraps `publicErrorFor()`) to the client status/message on failure, and
  on success calls the handler with the verified `AuthenticatedRequest` and the responder. It is
  **authentication only**: body decoding is an `IBodyDecoder` handed to its constructor, so the gateway
  never learns which encodings exist, how one is decoded, or how the memory that costs is accounted
  for — only that the step can fail with an `AuthError`. The
  facade registers **`POST /stateless`** with `stateless::makeHandler(forwarder, socketPath)`: once
  auth succeeds it cross-checks the payload's identity, then forwards the H/E batch to the engine
  over UDS (see *Deferred forwarding*) and replies from the downstream result
  (`202`/`400`/`413`/`503`); `400`/`401`/`413` auth rejections come straight from the gateway.
- **Per-endpoint policy (`statelessEndpoint.hpp/.cpp`):** each endpoint owns *what* it forwards and
  *how* it maps the answer, kept out of the generic `downstream/` machinery. `stateless::target(socket)`
  builds the engine ingest `DownstreamTarget` (`POST /events/enriched`, `application/x-ndjson`) and
  `stateless::postProcess(err, resp)` is the `PostProcessor` (the mapping above). A new endpoint adds
  its own `target`/`postProcess` (and, once there are several, its own `endpoints/<name>/` folder).
  `stateless::validatePayloadIdentity(req)` is a pure, pre-forward check: it parses the body's `H
  <json>` line with RapidJSON (`rapidjson::Document::Parse(data, length)` — non-in-situ, since the
  payload is a `string_view` into a shared, non-NUL-terminated buffer — plus `rapidjson::Pointer` for
  `/wazuh/agent/id`) and compares it, as a number, against the authenticated `agentId` (also parsed
  as a number, so `"001"` and `"1"` match). Anything that isn't a clean match — missing/malformed
  header, non-numeric on either side, or a real mismatch — collapses to `AuthError::PayloadAgentMismatch`;
  there is no partial-validation path an agent could use to skip the check.
  `stateless::makeHandler(forwarder, socketPath)` wires `validatePayloadIdentity` in front of
  `forwarder.forward(...)`: on failure it answers via `errorResponseFor()` and never forwards; this is
  the single `AuthenticatedHandler` the facade registers for `/stateless`.
- **`POST /stats` and `POST /config` (`statsEndpoint`, `configEndpoint`).** Same authenticated
  pipeline as `/stateless`, but forwarded to **modulesd's inventory sync server**
  (`queue/sockets/inventory-sync-http.sock`) instead of the engine. Nothing on THIS side interprets either
  document — but the far side does, and no longer trivially: it validates a specific shape
  (`/stats` an object keyed by module, `/config` an array of `{module, config}` pairs), rebuilds it
  into an indexable document, and writes one document per agent keyed by the agent id into
  `wazuh-agent-stats` / `wazuh-agent-config`
  (`wazuh_modules/inventory_sync_server/src/endpoints/{stats,config}Endpoint.hpp`). A malformed
  report is rejected whole, with a `400` this side maps to its own fixed message. Note the indexer
  write there is fire-and-forget, so a `200` from here means *accepted*, not *indexed* —
  `wazuh-agent-stats` is `dynamic: strict`, so an undeclared metric is dropped silently at the
  indexer. Three things differ from `/stateless`:
  - **They forward the authenticated agent id as an `X-Wazuh-Agent-Id` header.** Unlike an H/E batch,
    these documents do not carry the id, and modulesd is what writes it in — so it has to receive it.
    That is why `DownstreamTarget`/`DownstreamRequest` grew a `headers` field. The value comes from the
    Authorization header the gateway already verified, never from the body, so a document claiming a
    different agent cannot override it.
  - **They differ from each other only in what a success carries back.** `/config`'s `postProcess`
    passes the downstream body through (`200` + modulesd's JSON), unlike `/stateless` which discards it;
    `/stats` answers a fixed `{}` instead, since the agent has nothing to read back and a constant keeps
    an arbitrary downstream string off the wire. Failure statuses are collapsed to fixed local messages
    on both, so an arbitrary downstream string is never reflected back to an agent either way.
  - **The only endpoint-level validation is "body is not empty" → `400`.** Parsing is modulesd's job;
    doing it on both sides would walk the payload twice on the hot path. Rejecting an empty body here
    still saves a deferred-work slot and a UDS round trip.

  They are **deliberate near-duplicates** rather than one shared unit registered on two paths. They
  are the same shape only because this side does the same thing for both -- authenticate, forward,
  map the answer. Their payloads, downstream validation and index mappings already differ (see the
  sync server's own endpoints), and the rest will diverge too; separating them keeps that divergence a
  change to one file. Keep them in sync until they must not be.
- **`POST /stateful` (`statefulEndpoint`) — inventory synchronization sessions.** Same authenticated
  pipeline, same downstream service as `/stats`/`/config`, but the body is the agent's FlatBuffer
  `Message{FullSession}` (`application/octet-stream`) and remoted treats it as **opaque** — no
  identity parsing here; the sync server cross-checks the FlatBuffer's `Start.agentid` against the
  forwarded `X-Wazuh-Agent-Id` (403 on mismatch). Two policy differences from every other endpoint:
  - **The downstream result IS the session result**, so `postProcess` passes the sync contract's
    statuses and bodies through verbatim (`200` ok/noop, `400`, `403`, `409` checksum mismatch,
    `413`, `500` scan failed, `503` + `Retry-After`). The bodies are produced by the manager's own
    sync server (never echoed agent input), which is what makes reflecting them safe; anything
    outside that set — plus every transport failure — still collapses to a neutral `503`. Of the
    downstream headers only a digits-only `Retry-After` on a `503` is relayed (the one header in the
    contract); this is why `DownstreamResponse` grew a `headers` field (names lower-cased, capped by
    `kMaxResponseHeaderBytes`).
  - **A dedicated, longer response deadline** (`remoted.downstream_stateful_response_timeout`,
    default 20 s) flows into the target's `responseTimeoutMs` override: sessions are validated,
    indexed and flushed *within* the request, unlike the enqueue-style endpoints on the global 5 s
    default. Its default budget (2+5+20 s) deliberately stays inside `http_request_timeout` (30 s);
    raising it past that requires raising the request cap too (the facade warns at startup).
- **Handler exceptions → 500:** if an endpoint handler throws, the gateway catches it, logs a
  warning and answers `500` (`{"error":"Internal server error","code":500}`), so an exception never
  escapes onto the worker-pool thread (which would `std::terminate`). The responder's send-once
  guarantee makes the 500 a no-op if the handler had already replied.

## Control endpoint (`POST /control`) — `src/control/`

The `/control` endpoint handles **5.x agent lifecycle and keepalive messages** (startup, notify,
shutdown) over the authenticated HTTPS channel, replacing the legacy TCP text-format control messages
that 4.x agents still use. It performs version validation, updates agent status in wazuh-db, and
fetches pending tasks from task-manager for the agent.

```
src/control/
├── controlTypes.hpp          # DTOs: AgentId, StartupData, NotifyData, ShutdownData, HostInfo, HttpResponse
├── controlConfig.hpp/.cpp    # ControlConfig + buildControlConfig() from C-ABI fields
├── metrics.hpp               # ControlMetrics (remoted.control.* registry handles + wdb latency histogram)
├── controlHandler.hpp/.cpp   # ControlHandler: core business logic for all three message types
├── agentRegistry.hpp/.cpp    # AgentRegistry: thread-safe sharded map (agent metadata cache + eviction)
├── wazuhDBClient.hpp/.cpp    # WazuhDBClient: async UDS client to wazuh-db (agent status/data updates)
├── taskClient.hpp/.cpp       # TaskClient: async UDS client to task-manager (pending task fetch)
├── mergedMgWatcher.hpp/.cpp  # MergedMgWatcher: inotify + poll watcher for var/multigroups/*.mg changes
└── hashCache.hpp/.cpp        # HashCache: LRU cache for merged.mg file hashes (avoids repeated disk reads)
```

### Architecture

The `/control` endpoint is **synchronous** from the HTTP handler's perspective (replies immediately),
but internally **async** for database and task-manager operations via dedicated UDS clients. Unlike
`/stateless`, which forwards the entire request body downstream and waits, `/control` parses the
agent's message, updates the agent registry, triggers async database writes, and replies with task
data — all while keeping the HTTP handler thread free.

```mermaid
sequenceDiagram
    autonumber
    participant Ag as 5.x Agent
    participant EP as POST /control<br/>(controlEndpoint)
    participant CH as ControlHandler
    participant AR as AgentRegistry
    participant WDB as WazuhDBClient<br/>(wazuh-db UDS)
    participant TC as TaskClient<br/>(task-manager UDS)
    participant DB as wazuh-db
    participant TM as task-manager

    Ag->>EP: POST /control {"type":"startup","version":"v5.0.0"}
    Note over EP: Auth via AuthGateway<br/>Parse JSON + validate agent ID
    EP->>CH: handleStartup(id, data, callback)
    Note over CH: Version check (reject if invalid)
    CH->>WDB: getAgentGroups(id)
    WDB-->>DB: async UDS query
    DB-->>WDB: ["default","web-servers"]
    WDB-->>CH: groups
    CH->>AR: update(id, metadata)
    Note over AR: Sharded map insert/update
    CH->>WDB: updateStatusCode(id, Ok, version, "pending")
    Note over WDB: Fire-and-forget async write (version + pending keepalive)
    CH->>TC: getPendingTasks(id)
    TC-->>TM: async UDS query
    TM-->>TC: [task1, task2, ...]
    TC-->>CH: tasks
    CH->>EP: callback({"groups":[...],"tasks":[...]})
    EP-->>Ag: 200 OK + JSON response
```

### Message types

1. **`startup`** — agent sends on connect or after config reload
   - **Request**: `{"type":"startup","version":"5.0.0"}`
   - Validates agent version (rejects if `< manager` when `allow_higher_versions=false`)
   - Marks agent as `pending` in wazuh-db (global.db); the first notify promotes it to `active`
   - Persists the accepted agent version and resets `status_code` (host/os data arrives later via notify)
   - Records connection timestamp
   - Fetches agent groups from wazuh-db
   - **Response**:
     ```json
     {
       "limits": {
         "fim": {"file": 30000, "registry_key": 30000, "registry_value": 30000},
         "syscollector": {"hotfixes": 30000, "packages": 30000, "processes": 30000, ...},
         "sca": {"checks": 30000}
       },
       "cluster": {"name": "wazuh-cluster"},
       "agent": {"groups": ["default", "web-servers"]}
     }
     ```
   - On version rejection: updates wazuh-db status_code to `invalid_version` and answers
     `{"error":"invalid_version"}` with **`409`** when the version is well-formed but higher than
     this manager's policy allows, or **`400`** when it is malformed. Two statuses because they are
     two different failures: the agent's client maps `409` to `VersionRejected` (REJECTED state, slow
     `startup` retry — a policy rejection can start succeeding with no change on the agent's side)
     and `400` to `Permanent` (resending the same bytes can never succeed)

2. **`notify`** — periodic keepalive (agent polls every 10 seconds; hot path)
   - **Request**:
     ```json
     {
       "type": "notify",
       "agent": {"version": "5.0.0"},
       "host": {
         "hostname": "ubuntu-test",
         "architecture": "x86_64",
         "ip": "192.168.1.100",
         "os": {"name": "Ubuntu", "version": "20.04", "platform": "ubuntu", "type": "linux"}
       }
     }
     ```
   - Optional host metadata (OS, architecture, hostname, IP) — sent on first keepalive or when values change
   - Updates agent registry with last activity timestamp
   - Conditionally writes to wazuh-db (throttled by `keepaliveThrottleSec`, default 60s):
     - **Full update** (`updateAgentData`): when host metadata is present in the request. The first
       host-carrying notify bypasses the throttle, so host/os data lands as soon as the agent reports it
       even if an earlier metadata-less notify already consumed the window
     - **Lightweight keepalive** (`updateKeepalive`): when no host metadata in the request
     - A `/startup` resets the agent's window, so the first notify after a (re)start always writes:
       startup leaves the agent `pending` in wazuh-db and only a write lifts it to `active`
   - Calculates `settings_hash` (SHA256 of `limits` + `cluster.name` **only** -- NOT groups; see
     `hashCache.cpp`'s `getSettingsHash()`, which caches one value for the whole process, so it is
     necessarily agent-independent)
   - Calculates `config_hash` (SHA256 of agent's `merged.mg` shared config file); the literal `"0"`
     when the selector resolves to no file or it cannot be hashed -- never absent, never empty
   - Mints `config_token` (`makeConfigToken()`), the `resource_id` the agent must send to
     `/download` for that config. Opaque to the agent by contract -- it relays the value verbatim
     and never parses it, which is what lets this change without an agent change. Derived from the
     same groups CSV `config_hash` was computed over, so the two can never name different files;
     today that means its value *is* the group selector. Never empty (`"default"` when the CSV is)
   - Queries task-manager for pending tasks (`status='pending'`); if found, marks as `delivered` (local only, no cluster broadcast)
   - Reads this node's current Vulnerability Detection feed offset via `VdClient` (cached, see
     `common/vdClient.hpp` below) and includes it as `vd_feed_offset` — always present, 0 if the VD
     module has never completed a feed update or is temporarily unreachable
   - **Response** (every field always present -- `tasks` is `[]` when there is no work, never an
     absent key):
     ```json
     {
       "agent": {"groups": ["web-servers"], "config_token": "web-servers", "config_hash": "e3b0c44..."},
       "settings_hash": "d7a8fbb...",
       "tasks": [],
       "vd_feed_offset": 12345678
     }
     ```
   - **With tasks**: same shape, `tasks` populated -- `[{"task_id":"...","task_type":"active_response","payload":{...}}]`
   - **Agent behavior**: compares `settings_hash` (if different → new startup), compares `config_hash` (if different → downloads `merged.mg` via `/download`, sending `config_token` back as the `resource_id`), processes tasks, compares `vd_feed_offset`
     against its stored value (if strictly higher → request a re-scan via `POST /scan/vd`, see below)
   - **Design note**: Version is NOT validated on notify (only on startup) to keep the hot path fast

3. **`shutdown`** — agent sends on clean exit
   - **Request**: `{"type":"shutdown"}`
   - Updates agent registry
   - Sets connection status to `disconnected` in wazuh-db (global.db)
   - Records disconnection timestamp
   - **Response**: `{}` (empty JSON object)

### Components

#### ControlHandler (`controlHandler.hpp/.cpp`)

Core business logic. Owns references to all clients (wazuh-db, task-manager) and the agent registry.
Implements `handleStartup()`, `handleNotify()`, `handleShutdown()` with the logic above.

Wazuh-db writes are throttled per agent via `lastKeepaliveUpdateSec` (in `AgentRegistry`) to avoid
flooding wazuh-db with writes every 10 seconds. Full updates (`updateAgentData`) are sent when the
agent includes host metadata in the notify request; lightweight keepalives (`updateKeepalive`) are
sent otherwise. Both respect the `keepaliveThrottleSec` window (default 60s), except the first
host-carrying notify (`hostPersisted` in `AgentEntry`), which always triggers a full update.

Version comparison uses `compareVersions()` (`control/controlTypes.hpp`, shared with `/enroll` -- see
below) for semantic versioning (e.g., `"v5.0.0"` vs `"v4.9.2"`), stripping leading `v`/`V` and
ignoring everything after `-` or `+`.

#### AgentRegistry (`agentRegistry.hpp/.cpp`)

Thread-safe **sharded hash map** (`std::unordered_map` per shard, each with its own `shared_mutex`)
that caches agent metadata to avoid repeated wazuh-db lookups on every keepalive. Each `AgentEntry`
stores:
- `groups` — agent's assigned groups (vector of strings)
- `groupsRefreshedAtSec` — timestamp of last groups refresh
- `lastKeepaliveUpdateSec` — timestamp of last wazuh-db write (for throttling)
- `lastActivitySec` — timestamp of last control message (any type)
- `createdAtSec` — timestamp of first insertion into registry

Supports:
- `update(id, updateFn)` — atomic read-modify-write via a lambda (returns the new entry)
- `get(id)` — read-only lookup (returns `shared_ptr<const AgentEntry>`)
- `evictExpiredEntries(ttlSec)` — periodic cleanup (two-phase: read-lock scan, then write-lock erase)

Sharding (8 shards) minimizes lock contention on high-frequency keepalives from many agents.

#### WazuhDBClient (`wazuhDBClient.hpp/.cpp`)

Async UDS client to `queue/sockets/wdb` with a **dedicated worker thread** and **bounded request queue**.
Exposes:
- `getAgentGroups(id, callback)` — synchronous UDS round-trip (startup only, not on hot path)
- `updateAgentData(...)` — fire-and-forget async write (full agent metadata)
- `updateKeepalive(...)` — fire-and-forget async write (lightweight)
- `updateStatusCode(...)` — fire-and-forget async write (e.g., invalid_version rejection)

Internally:
- Maintains a persistent connection (reconnects on error)
- Request queue with `max_queue_size` — drops requests with `SocketError::QueueFull` when full
- Per-request deadline (`deadline_ms`) — reports `SocketError::Timeout` if wazuh-db doesn't respond
- Uses `LogThrottle` to avoid flooding logs with repeated errors (connection failures, timeouts, queue full)

#### TaskClient (`taskClient.hpp/.cpp`)

Async UDS client to `queue/sockets/task` with same architecture as `WazuhDBClient`. Fetches pending
upgrade/command tasks for an agent via `getPendingTasks(id, callback)`. Returns a vector of `Task`
objects (id, type, payload JSON). Uses the same bounded queue + deadline + error throttling pattern.

#### MergedMgWatcher (`mergedMgWatcher.hpp/.cpp`)

Watches `var/multigroups/*.mg` for changes (inotify + poll fallback) to detect group shared file
updates. When a `.mg` file changes, it:
1. Hashes the file
2. Compares against the cached hash (`HashCache`)
3. If changed, marks all agents in that group for config invalidation (via callback)

This is the signal that triggers agents in a group to re-fetch their shared configuration when
`merged.mg` is updated.

#### HashCache (`hashCache.hpp/.cpp`)

Simple LRU cache (`std::list` + `std::unordered_map`) for file path → SHA256 hash. Avoids re-reading
and re-hashing the same `.mg` file on every agent keepalive. Configurable `maxSize` (default 256).
Thread-safe via a single `std::mutex`.

#### VdClient (`common/vdClient.hpp/.cpp`)

Cached UDS client for the Vulnerability Detection module's feed offset, shared verbatim between
`/control` (populates `vd_feed_offset`) and `/scan/vd` (validates the agent's requested offset —
see [Scan endpoint](#scan-endpoint-post-scanvd--srcscanvd) below for the full picture, including why
this client never blocks a concurrent caller behind a slow VD module).

#### controlEndpoint (`endpoints/controlEndpoint.hpp/.cpp`)

The HTTP endpoint registration. Parses the JSON body (validates it's an object with a `"type"` field),
extracts the agent ID from the authenticated request, and dispatches to the appropriate
`ControlHandler` method. Returns:
- `400` — invalid_body, invalid_json, invalid_agent_id, unknown_message_type
- `200` — success + JSON response body

Uses `LogThrottle` for error conditions (invalid body/JSON/agent ID, unknown type) to avoid log
flooding from malformed agent requests.

### Configuration

Via `remoted::control::Config` (`controlConfig.hpp/.cpp`), populated by `buildControlConfig()`
from C-ABI struct fields in `remoted_module_config_t`; the tunable ones are fed by
`remoted.control_*` internal options (`secure.c`, `remoted_module_control_config()`):

| `Config` field | Default | Internal option (`wazuh-manager-internal-options.conf`) |
|---|---|---|
| `managerVersion` | `__wazuh_version` | — (manager's own version, for comparison) |
| `allowHigherVersions` | from XML | `<remote><agents><allow_higher_versions>` |
| `isWorkerNode` | from cluster config | — |
| `groupsRefreshIntervalSec` | 60 s | `remoted.control_groups_refresh_interval` (1–3600) |
| `wdbRequestConnections` | 4 | `remoted.control_wdb_request_connections` (1–64) |
| `wdbRoundtripDeadlineMs` | 2000 ms | `remoted.control_wdb_roundtrip_deadline` (100–30000) |
| `wdbMaxQueueSize` | 10000 | `remoted.control_wdb_max_queue_size` (100–1000000) |
| `tmConcurrency` | 4 | `remoted.control_tm_concurrency` (1–64) |
| `tmDeadlineMs` | 2000 ms | `remoted.control_tm_deadline` (100–30000) |
| `tmMaxQueueSize` | 10000 | `remoted.control_tm_max_queue_size` (100–1000000) |
| `wdbSocketPath` | `/queue/sockets/wdb.sock` | — (fixed) |
| `taskSocketPath` | `/queue/sockets/task.sock` | — (fixed) |
| `registryEvictionTtlSec` | 21600 s (6 h) | — **not configurable** (compile-time constant; never assigned from the C-ABI) |
| — eviction cadence | 300 s | — **not configurable** (`kRegistryEvictionIntervalSec`, used as a literal by the eviction thread) |
| `keepaliveThrottleSec` | 60 s | `remoted.control_keepalive_throttle` (1–3600) |

### Metrics

`ControlMetrics` (`metrics.hpp`) caches the `remoted.control.*` family, resolved from the
facade's shared `wazuh_metrics` registry (`shared_modules/metrics`) via `makeControlMetrics()`:
- `remoted.control.startup` — total `POST /control {"type":"startup"}` messages
- `remoted.control.notify` — total `POST /control {"type":"notify"}` messages
- `remoted.control.shutdown` — total `POST /control {"type":"shutdown"}` messages
- `remoted.control.wdb_error` — wazuh-db operation failures (connection, timeout, queue full)
- `remoted.control.task_fetch` — successful task fetches from task-manager
- `remoted.control.task_fetch_error` — task-manager operation failures
- `remoted.control.rejected` — the endpoint's own 400s (invalid body/JSON/agent-id/type), one
  counter for all four paths: it answers "are agents sending malformed control traffic"
  (agent/manager version drift); the throttled logs keep the which-field detail
- `remoted.control.wdb.latency` — histogram (µs) of SUCCESSFUL wazuh-db round trips (timeouts
  are wdb_error's, so the histogram keeps meaning "how long a healthy round trip takes" — the
  number that sizes the internal options `remoted.control_wdb_roundtrip_deadline` /
  `remoted.control_wdb_request_connections`)
- `remoted.control.registry.agents` — pull metric over `AgentRegistry::size()` (registered by
  the facade; weak target, quiesces to 0 once the control plane is torn down)

Each `inc*` helper is a single relaxed atomic op (and a silent no-op on a default-constructed,
all-null struct — the null object the unit tests use). The registry is dumped as JSON to the debug
log when the module stops; it is NEVER exposed through the public HTTPS endpoint (agent-facing,
not an admin plane). The full per-family catalog, including the data-plane and backpressure
families, lives in **Metrics catalog** below.

### Error handling

- **Version rejection**: `{"error":"invalid_version"}` + wazuh-db update (status_code=`invalid_version`); `409` when too high for policy, `400` when malformed
- **Database errors**: `500 {"error":"database_error"}` (wazuh-db down or timeout)
- **Queue full** (wazuh-db or task-manager): drops the operation, logs warning (throttled), continues
- **Invalid JSON/malformed request**: `400` with specific error code (invalid_body, invalid_json, etc.)

All errors use `LogThrottle` (90-second windows) to avoid log flooding:
- WARN-level: version rejections, wdb errors, queue full, timeouts
- DEBUG2-level: per-request success logs (startup, notify, shutdown)

### Thread safety

- **AgentRegistry**: sharded with per-shard `shared_mutex` (concurrent reads, exclusive writes)
- **WazuhDBClient / TaskClient**: single worker thread per client, requests queued via `std::queue` + mutex + CV
- **ControlHandler**: stateless (all state in registry + clients), thread-safe via client APIs
- **HashCache**: single `std::mutex` protecting LRU list + map

The HTTP handler threads call `ControlHandler` concurrently; the handler coordinates via the registry
and clients, which are all thread-safe internally.

### Lifecycle

1. **Startup**: `RemotedModuleFacade::start()` builds `ControlConfig`, creates all clients
   (wazuh-db, task-manager), creates the registry, creates `ControlHandler`, and registers
   `POST /control` via `controlEndpoint::makeHandler(handler)`.
2. **Runtime**: HTTP worker threads process `/control` requests concurrently. The registry eviction
   thread runs periodically (every `agentRegistryEvictionIntervalSec`). Wazuh-db and task-manager
   clients maintain persistent connections (reconnect on error).
3. **Shutdown**: `RemotedModuleFacade::stop()` stops the HTTP server (drains in-flight requests),
   then stops the wazuh-db and task-manager clients (drains their queues), then destroys the
   registry (eviction thread stops automatically on destruction).

## Scan endpoint (`POST /scan/vd`) — `src/scanvd/`

`/scan/vd` is the on-demand Vulnerability Detection re-scan request: an agent that notices (via
`/control`'s `vd_feed_offset`, above) that this node's feed has moved past what it last synced
against asks this node to re-scan it. It replaces the pre-HTTPS mechanism, where each node held a
persistent connection to a fixed set of agents and, on every feed update, queried global.db for
"its" agents and rescanned all of them — a mechanism that assumed a stable agent-to-node mapping
that stateless HTTPS load balancing no longer provides.

```mermaid
sequenceDiagram
    participant Ag as Agent
    participant EP as POST /scan/vd<br/>(scanVdEndpoint)
    participant SH as ScanVdHandlerImpl
    participant VC as VdClient
    participant VD as vulnerability_scanner<br/>(UDS)

    Ag->>EP: POST /scan/vd {"type":"feed_update","feed_offset":100}
    EP->>SH: handleVdScan(agentId, 100, callback)
    SH->>VC: getOffset()
    VC-->>SH: 100 (matches)
    SH->>VD: POST /vulnerability-detector/scan {"agent_id":"..."}
    VD-->>SH: 200 {} (queued in VD's dispatch lane -- it WILL run)
    SH-->>EP: Accepted
    EP-->>Ag: 200 OK {}

    Note over VD: VD's single worker runs the scan later.<br/>its outcome lands in modulesd's log
```

The whole exchange is synchronous: remoted holds no scan state and relays VD's **admission**
answer. A `200` therefore genuinely promises the scan will run; anything VD refuses (dispatch
lane full, feed mid-update, module stopping, no indexer host available) or a failed round trip
becomes an honest `503` the agent's next `/control` notify retries. The previous design — a
tracking table plus a worker pool retrying with backoff *behind an already-sent 200* — could
exhaust its retries and silently drop scans the agent believed were handled.

### Components

#### scanVdEndpoint (`endpoints/scanVdEndpoint.hpp/.cpp`)

The HTTP endpoint registration. Parses the JSON body (`type`, `feed_offset`), validates the agent
ID, and dispatches to `ScanVdHandler::handleVdScan()`. Maps each `ScanVdOutcome` to its wire
response:
- `Accepted` → `200 {}` (VD queued the scan)
- `VersionMismatch` → `409 {"error":"version_mismatch","current_version":N}`
- `VdRejected` → `503 {"error":<VD's own cause>}` — `scan_queue_full`, `feed_not_ready`,
  `scanner_not_ready`, `vd_not_initialized`, `shutting_down`, `indexer_unavailable`, or
  `vd_unreachable`/`vd_error` when the relay leg itself failed
- `InvalidAgent` → `400 {"error":"invalid_agent_id"}`
- Request-shape errors (empty/oversized body, malformed JSON, missing/invalid `type` or
  `feed_offset`) → `400` with a specific `error` code (see
  [https-events-api.md](../../../docs/ref/modules/remoted/https-events-api.md#scan-endpoint-post-scanvd))

Body cap is 4 KiB (`kMaxScanVdBodySize`), far tighter than `/control`'s 64 KiB — a scan request only
ever carries `type` and `feed_offset`.

#### ScanVdHandlerImpl (`scanvd/scanVdHandler.hpp/.cpp`)

A stateless, synchronous passthrough of VD's admission, run entirely on the HTTP handler thread
(the transport's request pool exists for handlers that do synchronous downstream round trips):

- Rejects `agentId == 0` outright; queries `VdClient::getOffset()` and rejects with
  `VersionMismatch` unless the request's `feed_offset` matches exactly.
- Makes **one** inline `POST /vulnerability-detector/scan` to the VD module (over the *same*
  `vd-http.sock` UDS socket `VdClient` uses for `/offset` — see below), with a 5 s timeout: VD
  answers at **admission** into its bounded dispatch lane (64 slots, per-agent dedup of queued
  items), so the round trip is inline route work measured in milliseconds, never a scan.
- Relays the answer honestly: VD's `200` → `Accepted`; any VD refusal → `VdRejected` carrying
  VD's own error code — `indexer_unavailable` included, which keeps its own counter and is VD's
  own cause to log, exactly like `scan_queue_full`, never folded into the relay-failure window
  below; an unreachable socket or unexpected status → `VdRejected` with
  `vd_unreachable`/`vd_error` (logged throttled, one line per 90 s window with its count).
- **No retry, by design**: the agent's pending state survives a `503` and its next `/control`
  notify re-requests — retrying here would only duplicate that loop with a worse deadline.
  Dedup of repeated requests lives in VD's lane, next to the queue it protects; queued scans
  cannot go stale because a scan always runs against the feed that is current at execution
  time (the POST carries no offset).

#### VdClient (`common/vdClient.hpp/.cpp`)

Already introduced under [Control endpoint](#control-endpoint-post-control--srccontrol) above,
since it's the same client instance — this is the rest of its contract. `getOffset()`:

1. Returns the cached offset immediately if still within TTL (default 30s).
2. Otherwise, exactly one caller becomes the "refresher" and performs the actual UDS round trip to
   `GET /vulnerability-detector/offset`; every other concurrent caller gets the last-known-good
   cached value instead of blocking behind it. This matters because `/control` is a hot path (every
   connected agent's `notify`, every ~10s) — without single-flight, a slow or hung VD module could
   serialize the entire node's control-plane throughput down to roughly one request per query
   latency.
3. On a failed refresh, the last known-good value is returned (0 if none was ever obtained), and
   the next attempt is gated to a short, separate `failureRetryInterval` (default 5s) rather than
   the normal 30s TTL — recovers quickly once VD comes back, without hammering it (or serializing
   every caller) on every single call during an outage.

### Metrics

`ScanVdMetrics` (`scanvd/scanVdMetrics.hpp`) caches the `remoted.scanvd.*` counter family —
admission decisions only, since that is all this handler does: `requests.total`,
`version_mismatch`, `queue_full` (VD's lane at capacity), `invalid_agent`, `accepted` (VD queued
it), `indexer_unavailable` (VD reports no healthy indexer host — its own cause, kept off the
relay window below), `vd_error` (any other relayed 503: unreachable, not ready, stopping).
Resolved from the facade's shared `wazuh_metrics` registry via `makeScanVdMetrics()` and
incremented inline at each outcome — same shape (and same null-object contract) as
`ControlMetrics`. What became of an accepted scan is the VD module's to report (it logs each
outcome per agent).

### Lifecycle

`ScanVdHandlerImpl` shares its `VdClient` instance with `ControlHandler` (constructed once in
`RemotedModuleFacade::start()` and passed to both), so the two endpoints never see different
offsets due to independent cache state. It owns no threads and no queue — teardown is trivial.

## Agent enrollment (`POST /enroll`) — `src/enrollment/`

Every other authenticated route on this server requires the caller to already be a known agent with
an entry in `etc/client.keys` — there is no such entry for an agent that has never enrolled. Today
that agent falls back to a second protocol on a second port: legacy `wazuh-authd` on 1515, speaking
the plaintext-inside-TLS `OSSEC A:'...'`/`OSSEC K:'...'` line format. `/enroll` lets it enroll over
the same HTTPS channel (1517) it uses for everything else afterward.

This is a **bridge, not a rewrite**: authd keeps owning every piece of enrollment business logic —
name/IP/group validation, key generation, agent-ID assignment, force-replace decisions, `client.keys`
and `wazuh-db` persistence, cluster forwarding. `enrollmentEndpoint` only authenticates the request,
validates the handful of things authd's *local* interface doesn't check for it (see below), and
relays the request to authd over its existing local Unix-domain socket — the same one `manage_agents`
and the framework already use. Port 1515 is untouched and keeps working exactly as it does today, for
legacy 4.x agents that never speak HTTPS. **`/enroll` is the intended long-term enrollment path**;
1515 stays alive only for that backward-compatibility window, not as a permanent second design.

```mermaid
sequenceDiagram
    autonumber
    participant Ag as New agent (no client.keys entry)
    participant EP as POST /enroll<br/>(enrollmentEndpoint)
    participant EA as EnrollmentAuthenticator
    participant PK as PasswordKeySource<br/>(etc/authd.pass)
    participant AC as AuthdClient
    participant AD as authd<br/>(queue/sockets/auth.sock UDS)

    Ag->>EP: POST /enroll {"name":...,"version":...,"groups":...}
    Note over EP: enrollment_enabled? -- 403 immediately if not, before auth/bridge
    Note over EP: If the listener requires a client cert, TLS already rejected the<br/>connection before this request could ever arrive here
    EP->>EA: authenticate(protocolVersion, authorization, bodySize, now)
    alt requirePassword
        EA->>PK: currentKey()
        PK-->>EA: HKDF-derived HS256 key (or nullopt)
        Note over EA: verify the wazuh-enroll+jwt bearer (JwtEnrollTokenVerifier)
    else not requirePassword
        Note over EA: always-pass -- nothing left for THIS class to check
    end
    EA-->>EP: ok / AuthError
    Note over EP: parse JSON, validate name/version/groups/ip
    EP->>AC: addAgent({name, ip, groups, key_hash})
    AC->>AD: {"function":"add","arguments":{...}} (SizeHeaderProtocol)
    AD-->>AC: {"error":0,"data":{id,name,ip,key}} or {"error":90xx,...}
    AC-->>EP: AuthdResult
    EP-->>Ag: 200 {id,name,ip,key} / mapped 4xx/5xx
```

### Two independent authentication gates

Unlike every other route, `/enroll` cannot be gated by `AuthGateway`'s `client.keys` lookup — the
caller has no key yet. Two checks apply instead, decided once at facade startup from how the HTTPS
listener and authd are each configured — never per request — and, critically, **independently of
each other**:

- **Client certificate** — purely a property of the HTTPS listener's `ClientVerificationMode`
  (`Certificate` or `Full`). When set, the TLS handshake validates the agent's client certificate
  against `root-ca.pem` **before the request ever reaches a handler** — `EnrollmentAuthenticator`
  is never even consulted for this; it has no notion of a client certificate at all. Mirrors
  authd's own `agent_ca`/`ssl_verify_host` mode.
- **Password (`EnrollmentAuthConfig::requirePassword`)** — set whenever authd's `use_password`
  flag is on, regardless of whether the listener also requires a client certificate. When set, the
  request must carry `Authorization: Bearer <wazuh-enroll+jwt>`: a JWT of the closed enroll profile
  (`shared_modules/utils/jwt/jwtEnrollProfileV1.hpp`) — header exactly `{alg: HS256, typ:
  wazuh-enroll+jwt}` (no `kid`, one shared key), claims exactly `{exp, iat, jti, nbf}` (no
  `iss`/`sub`, no identity yet), `exp - iat = 60`, verified by the shared
  `JwtEnrollTokenVerifier` with the `TimePolicy` every route reads
  (`remoted.jwt_max_age` / `remoted.jwt_clock_skew`).

  `EnrollmentAuthenticator::authenticate()` checks the `protocol-version` header first — before the
  body-size cap and before any credential, in **every** mode including the credential-less one — and
  rejects anything other than `remoted::auth::kSupportedProtocolVersion` with
  `MissingProtocolVersion` / `UnsupportedProtocolVersion` (both `400`), the same errors
  `AuthMiddleware::authenticate()` raises at its own step 1.

  Deliberately the same core as the agent<->manager `wazuh-agent+jwt` bearer used everywhere else
  in this module — same compact grammar, HS256, time rules and `AuthError` taxonomy (shared
  `jwtCompactGrammar.hpp`) — with a different `typ` and no identity claims, since an enrolling
  agent doesn't have one. A token of either profile presented to the other's verifier fails on its
  exact header set before the signature is even considered, so the two can never be confused.

  The signing key is not the password itself: `PasswordKeySource` derives a 32-byte key from it
  with the shared `enrollKeyDerivation.hpp` — **HKDF-SHA256**, salt 32 × 0x00,
  `info = "WAZUH-ENROLL-JWT-KEY\x01"` — the single construction the agent's `EnrollSigner` runs
  too, so the two cannot drift. HKDF is deterministic and salt-free on purpose (any implementation
  reproduces it with a handful of standard-library calls); the version byte in `info` reserves room
  to change the construction later without ambiguity. A memory-hard KDF would add nothing here — the derived
  key is never persisted, so the offline-guessing surface already matches authd's own
  plaintext-password-over-TLS on 1515.

  **Frozen known-answer vector** (shared by every implementation — `test_vectors::enroll` in
  `shared_modules/utils/jwt/testVectors.hpp`, mirrored under `"enroll"` in
  `tools/manager_benchmark/tool_simulator/internal/wire/testdata/jwt_vectors.json`, computed with
  Python's standard library as an independent oracle):
  - Password: `MyEnrollmentSecret123`
  - HKDF-SHA256 derived key: `eeecc651648436211783381e38d0a661bfecc2888a4e23b28c94f415f98616b6`
  - Header / claims (`iat` 1700000000, `jti` from bytes `00..0f`):
    `{"alg":"HS256","typ":"wazuh-enroll+jwt"}` /
    `{"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}`
  - Token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH0.Ll9rqCc4D0emY3xUV99-yD-ep0Xp7CI1qKG8Rzkvm8o`

  (Pinned on the C++ side by `enrollKeyDerivation_test.cpp` / `jwtEnrollSignVerify_test.cpp` /
  `passwordKeySource_test.cpp`, on the agent by `enrollSigner_test.cpp`, and in Python by
  `wire_jwt.py --self-test`.)

  The token does not cover the request body (TLS protects it), and there is no replay store: a
  captured token could be replayed inside its window (`jwt_max_age + jwt_clock_skew`, 90 s by
  default), bounded in practice by authd's own duplicate-name/IP rejection (unless force-replace is
  configured to permit it). Accepted for v1 — the same threat model the agent bearer carries, with
  TLS protecting the transport; `jti` lets a replay cache be added later without changing the wire.

When `requirePassword` is false — whether because the listener requires a client certificate
instead, or requires nothing at all — `EnrollmentAuthenticator` runs an always-pass check with no
header required. This is not a new exposure: it reproduces authd's own behavior today, where a
NULL password makes `w_auth_parse_data` skip the `PASS:` check entirely.

**Both gates apply simultaneously when both are configured**, exactly as legacy authd already
behaves: authd's own `check_x509_cert()` (at the TLS handshake) and its `use_password` check (while
parsing the enrollment message, `main-server.c:601`/`:886`) are two independent checks on the same
connection today, not a mutually-exclusive choice. `EnrollmentAuthConfig` models this the same way
— `requirePassword` says nothing about client certificates, and the listener's
`ClientVerificationMode` says nothing about passwords — so an operator who wants both enforced
together (defense in depth for the endpoint that mints new agent identities and keys) simply
configures both, and gets both. See `enrollmentMtlsE2E_test.cpp` for the combined case exercised
end-to-end over a real TLS listener.

A missing or unreadable `etc/authd.pass` while `requirePassword` is true fails **closed** — every
enrollment attempt gets `401`, never silently falls back to skipping the password check. This
mirrors authd itself: `etc/authd.pass` is one of the files the cluster's own integrity sync already
replicates from master to every worker (`framework/wazuh/core/cluster/cluster.json`, alongside
`client.keys`), and authd treats "password required but not yet synced" as a hard rejection, never
as a fallback to the NULL-password path (`main-server.c:777-790`) — conflating the two would let an
unsynced worker accept anyone. `PasswordKeySource` is **strictly read-only** on every node, master
or worker alike: only authd's master ever generates the password file (`w_authd_load_password`); a
worker only reads it, exactly as authd's own `run_authpass_watcher` does.

### Components

#### `PasswordKeySource` (`auth/passwordKeySource.hpp/.cpp`)

Turns the authd password file into the `wazuh-enroll+jwt` HS256 key (shared HKDF), hot-reloaded without a restart. Mirrors
`Keystore`'s watcher exactly (inotify + a poll fallback + content-hash change detection, so a rewrite
landing mid-read can never be adopted torn) — the two files have the same operational shape, an
operator-managed secret a running process must notice without a bounce. Parsing must byte-match
authd's own `read_password_line()`: first line only, trailing `\r`/`\n` stripped, length `<= 2` or
all-whitespace rejected, a 4096-byte cap — otherwise the manager's two enrollment paths could disagree
about which password is valid. Derivation runs once per file change and is cached — never per
request.

#### `EnrollmentAuthenticator` (`enrollment/enrollmentAuthenticator.hpp/.cpp`)

Implements the Password gate above, and nothing about client certificates at all — that's the TLS
listener's exclusive concern, checked before any handler runs, which is exactly why this class has
no "mode" spanning both: `requirePassword` gates the Password check alone, and is independent of
`timePolicy`/`maxBodySize` (the accepted token age + skew and the body-size cap, sourced from the
SAME `jwt_max_age`/`jwt_clock_skew`/`auth_max_body_size` internal options the agent<->manager
scheme reads, so the two never silently disagree). The body-size check runs first and
unconditionally — in Open mode too — so an unauthenticated peer can never make this endpoint hold
an arbitrarily large body before being rejected; the token itself is verified from the header
alone. Reuses the shared `JwtEnrollTokenVerifier`, `toAuthError()` and the `AuthError` taxonomy
from `auth/authTypes.hpp`, so a bad signature, a stale token, a malformed token and an oversized
body all collapse through the same `publicErrorFor()` → `401`/`413` path every other route already
uses — `401`s carry `WWW-Authenticate: Bearer` here too. Because `AuthGateway` bakes the `client.keys`
`Keystore` into its middleware with no per-route key-source hook, `/enroll` does **not** go through
`AuthGateway` at all — it registers directly on `IHttpServer::addRoute` (the same pattern the
unauthenticated `GET /` liveness probe already uses) and drives this authenticator itself, with
`countAgainstBudget=true` since, unlike the liveness probe, an enrollment request carries a real
body and does real work.

**No credential re-validation happens on authd's side, by design.** authd's local socket has never
validated passwords or certificates for any caller, including today's `manage_agents`/API caller — it
has always been "trust the caller, validate only business rules." Credential checking lives
exclusively at each front door (1515's TLS+`PASS:` line, or here). authd structurally *can't*
re-check either credential even if it wanted to: the plaintext password never leaves remoted, and no
TLS session reaches the local socket. remoted and authd already run as the same OS service account
(`Privsep_SetUser()` against the shared default `USER "wazuh"`), so the bridge crosses no new
privilege boundary — it joins the same trust domain `manage_agents` already sits in.

#### `AuthdClient` (`enrollment/authdClient.hpp/.cpp`)

The bridge to authd's local socket `queue/sockets/auth.sock`, framed with `shared_modules/utils`'s
`Socket<OSPrimitives, SizeHeaderProtocol>` — a 4-byte little-endian length prefix, the exact framing
`OS_SendSecureTCP`/`OS_RecvSecureTCP` use. Unlike `control/taskClient.cpp`/`control/wazuhDBClient.cpp`,
it does **not** use `shared_modules/utils`'s `SocketClient` async wrapper, even though it drives the
same underlying `Socket` class: authd closes the connection after **every** reply, so `AuthdClient`
connects, sends one frame, awaits one frame, and closes — per request, on its own dedicated worker
thread — rather than keeping a persistent, multi-request connection the way `SocketClient` is built
for. `SocketClient::connect()` is asynchronous (it starts a background thread and returns before the
connection exists), which is fine for `TaskClient`/`WazuhDBClient` — they connect once and only send
much later, well after that thread has settled — but is exactly wrong for a connect-then-immediately-
send-every-time client: an earlier version of this class did use `SocketClient` and lost that race
far more often than not, so `authd` would receive and successfully process a request while the reply
arrived on a connection nothing was listening on anymore, and the caller saw a spurious timeout for an
enrollment that had actually already succeeded. `AuthdClient` instead calls `Socket::connect()`
directly in **blocking** mode: it returns only once genuinely connected, or throws immediately on a
real failure, with no race and no background thread — and, as a side effect, an absent authd is now
distinguishable from a slow one (a fast "could not connect" instead of waiting out the full response
timeout). The response wait itself is bounded the same way authd's own `OS_SetRecvTimeout` bounds its
side: `SO_RCVTIMEO`/`SO_SNDTIMEO` set directly on the connected socket.

Wire request: `{"function":"add","arguments":{"name":...,"ip":...,"groups":...,"key_hash":...}}`.
**`force`, `id`, and `key` are never sent** — self-enrollment always gets an auto-assigned ID and an
authd-generated key, never a caller-supplied one; `force` stays a manager-config decision, exactly as
authd's local path already falls back to `config.force_options` from `ossec.conf` when it's absent.
This matches 1515's own agent-facing protocol exactly, not a new restriction: `w_auth_parse_data`
(`os_auth/src/auth.c`) recognizes only `PASS:`, `A:` (name), `V:` (version), `G:` (groups), `IP:`, and
`K:` — a **key hash**, feeding only the force/key-mismatch decision, never a raw key. There is no
`ID:` token and no raw-key token in that parser either, and no wire field for `force` at all. This
module's optional `key_hash` field is the direct equivalent of 1515's `K:` token.

**Response timeout is worker-aware.** authd's own worker→master forward can legitimately take several
seconds on a flaky cluster link: `w_request_agent_add_clustered` → `w_send_clustered_message` retries
up to `CLUSTER_SEND_MESSAGE_ATTEMPTS = 10` times with a 1 s sleep between failures
(`shared/src/agent_op.c`). If `AuthdClient`'s response timeout were shorter than that, a worker-node
enrollment authd is legitimately still retrying would be cut off early as a spurious `503`. It reads
the same `isWorkerNode` flag already plumbed into `ControlConfig` and uses a longer default (~15 s,
covering the worst-case retry budget) on workers versus a short default (~5 s, matching
`WazuhDBClient`/`TaskClient`, since there's no cluster hop on the master).

**Fixed: this retry no longer serializes behind authd's local-socket dispatch.** `run_local_server`
(`os_auth/src/local-server.c`) used to be a plain accept→recv→dispatch→send→close loop with no
per-connection thread, so while one worker-node `add` was inside
`w_request_agent_add_clustered`'s up-to-10-second retry budget, that ONE thread could not accept or
serve ANY other local-socket client -- another queued `/enroll` request, `manage_agents`, or the
API -- for the same window. This was not a risk this bridge introduced on its own: port 1515's own
worker-node enrollment forwarding calls the exact same `w_request_agent_add_clustered` inline on its
own single event loop (`run_remote_server`'s epoll thread, `main-server.c`), blocking every other
concurrent 1515 connection the same way -- but the local socket previously had no such exposure at
all (every `add` on a worker failed instantly with `9015`, before cluster forwarding existed for
it), so `manage_agents`/the API/`/enroll` would have been newly subject to a latency class 1515 has
already lived with. `run_local_server` now hands each accepted connection to its own detached
thread (`handle_local_client`) instead of dispatching inline, so a single slow or stuck cluster
forward only holds up the ONE connection waiting on it. This is safe to parallelize without any
further locking changes: every `local_add()`/`local_remove()`/`local_get()` call already serializes
access to the shared `keys` keystore (and `write_pending`/`cond_pending`) through the existing
`mutex_keys`, which every one of those functions already takes. Port 1515's own equivalent blocking
window (its epoll loop, not this one) is unchanged -- fixing that would be a separate, larger change
to `run_remote_server`'s connection model and is out of scope here.

**Bounded, not unbounded.** The number of connections serviced concurrently via a detached thread
is capped at `MAX_LOCAL_CLIENT_THREADS` (128, matching `AUTH_LOCAL_SOCK`'s own listen backlog --
there is no benefit to servicing more concurrently than that many could ever be queued at once).
Without this cap, a burst of connections -- e.g. many cluster workers enrolling against one
master's `authd` at the same time (`N` workers × up to `authd_worker_threads` each), or any local
caller not otherwise rate-limited -- would spawn one thread per connection with no ceiling at all.
At the cap, `run_local_server` falls back to servicing the connection synchronously, inline on the
accept loop, exactly like every connection was handled before this change -- self-limiting by
construction, rather than either growing the thread count without bound or dropping the client.

#### `enrollmentEndpoint` (`enrollment/enrollmentEndpoint.hpp/.cpp`)

The HTTP registration and glue: checks `enrollment_enabled` first (see *Enrollment scoping* below),
runs the authenticator, parses the JSON body, validates fields authd's local interface does not (see
below), resolves the agent's IP, calls `AuthdClient::addAgent`, and maps the result to an HTTP
response.

**Request** — `POST /enroll`, `application/json`:

| field | required | notes |
|---|---|---|
| `name` | yes | 2-128 chars, no leading `.`, charset `[A-Za-z0-9._-]` only -- byte-for-byte `OS_IsValidName()` (`shared/src/agent_validate_op.c`), the same rule the legacy port-1515 path applies, so both enrollment paths accept exactly the same set of names. authd's local socket (`local-server.c`) separately enforces a deliberately looser *storage-safety* floor for all of its callers (`is_storable_agent_name()`: no whitespace or control bytes, no leading `#`/`!`, non-empty, <=128 chars) -- historically it trusted every caller to have validated the name, which was never true for /enroll, but it cannot adopt `OS_IsValidName()` itself without breaking `manage_agents`/API names that predate this endpoint (`%`, single-character, leading `.`). /enroll therefore holds the tighter line here rather than relying on that floor |
| `version` | yes | authd's local `add` path has no version check at all, so remoted enforces `allow_higher_versions` itself, reusing `compareVersions()` (`control/controlTypes.hpp`) rather than duplicating it |
| `groups` | no | comma-separated string, passed through unchanged — matches authd's own wire format and `w_auth_validate_groups` with zero transformation |
| `ip` | no | syntactic IPv4/IPv6/CIDR check, or one of two sentinels (`any`, `src`); see IP resolution below |
| `key_hash` | no | opaque passthrough that drives authd's own force/key-mismatch decision |

**IP resolution** mirrors authd's `use_source_ip` flag: if it's set (manager-side), the connection's
observed peer address wins over anything the body claims — read from `HttpRequest::remoteIp`
(`http_server/IHttpServer.hpp`), which already exists (populated from RESTinio's
`remote_endpoint().address()`) and is already unused by any handler today. Otherwise, a body `ip` of
`"src"` (the agent-side sentinel — mirrors legacy port 1515's own `IP:'src'` wire convention,
os_auth/src/auth.c:208, sent by an agent configured with its own client-side `<use_source_ip>`) ALSO
resolves to the observed peer address, and is never forwarded to authd as the literal string "src":
authd's local `add` path has no notion of that sentinel at all (only port 1515's TEXT-protocol
parser does) and would reject it as an invalid IP (9006). Otherwise the body's `ip` is used if
present; if none of the above applies, `"any"` is sent, matching authd's own literal handling of
that value.

**Success — `200`**: `{"id":"...","name":"...","ip":"...","key":"..."}`, verbatim from authd's `data`.
**Failure**: `{"error":{"code":<authd-code-or-0-or--1>,"message":"..."}}`.

| authd code | meaning | HTTP |
|---|---|---|
| 9001 / 9002 / 9009 | internal / JSON-parse / key-generation failure | 500 |
| 9003 / 9004 / 9005 / 9006 / 9014 / 9017 (new) | bad function/args/name/ip/groups | 400 |
| 9007 / 9008 / 9012 | duplicate ip/name/id | 409 |
| 9013 | `max_agents` reached | 503 |
| 9015 | worker rejection (`remove`/`get`, or an `add` that supplied a caller-chosen `id`/`key` -- see below) | 503 |
| 9016 (new) | clustered forward to master failed (transport leg of `w_request_agent_add_clustered`) | 503 |
| transport failure (authd unreachable) | — | 503 |
| bad/missing/stale credential | — | 401 |
| local schema or version validation failure | — | 400 |
| enrollment administratively disabled | — | 403 |

`9013`/`9016` map to `503` rather than `429`: both are server-side conditions an operator resolves
(raise `max_agents`, fix the cluster link), not something the caller can fix by slowing down — `429`
would suggest the wrong remedy. `9016` exists because a failed clustered forward previously had no
dedicated code and fell through to generic `9001`/`500`, misrepresenting a transient cluster hiccup as
a server bug.

**`/enroll` is always registered — disabled enrollment answers `403`, never a missing route.**
Considered making registration itself conditional on `enrollment_enabled` (404 when off), rejected
because a 404 conflates two very different situations for both operators and an agent's own fallback
logic: "this manager is too old to have `/enroll`" versus "this manager has it but an admin turned it
off." `403` is also the more semantically precise status here: it signals a persistent policy decision
("understood, not authorized, won't change without a config edit"), unlike this design's own `503`
usage elsewhere (authd down, `max_agents`) which implies a transient condition that might resolve on
its own — disabling enrollment via config isn't that. It also matches this module's existing
philosophy of never letting a capability silently vanish, the same way `/scan/vd` always answers with
an explicit rejection reason rather than disappearing when VD isn't ready.

### authd-side change: cluster workers

authd's local socket rejects every JSON function on a worker node (`error 9015`) before it even parses
the request — only the 1515 network path knows how to forward enrollment to the master, via
`w_request_agent_add_clustered` (`os_auth/src/main-server.c`). The fix lives in authd itself:
`os_auth/src/local-server.c`'s worker gate moves to after the request is parsed, and on a worker,
`"add"` specifically takes the same `w_request_agent_add_clustered` path 1515 already uses, returning
the new `9016` when its transport leg fails; `"remove"`/`"get"` keep returning `9015` unchanged.
remoted stays completely unaware of cluster topology — it always just talks to the local socket.

**Cluster forwarding is gated on the request SHAPE, not just the function name.** `local_add_clustered()`
has no `id`/`key` parameters at all -- it only ever produces a self-enrollment-shaped result (an
auto-assigned ID, an authd-generated key), the same contract `/enroll` and port 1515 already have.
`manage_agents`/`framework/wazuh/core/agent.py`, on the other hand, can supply a caller-chosen `id`
and/or `key` on this same local socket (an admin/restore-style add, e.g. importing a specific agent
record) -- before this fix, EVERY `add` on a worker got a blanket `9015`, so that shape was rejected
too, just not distinguished from any other. Forwarding it through `local_add_clustered()` unchanged
would silently drop the caller's `id`/`key` and return `200` with a DIFFERENT identity than the one
requested, since nothing in that function's signature has anywhere to put them. So the gate now
checks: if the parsed request carries an `id` or a `key`, it still gets the original `9015` (an
honest "can't do this here" rather than a wrong answer); only the self-enrollment shape (`id`/`key`
absent) reaches `local_add_clustered()`.

This is a real, currently-hit gap for the self-enrollment shape specifically -- and a **net-new
capability that regresses nothing else**: the API's `POST /agents`/`POST /agents/insert` dispatch
through `DistributedAPI` with `request_type='local_master'`, which forwards the *entire HTTP request*
to the master node first whenever the local node isn't the master (`core/cluster/dapi/dapi.py`) for
that specific REST path -- but `core/agent.py`'s `add()` (the function that can attach `id`/`key`) is
also reachable through other, non-DAPI-gated callers on a worker (`manage_agents`, or any future
internal caller), which is exactly why the id/key-present shape keeps its own explicit `9015` above
rather than assuming DAPI already filtered every possible caller. Mirroring DAPI's approach in
remoted (detect worker, forward the whole HTTP request to the master's remoted) was considered and
rejected: it would mean remoted reimplementing cross-node request forwarding — with its own auth — in
C, for a problem the cluster's existing low-level socket protocol already solves more cheaply by
fixing authd once.

### Enrollment scoping — independent of legacy 1515

Three flags in the existing `<auth>` config block, in order of precedence:

| `disabled` | `remote_enrollment` | `legacy_enrollment` (new) | Port 1515 | `/enroll` |
|---|---|---|---|---|
| yes | – | – | off | off |
| no | no | – | off | off |
| no | yes | yes (default) | on | on |
| no | yes | no | off | **on** |

`<remote_enrollment>` is broadened from its current, narrower meaning ("start authd's TCP 1515
listener") to a master switch for **all** remote self-enrollment, `/enroll` included — a deliberate,
release-noted behavior change for any deployment already running with `remote_enrollment=no`. The new
`<legacy_enrollment>` flag (default `yes`, so nothing changes for anyone who doesn't set it) is what
lets an operator retire 1515 specifically while keeping HTTPS enrollment: `main-server.c`'s
`thread_remote_server` (the 1515 listener) becomes gated by `remote_enrollment && legacy_enrollment`;
`thread_local_server` (the UDS socket this bridge uses) stays gated only by `disabled`, unconditional
otherwise — the bridge always has something to talk to as long as authd is running at all.
`enrollment_enabled` on the remoted side is `!disabled && remote_enrollment`; `legacy_enrollment` has
no bearing on it whatsoever, and neither flag ever unregisters the route (see above) — only its `403`.

`authd_config_t.flags.disabled` looks tri-state in its header (`AD_CONF_UNPARSED`/`AD_CONF_UNDEFINED`
sentinels), but a repo-wide search shows nothing ever sets it to `AD_CONF_UNPARSED` — the one line
that used to is commented out — so the tri-state switch in `os_auth/src/config.c` is dead code today.
It behaves as a plain boolean, defaulting to enabled (`0`) unless `<disabled>yes</disabled>` is
explicit. `secure.c` needs no special resolution logic: zero-initialize a local `authd_config_t` the
normal way, call `ReadConfig(CAUTHD, OSSECCONF, &authd_cfg, NULL)`, and read `flags.disabled` directly.

### Manager certificate unification

authd used to serve its own certificate pair (`etc/certs/authd.pem`/`authd-key.pem`), a separate
manager identity from the one this module's HTTPS server presents (`etc/certs/remoted.pem`/
`remoted-key.pem`, CA `etc/certs/root-ca.pem`). Since a client certificate on `/enroll` (when the
listener requires one) treats "this certificate validated" as an enrollment credential, both
listeners now present the *same* identity: the install-time generation step
(`GenerateAuthCert()` in `init/inst-functions.sh`, plus its RPM/DEB packaging equivalents) that used
to create `authd.pem`/`authd-key.pem` has been removed, and the generated `<auth>` config
(`auth.template`, and the `<disabled>yes</disabled>` fallback written by `DisableAuthd()`) now
points `<ssl_manager_cert>`/`<ssl_manager_key>` at `remoted.pem`/`remoted-key.pem` instead — the
same certificate `GenerateHttpsManagerCert()` already generates for the HTTPS listener. Explicit
`<auth>` certificate overrides in `ossec.conf` keep working unchanged — only the generated
defaults change. Port 1515 keeps running with the unified certificate.

Two compiled-in defaults exist alongside the generated config, both now updated to match:
`shared/include/ssl_op.h`'s `CERTFILE`/`KEYFILE` macros (read only by `main-server.c`'s `-h` help
text) and `config/src/authd-config.c`'s `Read_Authd()`, which hardcodes the same path as the actual
runtime default `<ssl_manager_cert>`/`<ssl_manager_key>` fall back to when absent from
`ossec.conf`. Both are manager-only in practice: `os_auth/CMakeLists.txt` builds exactly one
executable (`wazuh-manager-authd`) from this module -- there is no separate agent-side `authd`
binary, despite `ARGV0`/the CMake project name still being spelled `wazuh-authd` as a historical
label, and every caller of `Read_Authd()`/`CAUTHD` (`os_auth/src/config.c`,
`remoted/src/secure.c`) is itself a manager-only binary. So there was no agent-vs-manager
conflict to avoid here, and no reason to leave a stale default in place. In practice this fallback
is never reached on a fresh manager install anyway: `auth.template` always writes
`<ssl_manager_cert>`/`<ssl_manager_key>` explicitly.

### Configuration

Unlike every other subsystem's tunables in this module, enrollment's *behavioral* flags do not come
from a new `<https>` block or a new internal option: remoted's C side calls
`ReadConfig(CAUTHD, OSSECCONF, &authd_cfg, NULL)` — the `config` library is already linked into
`remoted_lib` — and copies fields straight out of authd's own `<auth>` config (`use_password`,
`use_source_ip`, `allow_higher_versions`, `remote_enrollment`). This is deliberate: `/enroll` and
1515 must agree on whether password auth is required and which versions are acceptable, and reading
the *same* config block is what guarantees that rather than two settings that can drift apart. Only
operational knobs (password-file poll interval, authd-socket connect/response timeouts, queue size)
are new C-ABI fields with their own defaults, following this module's usual "`<=0` means default"
convention. `enrollment_enabled` gates only the response the endpoint gives, never whether the route
exists (see *Two independent authentication gates* above's `403` discussion).

### Metrics

Following `ControlMetrics`/`ScanVdMetrics`'s pattern (relaxed atomics on the shared `wazuh_metrics`
registry, a silent no-op on a null-object instance): `remoted.enrollment.requests`,
`remoted.enrollment.accepted`, `remoted.enrollment.auth_rejected` (401s — a spike here means a
password rollout is out of sync between managers and agents), `remoted.enrollment.disabled` (403s —
useful to notice an agent still trying an enrollment path an operator turned off),
`remoted.enrollment.authd_error` (any 90xx), `remoted.enrollment.authd_unreachable` (transport
failures).

### Lifecycle

Constructed in `RemotedModuleFacade::startHttpServer()` alongside the other endpoint dependencies:
`PasswordKeySource` only when `requirePassword` is set, `AuthdClient` always (the route is always
registered, so the client always exists even if `enrollment_enabled` is currently false — it simply
goes unused while the endpoint short-circuits to `403`). Torn down in the same phase as
`m_downstreamClient` — `AuthdClient::stop()` before the HTTP transport's final `stop()` releases its
I/O runtime, matching the ordering documented in *Deferred forwarding* above.

## Streamed responses — `POST /download`

Most endpoints answer with one in-memory body. `/download` serves `merged.mg` and WPK packages,
which can be hundreds of megabytes, so it streams with **HTTP chunked transfer encoding** (64 KiB
chunks) and memory that does not grow with file size.

Metrics: `remoted.download.*` (admission outcomes + started transfers/offered bytes, all counted
before the pump runs; the per-chunk loop is deliberately uninstrumented) — catalog in
`endpoints/downloadMetrics.hpp`, overview in the [Metrics catalog](#metrics-catalog).

- **Declared at registration, not per response.** The transport creates a request's response builder
  when the request is dispatched — that is what lets it release the received body before the request
  is queued — and a builder's output mode is fixed at creation. So a streaming route registers with
  `ResponseMode::Streamable`; its responder then keeps the request handle and builds *buffered* for
  an error (a 404 is a normal response, not a chunked one) or *chunked* for a transfer. The cost is
  that the received request survives into the worker queue, which is why it is opt-in per route.
  `IHttpResponder::stream()` has a fail-loud default (answer `500`) so a `Buffered` mis-registration
  is obvious instead of silently buffering a large body.
- **Pull, not push.** The handler hands the transport an `IByteSource`; the transport drives the
  loop, because only it owns both the connection's I/O strand and the worker pool. Read a chunk on a
  worker, write it, and read the next only once the write completes. One chunk is resident, and a
  worker slot is held only for the duration of a single read — never for the whole transfer.
  Measured on a live manager: 2 GiB streamed for a 0.6 MiB RSS delta.
- **Failure is truncation, not a short success.** A read error propagates out of `read()` and the
  builder is dropped *without* `done()`, so the terminating `0\r\n\r\n` is never sent and the agent
  sees an incomplete body it will retry. Returning 0 instead would emit the terminator and hand over
  a truncated file that looks complete. RESTinio always fires the write callback (with
  `write_was_not_executed` if the connection died first), so an aborted transfer always releases its
  descriptor — verified: 25 mid-transfer disconnects left the fd count unchanged.
- **`resource_id` is what the agent asks for, and the manager serves exactly that.** A `config`
  request names either one group (`etc/shared/<group>/merged.mg`) or several, comma-separated —
  wazuh's own multigroup form — which resolves to `var/multigroups/<sha256(resource_id)[:8]>/merged.mg`.
  A `wpk` request names a filename and gets `var/upgrade/<filename>`. The multigroup form is what
  lets an agent in several groups fetch its *effective* configuration rather than one member
  group's, and it needs no database: the selector is hashed exactly as wazuh-db names the directory.
  There is no group lookup and no membership check (protocol decision on #38022), so **any
  authenticated agent can fetch any group's or multigroup's merged configuration**. For a `config`
  request the agent does not pick that value: it relays the `config_token` `/control` handed it (see
  the notify response above), so `/control` must report `config_hash` over the file this resolves to
  for the token it handed that agent, or that agent re-downloads on every notify.
- **Containment differs per form.** The multigroup selector is *hashed, never joined*, so it cannot
  traverse by construction. The single-group and WPK forms **do** join agent input into a path, so
  there the grammars are the boundary: no `/`, not `.` or `..`, no leading dot, and for a WPK a
  `.wpk` suffix. With no separator admitted, the joined path has exactly one component below the
  base directory, and `openRegularFile()`'s `O_NOFOLLOW` stops that component being a symlink.
  Loosening either grammar would break that and require a `realpath()` containment check instead.

## Body decoding (`src/decoding/`)

```
src/decoding/
├── iBodyDecoder.hpp     # ContentEncoding enum + parseContentEncoding() + the IBodyDecoder interface
└── bodyDecoder.hpp/.cpp # BodyDecoder: the ONLY place in the module that knows compression exists
```

Split interface/implementation the same way `auth/` does (`IAgentKeystore` + `Keystore`), so the
gateway depends on the abstraction and the concrete decoder stays swappable and separately testable.
It is its own layer rather than part of `endpoints/` because it is not an endpoint: it is one
cross-cutting step every authenticated route runs.

The facade composes a `BodyDecoder` into the gateway's constructor as a **required** dependency, so
it is configured **once per gateway rather than per route**: every authenticated endpoint gets
decoding and none can accidentally opt out. `zstd` is the only accepted encoding (**gzip is not
supported** — see the benchmark note in
[HTTPS Agent API](../../../docs/ref/modules/remoted/https-events-api.md#content-encoding-zstd));
anything else, including `zstd` when `remoted.http_content_encoding_enabled` is off, is `415`. A body
that isn't a valid/complete zstd frame is `400`.
- **Runs strictly AFTER the bearer is verified.** The token is checked from the headers alone (the
  body is not part of it — TLS protects the wire bytes), so an unauthenticated peer never reaches
  the decoder and cannot spend our CPU or memory on it.
- **Both of the decoder's memory costs are charged to the in-flight byte budget as real
  reservations, not merely capped** (see *Memory management* above). (1) The buffers zstd allocates
  before producing any output, reserved at exactly what *this* frame's header declares it needs
  (`ZSTD_getFrameHeader` + `ZSTD_decodingBufferSize_min`) and released as soon as decoding returns,
  since zstd frees them by then. (2) The output buffer, charged for the memory it really takes from
  the allocator and always reserved *before* it grows, then bundled into the new payload's
  keep-alive so it stays charged for exactly as long as the payload is held. Reserving rather than
  checking a figure is what stops N concurrent requests from each reading the same "free" number
  and together overshooting the budget; a frame that doesn't fit is `413` (retryable, unlike the
  `400`/`415` above).
- **Why the output is charged by capacity, not by bytes written.** `std::string` grows by doubling,
  so charging what was written let the buffer over-allocate uncharged — measured at **45% under**
  for an 11 MiB body (11 MiB charged, 16 MiB actually held), which pushed the effective memory
  ceiling that much above the configured one. Now: a frame's header normally declares its
  decompressed size, so that is charged once and the buffer sized to it exactly — one allocation,
  no over-allocation, nothing to copy as it fills. A frame that omits the size (streaming
  compression with no pledged size) grows in doubling blocks, each charged before being allocated,
  so the over-allocation is charged rather than hidden.

## Deferred forwarding (async UDS) — `src/downstream/`

Endpoints process a request, forward it to another service over a Unix-domain HTTP socket, and reply
to the agent once that service answers. First target: the engine's event ingress —
`queue/sockets/engine-ingest-http.sock`, `POST /events/enriched` (HTTP over UDS; replies `200` accepted /
`400` bad batch / `500` orchestrator down) — and a `/stateless` body already **is** the H/E batch it
expects, so the forwarder is near pass-through with auth in front.

Metrics: the forwarder counts each delivered response into its endpoint's
`remoted.http.<endpoint>.responses.*` set (and observes `.latency` where wired), classifies
failures into `remoted.forwarder.error.*`/`downstream_5xx`/`route_mismatch`
(`forwarderMetrics.hpp`), and the limiter's occupancy/sheds are the
`remoted.forwarder.deferred.*` pulls — see the [Metrics catalog](#metrics-catalog).

```
src/downstream/
├── deferredWorkLimiter.hpp   # count-based RAII limiter (parked-request cap; see Memory management)
├── downstreamConfig.hpp/.cpp # events socket (fixed) + C-ABI-driven connect/write/response timeouts,
│                            #   io/post threads, max response body (buildDownstreamConfig())
├── IDownstreamClient.hpp     # async forward interface + DTOs (DownstreamRequest/Response/Error)
├── asioUdsHttpClient.hpp/.cpp# standalone-Asio impl (UDS connect-per-request) + llhttp response parse
└── deferredForwarder.hpp/.cpp# limiter + client + per-endpoint post-processing pool orchestration
```

- **`IDownstreamClient::sendAsync(request, bodyKeepAlive, onComplete)`** — the `AsioUdsHttpClient`
  holds `bodyKeepAlive` only until the **send** completes, then drops it → the payload + byte budget
  are freed at send time (not the round-trip). Async on standalone Asio (`asio::local::stream_protocol`,
  connect-per-request, `Connection: close`), request framed by hand, response parsed with the vendored
  **llhttp**; sends **zero-copy** from our single buffer and parks **no** thread per in-flight request
  (one small `io_context` serves many). Each phase has its own deadline **and its own error value** —
  `DownstreamError::{ConnectTimeout,WriteTimeout,ResponseTimeout}` — so a log line can name the
  tunable that governs whichever one elapsed. `DownstreamTarget::responseTimeoutMs` (`<=0` → the
  configured default) lets one endpoint wait minutes for a slow async handler without every other
  endpoint tolerating the same delay before a hung downstream is noticed; the facade warns at startup
  if an endpoint's connect+write+response budget exceeds `http_request_timeout`, which caps the whole
  request and would otherwise cut the wait short.
- **`DeferredForwarder::forward(req, responder, target, postProcess)`** — acquires a
  `DeferredWorkLimiter::Slot` (plain `503` when full; the agent retries), sends via the client, and on
  completion **offloads** the per-endpoint `PostProcessor` onto its own pool (so the client's I/O
  threads stay free), which builds and delivers the reply, then releases the slot. `DownstreamTarget`
  carries the `socketPath`, so one forwarder serves **many endpoints and many sockets**.
- **`PostProcessor`** is the *type*; concrete post-processors are **endpoint policy** and live in
  `endpoints/`, not here (e.g. `endpoints::stateless::postProcess`: send/connect/timeout → **503**;
  downstream `2xx` → **202 Accepted**; `400` → **400**; `413` → **413**; `5xx`/other → **503**). A
  `PostProcessor` may be non-trivial (inspect the downstream body, apply business logic).
- **Lifecycle**: the client owns its own `io_context` + thread(s) (RESTinio keeps its loop private);
  the forwarder owns the post-processing pool. The builder-only responder is thread-safe, so the reply
  is delivered from the post-processing thread. `IHttpServer::stopAccepting()` closes the acceptor and
  drains the handler worker pool **while deliberately leaving the HTTP transport's I/O runtime
  alive** -- only then does the facade stop the downstream client and drain the forwarder (so any
  reply already in flight can still be delivered safely), and only after *that* does it fully
  `stop()` the transport (releasing the I/O runtime). Getting this order backwards is a real
  use-after-free: a `RestinioResponder` handed to an in-flight forward keeps the agent's connection
  alive independently of the server object, but calling `send()` on it after the transport's I/O
  runtime is gone touches freed memory. See `RemotedModuleFacade::stop()` for the exact 4-phase
  sequence, and `test/unit/shutdownRace_test.cpp` for the end-to-end regression test (run it under
  ASan -- `-DFSANITIZE=ON` -- for it to be a meaningful check).

## Request lifecycle example — a `POST /stateless`, end to end

How a payload flows, which threads/queues it crosses, and how `IDownstreamClient`, `AsioUdsHttpClient`
and `DeferredForwarder` interact. A `/stateless` request crosses **four execution contexts**; each hop
between them is an `asio::post(...)` — i.e. a queue.

| # | Context | Threads (config) | `<=0` default |
|---|---|---|---|
| **A** | RESTinio I/O threads | `io_threads` | `cpp_get_nproc()` |
| **B** | Transport worker pool (`asio::thread_pool`) | `http_worker_threads` | `2 * cpp_get_nproc()` (oversubscribed: work here can block) |
| **C** | Downstream client `io_context` (`AsioUdsHttpClient`) | `downstream_io_threads` | `cpp_get_nproc()` |
| **D** | Post-processing pool (`DeferredForwarder`) | `downstream_post_process_threads` | `cpp_get_nproc()` |

All four are thread-count fields: a caller value `<=0` resolves via `cpp_get_nproc()`
(`shared_modules/utils/proc.hpp`, cgroup-aware on Linux) instead of a fixed built-in constant, so
the pool sizes track the host/cgroup's available CPUs (`httpServerConfig.cpp::resolveThreadCount()`
for **A**/**B**, `downstreamConfig.cpp`'s local `resolveThreadCount()` for **C**/**D**). **B** uses
a `2x` multiplier because its own doc comment ("blocking work offload") means threads there can
block (token verification, `client.keys` file I/O), unlike the purely async I/O reactors **A**/**C**.

### End-to-end flow

```mermaid
sequenceDiagram
    autonumber
    participant Ag as Agent
    participant A as RESTinio IO threads A
    participant B as Worker pool B
    participant F as DeferredForwarder
    participant C as UDS client io_context C
    participant D as Post-proc pool D
    participant E as Engine

    Ag->>A: TLS + POST /stateless (H/E batch)
    Note over A: tryReserve(byte budget) — plain 503 if full<br/>makeHttpRequest() = SINGLE copy into RequestContext<br/>create_response() builder drop RESTinio's buffer
    A->>B: asio::post (worker queue)
    Note over A: return request_accepted() — I/O thread free
    Note over B: bearer verify (AuthMiddleware::authenticate)<br/>build AuthenticatedRequest (payload = view + keep-alive)
    B->>F: forward(authReq, responder, target, mapper)
    Note over F: limiter.tryAcquire() — plain 503 if full
    F->>C: client.sendAsync(req, keepAlive = authReq, onComplete)
    Note over B: forward() returns — worker thread free
    Note over C: async_connect → async_write(head + body view)
    Note over C: write done → drop keep-alive<br/>⇒ payload buffer + byte budget FREED (at send)
    C->>E: POST /events/enriched (zero-copy body)
    E-->>C: 200 / 400 / 500
    Note over C: async_read → llhttp parse → finish() (once)
    C->>D: asio::post (post-proc queue)
    Note over D: stateless::postProcess → 202 / 400 / 413 / 503<br/>responder->send() Slot released
    D->>A: builder.done() schedules the write on the connection strand
    A-->>Ag: HTTP response
```

### Step by step

1. **[A] Ingress.** RESTinio accepts the TLS connection and reads the full request into its own buffer
   (bounded by `http_max_body_size` and `max_parallel_connections`). The route handler runs on the I/O
   thread: it reserves the payload against the **byte budget** (plain `503` if exhausted), copies the
   body **once** into a shared `RequestContext` (with its `Reservation`), builds a `RestinioResponder`
   (`create_response()` moves the connection into a builder), and **drops the RESTinio handle** — freeing
   RESTinio's original buffer here. Then it `asio::post`s to the worker pool and returns immediately.
2. **[B] Auth + handler.** A worker thread runs the `AuthGateway` wrapper: full bearer-token verification
   (synchronous — CPU, off the I/O threads). On failure it replies `400`/`401`/`413`. On success it
   builds an `AuthenticatedRequest` whose `payload` is a **zero-copy view** into the single buffer plus
   a keep-alive to the context, and calls the `/stateless` handler (`stateless::makeHandler`'s
   closure), which first runs `validatePayloadIdentity()` (parses the `H` line, cross-checks
   `wazuh.agent.id` against the authenticated agent id — `400` on a mismatch/malformed header,
   without ever calling `forward()`), then calls `DeferredForwarder::forward(...)`.
3. **[B] forward().** Acquires a `DeferredWorkLimiter` slot (plain `503` if full), then
   `client->sendAsync(dreq, keepAlive = std::move(authReq), completion)`. `forward()` returns and the
   **worker thread is free** — the request is now in flight holding only the byte reservation (via the
   keep-alive), the deferred slot, and the responder builder.
4. **[C] Async UDS.** `AsioUdsHttpClient` runs a per-request `Session` (its own strand) on the client
   `io_context`: connect → `async_write(head + body view)` (zero-copy). **On write-complete it drops
   the keep-alive** → the context (single body copy) and its `Reservation` are destroyed → the
   **byte budget is freed at send time**. Then it reads and parses the response with llhttp and calls
   the completion (once).
5. **[C]→[D] Completion.** The completion does **not** post-process on the I/O thread; it `asio::post`s
   to the **post-processing pool**, keeping the client's I/O threads free for other in-flight requests.
6. **[D] Reply.** A post-pool thread runs `stateless::postProcess` (maps the downstream result to
   `202`/`400`/`413`/`503`) and calls `responder->send(...)`; the builder's `done()` marshals the write
   back onto the RESTinio connection strand ([A]), which writes the reply to the agent. Destroying the
   task **releases the deferred slot**.

### Who does what

```mermaid
flowchart TD
    facade["RemotedModuleFacade<br/>(owns everything; lifecycle)"]
    gw["AuthGateway<br/>(JWT bearer)"]
    fwd["DeferredForwarder<br/>(owns post-proc pool)"]
    lim["DeferredWorkLimiter<br/>(slot cap → 503)"]
    cli["AsioUdsHttpClient : IDownstreamClient<br/>(owns io_context + threads)"]

    facade -->|owns| gw
    facade -->|owns| fwd
    facade -->|owns| lim
    facade -->|owns| cli
    gw -->|"/stateless handler calls"| fwd
    fwd -->|tryAcquire slot| lim
    fwd -->|sendAsync| cli
    cli -->|"onComplete → post-proc pool"| fwd
```

- **`IDownstreamClient`** — the interface / mock seam. Its contract: `sendAsync` drops `bodyKeepAlive`
  when the **send** completes and invokes `onComplete` **exactly once**. `DeferredForwarder` depends
  only on this interface.
- **`AsioUdsHttpClient`** — the async I/O engine (context C). Owns the `io_context` + thread(s); per
  request drives a `Session` state machine (connect → write → read → llhttp parse → timeouts) on its
  own strand, holding itself alive via a `shared_ptr` through the callback chain. It is the component
  that frees the payload at write-complete.
- **`DeferredForwarder`** — the orchestrator / glue between the endpoint handler and the client. Gates
  the limiter (503 when full), calls the client, and offloads the per-endpoint `PostProcessor` to its
  own pool (context D) to build the reply and release the slot. Owns the post-processing pool.

### What each resource costs and for how long

| Resource | Acquired at | Released at | Held during |
|---|---|---|---|
| **Single payload copy** (`RequestContext` body) | [A] `makeHttpRequest` | [C] **write-complete** | worker queue + auth + forward + connect + write |
| **Byte-budget reservation** | [A] `tryReserve` | with the buffer (same context) | same as above |
| **Deferred-work slot** | [B] `forward()` | [D] after the reply (post-task destroyed) | connect + write + **downstream wait** + post-process |
| **Responder** (builder) | [A] | after `send()` in [D] | the whole trip (thread-safe, send-once) |

Two complementary backpressure phases: the **byte budget** bounds *receive→send* (released at send),
the **deferred limiter** bounds *the wait for the downstream*.

### Notes

- **RESTinio's buffer is freed early** (step 1, on the I/O thread), before queueing to the worker pool
  — so while the request waits in the worker queue only **our** single copy exists.
- **`forward()` never blocks**: it returns as soon as it hands off to the client; no worker/`io_context`
  thread is parked waiting for the downstream (the client's `io_context` multiplexes many in-flight
  requests without a thread each).
- **The `AuthenticatedRequest` metadata (`agentId`, …) is freed at send too** (it *is* the keep-alive).
  `stateless::postProcess` doesn't need it; a future post-processor that does must copy it out **before**
  `forward()` (capture it in the `PostProcessor` closure).
- **`send()` is cross-thread safe**: it is called from a post-pool thread [D]; the builder marshals the
  actual socket write onto the RESTinio connection strand [A].

## Agent<->manager auth middleware (`src/auth/`)

Framework-agnostic implementation of the agent<->manager request authentication protocol: the
`wazuh-agent+jwt` bearer (issue #38582). The token itself — compact grammar, exact header/claim
sets, HS256, time rules, identity — is verified by the shared `JwtRequestTokenVerifier` in
`shared_modules/utils/jwt/` (header-only over jwt-cpp's base64url, rapidjson SAX for a strict
pre-parse and OpenSSL's `EVP_Q_mac`; the same library the agent signs with and the fake managers
of the agent's tests verify with). `AuthMiddleware::authenticate(protocolVersion, authorization,
peerAddress, now)` is a single call: `protocol-version` first, `Bearer` scheme, `peekKid()` to
resolve the CANDIDATE key from the keystore (and the registered-address verdict in the same pass),
then the verifier, then `AuthError`. Nothing from the token is trusted before its signature except
the bounded `kid` used for the lookup, and the algorithm is fixed to HS256 — never read from the
token. The JSON pre-parse (`StrictJsonObject`) is ASCII-only and length-bounded (rapidjson
`MemoryStream`, not a NUL-terminated `StringStream`): the profile text never needs anything else, and
it keeps rapidjson's UTF-8 validation — which consumes continuation bytes without checking for the end
of a C string — from ever running over a decoded segment (the ASAN CI finding on the fuzz test).
Metrics: every client-visible rejection is counted with its pre-collapse cause as
`remoted.auth.reject.*` (catalog in `endpoints/endpoint.hpp`, counted at `errorResponseFor()`),
and the keystore's health as the `remoted.auth.keystore.*` pulls — see the
[Metrics catalog](#metrics-catalog). `authTypes.hpp` holds the shared contract
(`AuthenticatedRequest`/`Payload`/`AuthError`/`toAuthError`/`publicErrorFor`/`AuthConfig`) and
`iAgentKeystore.hpp` the key-lookup interface; `authMiddleware`, `keystore`, `addressRule` are the
implementation. It knows nothing about RESTinio or sockets -- the `AuthGateway` (in `endpoints/`)
is the only adapter between it and our transport. The token does **not** cover the body: the
middleware authenticates from the headers alone, the gateway applies the body cap directly, and the
body is exposed as a zero-copy `Payload` view that the `AuthGateway` attaches from the transport's
single request buffer. Every credential `401` carries `WWW-Authenticate: Bearer`.

`AuthConfig`'s tunables (`timePolicy` -- accepted token age and clock skew -- and `maxBodySize`) are
populated from the matching C-ABI fields (`jwt_max_age`, `jwt_clock_skew`,
`auth_max_body_size`, in turn read from the `remoted.jwt_*`/`remoted.auth_*` internal options in `secure.c`) via
`remoted::auth::buildAuthConfig()` (`auth/authTypes.cpp`), which the facade calls instead of
default-constructing `AuthConfig{}`. `supportedProtocolVersion` stays fixed (`"1"`) -- it's a
protocol constant, not an ops tuning knob. See *Configuration* above.

Unit tests under `test/unit/` (`jwtVerify_test.cpp`, `jwtSigner_test.cpp`, `jwtEnrollSignVerify_test.cpp`,
`authMiddleware_test.cpp`, `keystore_test.cpp`, `addressRule_test.cpp`); `authMiddleware_test.cpp` exercises `AuthMiddleware`
against a scratch `client.keys` file it writes to `/tmp`, through `Keystore` -- there is no
in-memory stand-in.

**Agent key lookup:** `Keystore` reads `etc/client.keys` directly and parses it
the same way the manager's own `OS_ReadKeys()` does (id/name/ip/key columns, `#`/`!`-marked removed
entries skipped), independent of remoted's C `keystore`. This was a deliberate choice over reaching
into remoted's live `keystore`: remoted loads it in `W_ENCRYPTION_KEY` mode (see `secure.c`), which
never keeps the raw pre-shared key in memory -- only a derived key for the legacy message cipher --
so the raw key needed for verification has to come from the file itself. The key column is treated as
lowercase hex and hex-decoded as-is (no further derivation) by the shared `JwtKeyDecoder`; it must be
exactly 64 lowercase hex characters (32 bytes) to work as the HS256 key — the form `authd` generates;
any other shape is reported as unusable (`MissingKey`) and the agent has to re-enroll. client.keys has no "disabled but present" state -- a removed entry is simply
absent -- so `AuthError` has no separate inactive-agent case; an unknown and a removed agent are
indistinguishable and both resolve to `AuthError::UnknownAgent`.

**Registered-address enforcement:** the `ip` column is parsed into an `AddressRule`
(`auth/addressRule.hpp`) and evaluated by `IAgentKeystore::lookup()`, which resolves the agent's key
and its address verdict in the same pass -- so the two answers always describe the same entry, even if
the file is reloaded mid-request. `AuthMiddleware` acts on the verdict before verifying the
token's signature. An
agent registered with a fixed address or a range authenticates only from it; `any` accepts every
peer. The accepted forms match the manager's own `OS_IsValidIP()`/`OS_IPFound()`
(`shared/src/validate_op.c`): `any`, an IPv4 address alone or with `/CIDR` (0-32) or a dotted
`/mask`, an IPv6 address alone or with `/prefix` (0-128), and the `::ffff:a.b.c.d` v4-mapped form,
unmapped before use. An IPv6 zone id (`fe80::1%eth0`) is dropped on both sides of the comparison, since
it names a local interface rather than part of the address -- the transport unmaps the peer address the same way in
`normalizeRemoteAddress()`, so both sides of the comparison agree on the representation. A dotted
mask is applied as written, with no contiguity check. A leading `!` is stripped and the remainder read
positively -- it is not a negation, matching the legacy keystore, where `OS_IsValidIP()` drops the `!`
before storing the text so `OS_IPFound()`'s negation branch can never fire; keeping it identical is what
lets a `client.keys` migrated from 4.x authorize the same agents it did there. A line whose `ip` column
does not parse is skipped with a warning, like any other malformed line, rather than being loaded
without a restriction. The peer address is **not** part of the token, so a NAT rewrite
between agent and manager does not invalidate it. A mismatch resolves to
`AuthError::AddressNotAllowed`, which `publicErrorFor()` folds into the same generic 401 as the other
credential failures; `AuthMiddleware` reports it with a throttled warning naming the agent id and the
peer address, and `endpoints/endpoint.cpp` keeps it at DEBUG2 in its own rejection funnel so the line
is not emitted twice.

**Hot-reload:** `Keystore` runs a background watcher thread (RAII -- started at the end of the
constructor, stopped and joined in the destructor) so an agent enrolled or removed after startup is
picked up without restarting `remoted`. Two triggers feed the same check: an `inotify` subscription
on the file (`IN_MODIFY`/`IN_CLOSE_WRITE`/`IN_MOVE_SELF`/`IN_DELETE_SELF`, re-armed on the same path
if an atomic rename-replace invalidates the watch descriptor) reacts immediately, and a periodic
fallback poll (`poll()`'s own timeout doubles as the interval) catches anything the subscription
ever missed -- both converge on the same `fileLooksChanged()` gate. Change detection compares the
file's **content hash** (`Utils::hashFile()`, `shared_modules/utils/hashHelper.h`), not mtime: mtime
is only second-granularity, so two rewrites landing in the same wall-clock second would otherwise
look identical. `reload()` itself is guarded against adopting a line caught mid-write: it hashes the
file before and after parsing and discards+retries (a few times, briefly) if they don't match, so a
concurrent rewrite can only ever flip the in-memory table between two complete, consistent states,
never a torn mix of both -- see `test/unit/keystore_test.cpp`'s `ReloadNeverAdoptsATornMixOfTwoValidContents`
for the regression test. The poll/fallback interval is `remoted_module_config_t::keystore_refresh_interval`,
which `secure.c` populates from the classic pipeline's own `remoted.keyupdate_interval` (its
`rem_keyupdate_main` thread, `secure.c`) rather than a second, redundant internal option.

**Agent ids are numeric (`AgentId = std::uint32_t`, `authTypes.hpp`):** an agent id is always numeric
by design, so `Keystore`'s id→key table is keyed by `AgentId`, not by string. A `client.keys` line
whose id column doesn't parse as a non-negative integer (fully consuming the field, via
`std::from_chars`) is skipped like any other malformed line -- it can never match a real lookup, and
the rest of the file still loads normally. The `Authorization` header's `<agent-id>` segment is
likewise restricted to the canonical zero-padded digits by `peekKid()` (`CanonicalAgentId::parseCanonical`);
anything else fails immediately as `AuthError::InvalidToken`, before it ever reaches the Keystore.
`AuthenticatedRequest::agentId` carries that canonical text -- only the Keystore's key type and the
lookup argument are numeric.

## Contract

```c
void remoted_module_start(full_log_fnc_t callbackLog, const remoted_module_config_t* configuration);
void remoted_module_stop(void);
```

- `start()` launches the worker thread and returns immediately; the module owns the thread.
- `stop()` signals the worker (atomic flag + condition_variable) and joins it. Safe to call
  when never started.
- All exceptions are caught at the `extern "C"` boundary — nothing throws into C. Both wrappers
  catch `std::exception` **and** `(...)`: a non-`std::exception` crossing into remoted's C code
  would hit no handler at all and `std::terminate` the daemon.
- Logging is routed back into remoted's `wazuh-manager.log ` via the `full_log_fnc_t` callback
  (remoted passes `mtLoggingFunctionsWrapper`) and the `LOGFN_*` macros.

## Diagnostics — `src/common/logThrottle.hpp`

Every condition where an operator may need to change a setting is logged, and named with the setting
to change (`"…Consider increasing the value of 'max_deferred_requests'."`). The rules:

- **Operator-actionable → `LOGFN_WARN`, throttled.** Byte budget exhausted (`max_inflight_bytes`),
  deferred slots exhausted (`max_deferred_requests`), each downstream failure kind
  (`downstream_connect_timeout` / `_write_timeout` / `_response_timeout` /
  `_max_response_body_size`), clock skew (`jwt_max_age` / `jwt_clock_skew`), body cap
  (`auth_max_body_size`), an unusable `client.keys` key, and an authenticated agent claiming a
  different agent id.
- **Client-fault 4xx → `LOGFN_DEBUG2`, unthrottled.** Malformed/unauthenticated requests. An
  unauthenticated peer controls how many of these it triggers, so logging them at WARN would be a
  log-amplification vector against `wazuh-manager.log ` — and a bad MAC from an internet scanner is noise.
  Visible with `remoted.debug=2` when someone is actually diagnosing a client.
- **`LogThrottle`** (`src/common/logThrottle.hpp`) enforces one line per 90 s per condition —
  matching remoted's own C throttles — and folds the suppressed count into the emitted line, so
  nothing is silently lost. One instance **per condition**, never shared: a permanently-failing
  condition must not mask a newly-appearing one. It deliberately does **not** log (it only decides),
  which is what keeps `loggerHelper.h` out of headers the test binary includes, and makes the
  decision unit-testable on its own.

`endpoints/endpoint.cpp`'s `errorResponseFor()` is the single funnel for all auth rejections: it logs
the reason **before** `publicErrorFor()` collapses seven distinct credential failures into one
generic 401. Downstream failures are logged in `deferredForwarder.cpp`'s completion callback, where
the raw `DownstreamError` is still available — `stateless::postProcess` turns them all into one 503,
so by the time the agent is answered the cause is gone.

RESTinio's own diagnostics reach `wazuh-manager.log` too, via `WazuhRestinioLogger`
(`http_server/RestinioHttpServer.cpp`), which replaces `restinio::null_logger_t` — whose methods are
`constexpr void {}`, i.e. every transport diagnostic was previously discarded *at compile time*. This
covers TLS handshake failures, malformed HTTP, `EADDRINUSE`, and every `http_max_*` breach — but
**none of it appears by default**: both `warn()` and `error()` are logged at `LOGFN_DEBUG1`,
throttled (visible with `remoted.debug>=1`). RESTinio's own notion of "error" is a per-connection
protocol/socket event (a truncated read, a malformed parse, a header/URL over its limit) driven
overwhelmingly by client behavior — a portscanner, or deliberately-malformed negative-test traffic
like `tools/send_stateless.py --all` — not "the manager is broken" in the sense this module reserves
`LOGFN_ERROR` for. The one genuinely rare, operator-facing case (the acceptor failing to bind) is
already surfaced distinctly by our own cert/key pre-check and `RemotedModuleFacade::start()`, which
logs and rethrows on failure (there is no retry: remoted must not start without HTTPS up), so
demoting RESTinio's own duplicate report of it costs nothing. The throttle matters even at DEBUG1:
`Log::isDebugEnabled()` filters nothing today (`Log::GLOBAL_LOG_LEVEL` is `0` fixed), so the message
builder — an allocation — runs unconditionally per call unless bounded; the real `dbg_flag` filter
is further downstream. `trace`/`info` are left as `constexpr {}` no-ops for a different reason: with
a real logger type RESTinio selects a generic logging overload that materializes a closure and a
try/catch frame at ~30 per-request call sites, measurable even when the body does nothing.
**The message is always passed as an argument to `"%s"`, never as the format string** — `LogFn`
forwards its format to `_log()`'s `vfprintf`, and RESTinio's builders embed client-controlled data
(request target, header values), so using it as a format would be a remote format-string bug.

## Metrics catalog

Everything lives on the facade's single `wazuh_metrics` registry and is observable in two
places: `GET /metrics` on the local admin socket (below) and the debug-log dump on `stop()`.
Design rules shared by every family: names are the only dimension (closed sets pre-resolved
into structs, selected by `switch` — the hot path never formats a name); update cost is one
relaxed atomic op (histogram `observe()` ≈ 2×, and never on a transport I/O thread); a
default-constructed struct is a null object that counts nothing; pull metrics read weak
targets repointed per start and quiesce to 0 after teardown (`IManager` has no unregister).

The operator-facing reference — every metric with the configuration setting it helps size,
linked into the settings' own documentation — is the official docs page:
[Metrics](../../../docs/ref/modules/remoted/metrics.md). This table is the developer's map
(which component counts what, and where).

| Family | What it answers | Counted at |
|---|---|---|
| `remoted.control.*` (6 counters + `rejected` + `wdb.latency` histogram) | control-plane health, wazuh-db sizing | `controlHandler`/`controlEndpoint`/`wazuhDBClient`/`taskClient` (see the /control section) |
| `remoted.control.registry.agents` (pull) | how many agents this node currently tracks — diagnostic only: the registry TTL (6 h) and eviction cadence (5 min) are compile-time constants, not settings | `AgentRegistry::size()` |
| `remoted.scanvd.*` (7 counters) | VD scan admission split | `scanVdHandler` (see the /scan/vd section) |
| `remoted.auth.reject.{unknown_agent, invalid_signature, bad_token, identity_mismatch, clock_skew, unusable_key, address_not_allowed, enrollment_key_unavailable, payload_mismatch, body_too_large, bad_encoding, malformed}` | WHY authentication failed, pre-collapse (the wire folds credential failures into one 401) | `errorResponseFor()` — the single funnel, shared with `/enroll`; installed process-wide via `installAuthRejectMetrics()`. `metrics_test.cpp` DISCOVERS the live `AuthError` values through `toString()` instead of listing them, so a value appended upstream without its own cell fails the test — a hand-written list missed `address_not_allowed` and then `enrollment_key_unavailable` |
| `remoted.auth.keystore.{agents, entries_skipped, reloads.total, reload_failures.total}` (pulls) | did the client.keys hot-reload pick up re-enrolls; is the file unreadable/unstable; how many lines the load could not use | atomics maintained by `Keystore::reload()`. `agents`/`entries_skipped` are LEVELS of the adopted load (a failed load leaves both untouched); neither counts comments, blanks or removed entries |
| `remoted.http.<stateless\|stateful\|stats\|config\|enroll>.responses.{2xx,400,403,409,413,500,503,other}` | WHAT each endpoint answered agents (some cells structurally zero per endpoint — kept so the vocabulary is uniform) | the single place each response is sent: the forwarder's delivery task, the limiter-shed 503 in `forward()`, or the handler's own pre-forward 400. `/enroll` is not forwarded, so it counts through a `MeteredResponder` wrapper instead (`common/requestOutcomeMetrics.hpp`) — one wrap covers its five inline answers AND the one authd's callback delivers on another thread |
| `remoted.http.<stateless\|stateful\|enroll>.latency` (histograms, µs) | end-to-end time; sizes `remoted.http_worker_threads` / `remoted.downstream_stateful_response_timeout` / the `authd_*` timeouts | stamped once in the auth gateway (`AuthenticatedRequest::receivedAt`), observed on the forwarder's post-processing pool. `/enroll` has no gateway, so `MeteredResponder` times it from handler entry. `/stats`/`/config` deliberately have none (same downstream as `/stateful`, no new answer) |
| `remoted.forwarder.error.{connect, connect_timeout, write_timeout, response_timeout, transport, protocol, response_too_large}` + `downstream_5xx` + `route_mismatch` | WHY the 503s: which timeout knob, transport vs protocol, a downstream 5xx, or a route contract mismatch. Aggregate across services — the per-endpoint 503 cells already say which path | the forwarder's classification branches, next to the throttles that log the same cause |
| `remoted.download.{rejected, not_found, open_error, started, bytes.total}` | group/WPK drift (404 retry storms) and offered transfer volume | `downloadEndpoint` admission + stream start (the per-chunk pump is deliberately uninstrumented) |
| `remoted.server.budget.{available.bytes, inflight.bytes, inflight.requests, rejected.total}` (pulls) | is `remoted.max_inflight_bytes` sized right; how much did the byte budget shed | `IHttpServer::diagnostics()` over the transport's `InFlightBudget` |
| `remoted.enroll.{accepted, rejected_auth, rejected_validation, disabled, authd_error, authd_unavailable}` | WHY each `/enroll` request ended that way (the status/latency view is the `enroll` families above) | `enrollment/metrics.hpp`, counted in `enrollmentEndpoint.cpp` |
| `remoted.enroll.authd.queue.{depth, capacity, rejected.total}` (pulls) | is `remoted.authd_max_queue_size`/`authd_worker_threads` sized right, and how much of `authd_unavailable` was saturation rather than an unreachable authd | `AuthdClient::queueDiagnostics()` (same lock, dump cadence only); the counter is bumped ONLY on the queue-full branch, never on shutdown |
| `remoted.forwarder.deferred.{inflight, capacity, rejected.total}` (pulls) | is `remoted.max_deferred_requests` sized right; how much did the limiter shed | the `DeferredWorkLimiter`'s own atomics |
| `remoted.admin.server.*` (7 pulls) | the admin transport dogfooding itself | `IUdsHttpServer::diagnostics()` |

**Accounting boundary** (what sums to what): a request shed by the byte budget is refused on
the transport I/O thread BEFORE any route runs — it appears ONLY in
`remoted.server.budget.rejected.total`, never in a `responses.*` cell. The converse holds too:
an *admitted* compressed request whose decode does not fit the budget is answered `413` and
counted only in `remoted.auth.reject.body_too_large` — never as a budget shed. A deferred-limiter shed
is the endpoint's answer, so it counts BOTH as that endpoint's `responses.503` and in
`remoted.forwarder.deferred.rejected.total`. Auth-gateway rejections happen before any handler
and appear only in `remoted.auth.reject.*`; a handler's own pre-forward rejection (empty body,
payload identity) counts in its `responses.*` (the "what") and, where it is an AuthError, in
`remoted.auth.reject.*` too (the "why"). EPS/rates are deliberately NOT computed in-process —
the scraper (`engine/tools/devContainer/scripts/monitor.py`) derives rates by diffing counters
per interval, which is exactly what its `_REMOTED_MODULE_SCALARS`/`_REMOTED_MODULE_HISTOGRAMS`
catalogs consume.

## Local admin socket — `queue/sockets/remote-admin-http.sock`

The module's management plane: a second, independent HTTP server (the shared
`shared_modules/uds_http_server` library — the public HTTPS server keeps its own RESTinio stack)
brought up by `startAdminServer()` right after the public server. It serves exactly two
read-only routes, both **Liveness** class (answered inline from resident state, exempt from the
byte budget):

| Route | Answer |
|---|---|
| `GET /` | `{"status":"ok","module":"remoted_module"}` — liveness probe |
| `GET /metrics` | JSON dump of the module's whole `wazuh_metrics` registry (every family in **Metrics catalog** above), same envelope as inventory sync's `/metrics` |

Contract points:

- **Fixed path, no knob**: the constant `queue/sockets/remote-admin-http.sock` is **relative** on
  purpose — remoted `chroot()`s into the install dir, so the socket lands at
  `$WAZUH_HOME/queue/sockets/remote-admin-http.sock` (mode 0660). Internal options only carry ints,
  so a path knob has nowhere to live — the same criterion that fixed inventory sync's path.
- **Warn-on-failure**: a failed bind/start is a `WARN` and the module continues without the
  admin plane — metrics are optional, and remoted must never die for them. (The public HTTPS
  server keeps the opposite policy: its failure is fatal.)
- **Local-only by construction**: agents can never reach it — no route on the public HTTPS
  endpoint exposes it (that endpoint is agent-facing, not an admin plane), and the C-side stats
  served by remcom's legacy `getstats` are untouched (decision U6).
- **Dogfooding**: the admin server's own `TransportDiagnostics` are published on the same
  registry as `remoted.admin.server.*` pull metrics (weak_ptr target behind its own mutex,
  registered once per process — pulls cannot be unregistered), so `GET /metrics` also reports
  the transport serving it.
- **Shutdown**: `stopAccepting()` in `stop()`'s phase 1 alongside the HTTPS server's, full
  `stop()` + reset in the teardown phase — the metrics manager its handlers read outlives it.

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
```

## Integration in remoted

- Build wiring: `add_subdirectory(remoted_module)` + `remoted_module` added to
  `target_link_libraries(remoted_lib ...)` in `src/remoted/CMakeLists.txt`.
- Lifecycle: `HandleSecure()` (in `src/remoted/src/secure.c`) builds a
  `remoted_module_config_t`, calls `remoted_module_start(...)`, and registers
  `remoted_module_stop` with `atexit`.

## Tests

Unit tests (built when `UNIT_TEST` is enabled) live in `test/unit/`: `remotedModule_test.cpp`
(C-ABI black-box), `httpServer_test.cpp` (transport config incl. in-flight-budget/max-connections
resolution + responder contract incl. a shared request surviving a deferred handler),
`inFlightBudget_test.cpp` (reserve/release accounting, exhaustion, RAII move-once, disabled mode,
concurrency), `deferredWorkLimiter_test.cpp` (count-based limiter: acquire-to-capacity, RAII/move
release, disabled mode, concurrency), `deferredForwarder_test.cpp` (mock client: slot-full→503,
target/body forwarded, post-processor result delivered + slot released, keep-alive release),
`statelessEndpoint_test.cpp` (endpoint policy: `target()` + `postProcess()` mapping 202/400/413/503;
`validatePayloadIdentity()` mismatch/malformed-header/non-numeric/leading-zero-normalization cases;
`makeHandler()` short-circuits before `forward()` on a validation failure and still forwards +
post-processes on success), `statsEndpoint_test.cpp` and `configEndpoint_test.cpp` (the two
forwarding endpoints, one file each mirroring their near-duplicate implementations: the target's
socket/path/content-type, the `X-Wazuh-Agent-Id` header, the `serviceName` used in failure logs, the
full `postProcess` mapping table, **that no downstream body is ever reflected to an agent** — `/stats`
answers a fixed `{}`, `/config` passes the sync server's enriched document through — and that an empty body
answers 400 without ever reaching `forward()`),
`asioUdsHttpClient_test.cpp` (in-process UDS stub: response parse, connect/timeout errors, keep-alive,
**and that caller-supplied headers are actually serialized onto the wire without displacing
Content-Type/Content-Length** — the assertion that the agent id really reaches modulesd),
`payload_test.cpp` (zero-copy `Payload`: view validity,
keep-alive pinning, explicit `release()` + RAII), `authGateway_test.cpp` (gateway: 400/401 paths, valid-auth success + payload
view, payload outliving dispatch + release keeping metadata, handler-exception → 500), plus the auth
core `jwtVerify_test.cpp`/`jwtEnrollSignVerify_test.cpp`, `authMiddleware_test.cpp` (incl. a non-canonical
`kid` → `InvalidToken`), `keystore_test.cpp` (incl. a non-numeric `client.keys` id line being
skipped without blocking the rest of the file).

VD re-scan coverage: `vdClient_test.cpp` (a real `httplib::Server` fake VD backend — cache hit
within TTL, single-flight refresh under a concurrent caller with the lock released during the UDS
round trip, stale-value fallback and bounded retry gating on a failed query, recovery clearing the
failure state), `scanVdEndpoint_test.cpp` (JSON dispatch in isolation against a fake
`ScanVdHandler`: every rejection code, the `ScanVdOutcome` → response mapping), `scanVdHandler_test.cpp`
(the synchronous admission passthrough against a real `VdClient` + fake VD backend: version
mismatch and invalid-agent gates, VD's 200 relayed as exactly one POST with no retry, VD's
capacity/readiness rejections passed through with their error codes, an unreachable VD answered
as an honest `vd_unreachable` 503, VD's `indexer_unavailable` cause kept off the `vd_error`
counter, and the wire shape of the scan POST), and
`controlScanVdE2E_test.cpp` (the one test that goes over a **real** TLS
`RestinioHttpServer` + real `AuthGateway` + real `ControlHandler`/`ScanVdHandlerImpl`, with only
wazuh-db/task-manager/VD faked — confirms `vd_feed_offset` and the `/scan/vd` 200/409/503
responses survive actual HTTP/TLS/JSON serialization, not just the handler logic the other files
exercise directly).

Admin socket coverage: `adminServer_test.cpp` (C-ABI black-box + a real `httplib::Client` over
the UDS socket: the fixed path and 0660 mode, `GET /` liveness, `GET /metrics` carrying every
metric family in the catalog (one representative name per family, plus live — not quiesced —
values for the public-transport pulls), 404/405 exact-match routing, the warn-and-continue
policy when the bind fails with the public listener unaffected, and `stop()` unlinking the
socket with a restart cycle bringing the plane back).

```bash
ctest --test-dir <build> -R remoted_module_utest -V
```

### Manual / end-to-end (`tools/send_stateless.py`, `tools/send_download.py`)

Mints the `wazuh-agent+jwt` bearer and sends `POST /stateless` requests exactly as `AuthMiddleware`
expects (shared `tools/wire_jwt.py`, pure standard library; agent key read straight from
`client.keys`; `python3 wire_jwt.py --self-test` reproduces the frozen vectors). Requires
`pip install -r tools/requirements.txt`.

Every sender resolves `--global-prefix` the way `run_benchmark.sh` resolves `--cluster`: when the
flag is absent it reads `<remote><https><global_prefix>` from the local manager's configuration, so
a default installation needs no flag. The prefix is a routing matter only (the bearer does not bind
the target; a mismatch is a `404`); pass `/` to force the unprefixed paths.

```bash
python3 tools/send_stateless.py            # one valid signed request -> 200
python3 tools/send_stateless.py --tamper   # corrupted token signature -> 401 (invalid_signature)
python3 tools/send_stateless.py --all      # every success/failure scenario with expected codes,
                                            # incl. payload_agent_mismatch -> 400 (PayloadAgentMismatch)
# options: --url (default https://127.0.0.1:1517), --agent-id, --body, --client-keys, --global-prefix
```

### Manual / end-to-end (`tools/send_agent_json.py`)

Same bearer, for `POST /stats` and `POST /config`. This one is the end-to-end check of the *whole*
forwarding path.

**It verifies the body, not just the status code.** Both endpoints now behave the same way: they
validate the agent's `modules`-keyed report, index one document per agent (`wazuh-agent-stats` /
`wazuh-agent-config`) and answer the protocol's empty acknowledgment — so a `200` carrying anything
but `{}` is a FAIL. Neither echoes the enriched document any more.

That is all the tool can assert. Confirming the document actually landed means reading it yourself
with `GET wazuh-agent-stats/_doc/<agent_id>` or `GET wazuh-agent-config/_doc/<agent_id>` on the
indexer — which is also the only way to see a write the indexer rejected, since both writes are
fire-and-forget and the agent gets its `200` either way. The write is asynchronous, so the document
appears shortly *after* the `200`, not with it.

Requires `wazuh-manager-modulesd` running with the `inventory_sync_server` module; without it every
forwarded request answers `503` and the tool says so explicitly (distinct from remoted itself being
unreachable, which it also reports separately).

```bash
python3 tools/send_agent_json.py                          # one signed /stats -> 200 + {}
python3 tools/send_agent_json.py --endpoint config        # same, against /config -> 200 + {}
python3 tools/send_agent_json.py --body '{"cpu":42}'      # no `modules` object -> 400, both endpoints
python3 tools/send_agent_json.py --tamper                 # corrupted token signature -> 401 (invalid_signature)
python3 tools/send_agent_json.py --all                    # 16 scenarios x BOTH endpoints
# options: --url, --agent-id, --body, --client-keys, --endpoint {stats,config}, --global-prefix
```

`--all` runs every scenario against **both** endpoints on purpose: they are deliberate near-duplicates
in the C++, so covering both is what proves the duplication is actually wired up on each path. It
covers the endpoint-specific rejections (empty body → 400 short-circuited by remoted before any UDS
round trip; non-object and malformed JSON → 400 from modulesd) plus every auth-layer failure. It does
**not** repeat the transport-level limits (oversized URL/header/count → dropped connection) — those are
endpoint-independent and already covered by `send_stateless.py --all`.

> The bearer comes from one shared module, `tools/wire_jwt.py` (copy it next to the script you take
> onto a manager). It is pinned to the frozen vectors the C++ side is pinned to, so a profile change
> on either side fails `--self-test` loudly rather than silently mis-signing.

### Manual / end-to-end (`tools/send_control.py`, `tools/send_scan_vd.py`)

Same bearer, for the VD re-scan pair: `send_control.py` covers `/control`
(startup/notify/shutdown, including the auth-layer scenarios), and `send_scan_vd.py` covers
`/scan/vd` specifically.

```bash
python3 tools/send_control.py --type notify                # prints the vd_feed_offset it got back
python3 tools/send_control.py --all                         # every /control success/failure scenario

python3 tools/send_scan_vd.py --auto-offset                 # looks up the current offset via
                                                              # /control first, then a matching request -> 200
python3 tools/send_scan_vd.py --feed-offset 1                # a deliberately wrong offset -> 409,
                                                              # prints the manager's real current_version
python3 tools/send_scan_vd.py --all                          # every /scan/vd success/failure scenario
# options: --url (default https://127.0.0.1:9443), --agent-id, --client-keys, --global-prefix
```

`send_scan_vd.py --auto-offset` is the tool doing what a real agent does before ever calling
`/scan/vd`: read the current offset off a live `/control` notify response rather than requiring you
to already know it.
