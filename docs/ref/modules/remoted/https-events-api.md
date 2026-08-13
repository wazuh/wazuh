# HTTPS Events API

`remoted` embeds a self-contained C++ module (`remoted_module`) that runs an **HTTPS listener**
for agent-authenticated event ingestion, in addition to the classic AES-encrypted TCP/UDP channel
on port `1514`. The listener is built on RESTinio + OpenSSL and authenticates every request with a
per-agent **AES-CMAC** signature derived from the agent's pre-shared key.

> **Experimental / work in progress.** A successful request is authenticated, its H/E batch is
> forwarded to the engine's event ingress, and the response reflects the downstream result (see
> [Endpoints](#endpoints)). The listener **requires** a TLS certificate and key to be present (see
> [Transport and TLS](#transport-and-tls)); a self-signed pair is generated automatically at
> install time on manager packages, so this is satisfied on a default install.

## Overview

- A C++17 module linked into `wazuh-manager-remoted` exposes the HTTPS server. It is **Linux
  manager only** (agents and Windows do not build it).
- The transport (RESTinio) sits behind an internal interface, so the endpoint contract and the
  authentication layer are independent of the HTTP library.
- The HTTPS server is started **synchronously** as part of the module's startup, and there is
  **no retry**: if the certificate/key are missing or invalid, starting the module fails and
  `remoted` itself does not start. This is intentional — the manager must not come up believing
  the HTTPS listener is available when it silently is not.
- Authentication and endpoint handlers run on a bounded worker pool, off the I/O threads.

## Transport and TLS

- **Bind address / port:** `127.0.0.1:1517` by default. Both IPv4 and IPv6 literals are accepted
  (see [Bind address: IPv4, IPv6 and dual-stack](#bind-address-ipv4-ipv6-and-dual-stack) below).
- **TLS:** minimum version TLS 1.3; the server loads a PEM certificate chain and private key and
  verifies that the key matches the certificate.
- **TLS file paths (evaluated after `remoted` enters its chroot):**
  `etc/certs/remoted.pem`, `etc/certs/remoted-key.pem`, and `etc/certs/root-ca.pem` — i.e. host paths
  `/var/wazuh-manager/etc/certs/remoted.pem`, `/var/wazuh-manager/etc/certs/remoted-key.pem`, and
  `/var/wazuh-manager/etc/certs/root-ca.pem`. These paths are opened by the module itself,
  **after** `remoted` has already dropped root privileges (`Privsep_SetUser()`), so the private
  key (and the CA bundle, when `verification_mode` requires one) must be readable by the
  `wazuh-manager` user `remoted` runs as. Packaging generates and owns the auto-signed pair as
  `wazuh-manager:wazuh-manager`, mode `640`; an administrator-provided pair must match that
  ownership, or the module fails to start (see
  [Diagnosing rejections and capacity problems](#diagnosing-rejections-and-capacity-problems)).
- **Message limits and timeouts:** max URL 2048 B, max header name 256 B, max header value 8192 B,
  max 64 header fields, and a transport body cap of 20 MiB by default (`<remote><https><max_body_size>`);
  read/handshake timeout 10 s, write timeout 10 s, request timeout 30 s. The header/URL/timeout
  limits are tunable via `remoted.http_*` internal options -- see [Configuration](#configuration)
  below.

### Bind address: IPv4, IPv6 and dual-stack

`<remote><https><bind_addr>` accepts any literal IPv4 or IPv6 address (validated with the same
`OS_IsValidIP()` check used for the classic `<remote><legacy><local_ip>`, so both families work
with no extra configuration). A few things to know before choosing one:

- **`0.0.0.0`** binds an IPv4-only socket. Only IPv4 clients can connect; there is no way for an
  IPv6 client to reach it.
- **`::`** binds an IPv6 socket that listens on every local address. Whether IPv4 clients can also
  reach it depends on the **`IPV6_V6ONLY`** socket option, which the server sets to `1` (IPv6-only)
  by default -- `::` alone does **not** accept IPv4 connections unless
  `<remote><https><dual_stack>yes</dual_stack>` is explicitly configured -- see
  [`https.dual_stack`](configuration.md#httpsdual_stack). It only applies when `bind_addr` is IPv6;
  an explicit `yes` or `no` is ignored (with a warning) for an IPv4 `bind_addr`. Leaving
  `<dual_stack>` unset never warns, even on an IPv4 `bind_addr` -- it produces the same effective
  behavior as an explicit `no`, just without the warning.
- **A specific literal** (`10.0.0.5`, `2001:db8::1`, ...) binds only that address/family, same as
  today.
- Internally, an IPv4 client connecting through a dual-stack (`::`) socket is reported by the OS as
  an "IPv4-mapped IPv6" address (`::ffff:10.0.0.5`), not the plain `10.0.0.5` form. `remoted_module`
  unmaps this back to plain IPv4 before it's used anywhere (e.g. `HttpRequest::remoteIp`), so any
  future code comparing it against a plain IPv4 address (such as the IP column in `client.keys`)
  doesn't need to handle the mapped form itself.

A self-signed certificate/key pair is generated automatically at install time (source install,
`.deb` and `.rpm` all wire this in), using the same self-signed `generate_cert()` routine that
`authd` uses for `authd.pem`/`authd-key.pem` — now shared code, invoked through remoted's
own binary, and chowned to `wazuh-manager:wazuh-manager` afterward so the module can read it once
`remoted` drops privileges:

```bash
wazuh-manager-remoted -C 365 -B 2048 \
  -K /var/wazuh-manager/etc/certs/remoted-key.pem \
  -X /var/wazuh-manager/etc/certs/remoted.pem \
  -S "/C=US/ST=California/CN=Wazuh/"
chown wazuh-manager:wazuh-manager /var/wazuh-manager/etc/certs/remoted-key.pem /var/wazuh-manager/etc/certs/remoted.pem
chmod 640 /var/wazuh-manager/etc/certs/remoted-key.pem /var/wazuh-manager/etc/certs/remoted.pem
```

Generation is skipped if a certificate/key pair already exists at those paths, so an
administrator-provided certificate is never overwritten. To force regeneration, remove both files
and re-run the command above (or reinstall). An administrator-provided pair must be readable by
the `wazuh-manager` user (e.g. via the same ownership/mode) or the module fails to start.

## Authentication (AES-CMAC)

Every request MUST carry two headers:

```text
protocol-version: 1
Authorization: Wazuh <agent-id>:<timestamp>:<mac>
```

- `agent-id` — identifier of the enrolled agent; used to look up its pre-shared AES key.
- `timestamp` — UNIX time in seconds. Accepted window: up to **300 s** in the past and **30 s** in
  the future.
- `mac` — the 16-byte AES-CMAC result, lowercase hex (32 chars).

The MAC is computed over a canonical byte sequence (LF = `0x0A`); the pre-shared key is **never**
transmitted:

```text
WAZUH-REQUEST\n
<protocol-version>\n
<uppercase-method>\n
<request-target>\n      (raw path + query, exactly as sent — no normalization)
<agent-id>\n
<timestamp>\n
<request-body>          (exact body bytes, no trailing newline)
```

The manager resolves the agent key by reading `etc/client.keys` directly (the same id/name/ip/key
format `OS_ReadKeys()` uses); the key column is lowercase hex and must decode to 16, 24 or 32 bytes.
A removed/disabled agent (`#`/`!`-marked, or simply absent) is treated as unknown.

### Content-Encoding (zstd)

The request body MAY optionally be compressed with `Content-Encoding: zstd` (case-insensitive). No
other value is accepted — **`gzip` is not supported.** Support can be turned off entirely with
`remoted.http_content_encoding_enabled` (default: enabled) — see [Configuration](#configuration).

**Why zstd and not gzip.** Both were measured on a real 48 MB FIM sync payload before choosing. At
its default level zstd beats gzip's default on all three axes at once, so there is no trade-off to
weigh — and decompression speed is the side that matters here, since agents compress while the
manager decompresses:

| Codec | Compressed | Compress | Decompress |
|---|---|---|---|
| `gzip-6` (default) | 4.25 MB | 224 ms | 44.2 ms |
| `gzip-9` (max) | 4.10 MB | 429 ms | 43.1 ms |
| **`zstd-3` (default)** | **3.66 MB** | **55 ms** | **24.0 ms** |
| `zstd-9` | 3.44 MB | 157 ms | 24.3 ms |

Supporting both was considered and dropped: it would mean two decoders, two dependency chains and
two test matrices for a codec that is dominated on this workload.

- Decompression happens **after** authentication succeeds, never before: the AES-CMAC always covers
  the exact wire bytes (the compressed body, if `Content-Encoding: zstd` is set), so an
  unauthenticated request never costs CPU/memory decompressing anything.
- `remoted.auth_max_body_size` (the 10 MiB cap that bounds an *uncompressed* body) plays **no part**
  in the zstd path at all. Instead, **both** of the decoder's memory costs are charged as real
  reservations against the **in-flight byte budget** (`max_inflight_bytes`, see
  [Configuration](#configuration)) — the same pool that bounds unprocessed request payloads. So a
  mostly-idle server admits requests one already near its memory ceiling refuses, and concurrent
  zstd requests genuinely compete for that pool rather than each reading the same "free" figure and
  all proceeding at once:
  - **The decoder's own buffers**, which zstd allocates *before* producing any output. Unlike
    gzip/DEFLATE (fixed 32 KiB window by spec), a zstd frame's header declares its own window size,
    so the amount needed is read straight off that header — each frame reserves exactly what it
    needs, not a blanket worst case. A frame is refused with `413` if that doesn't fit, before
    anything is decoded; a frame whose header can't even be read is rejected without consulting the
    budget at all. This reservation is released as soon as decompression finishes, since zstd frees
    those buffers then.
  - **The decompressed output buffer.** What is charged is the memory the buffer actually takes from
    the allocator, always reserved *before* it grows — so the figure can never lag behind real usage.
    A frame header normally declares its decompressed size, in which case that is charged once and
    the buffer sized to it exactly (one allocation, nothing to copy as it fills, and such a frame is
    refused up front if the declaration alone doesn't fit). A frame that omits the size — streaming
    compression with no pledged size — grows in doubling blocks instead, each block charged before it
    is allocated; that over-allocates relative to the data, but the over-allocation is charged rather
    than hidden. Either way a highly-compressed "decompression bomb" is rejected the moment a
    reservation is refused, before the full payload is ever materialized in memory. These bytes stay
    charged for as long as the decompressed body is held (released once the handler is done with it),
    the same way the compressed wire body's own reservation already works.
- A missing `Content-Encoding` header is treated exactly like today: the body is passed through
  unchanged.
- Any `Content-Encoding` value other than `zstd` — including `gzip`, which was intentionally dropped
  in favor of zstd-only support — is rejected with `415`. The same happens to `zstd` itself when
  `remoted.http_content_encoding_enabled` is disabled.
- A `Content-Encoding: zstd` body that isn't a valid, complete zstd frame (bad magic, truncated,
  unreadable header) is rejected with `400`. Note the distinction from `413` above: `400` means the
  frame itself is bad, `413` means the frame is fine but there isn't capacity for it right now.

### Error responses

On rejection the body is `{"error":"<message>","code":<status>}`. Credential-related failures all
collapse to a **single generic `401`** so a client cannot tell which specific check failed.

| Condition | HTTP | `error` message |
|---|---|---|
| Missing `protocol-version` header | `400` | `Missing required header: protocol-version` |
| Unsupported `protocol-version` | `400` | `Unsupported protocol-version` |
| Missing / malformed `Authorization`, unknown agent, unusable key, expired or future timestamp, invalid MAC | `401` | `Invalid client authentication` |
| Body exceeds the auth body limit (10 MiB) -- or, for `Content-Encoding: zstd`, the decoder's buffers or the decompressed output don't fit in the in-flight capacity free at that moment | `413` | `Request payload is too large` |
| `Content-Encoding` present but not (case-insensitively) `zstd` | `415` | `Unsupported Content-Encoding` |
| `Content-Encoding: zstd`, but the body isn't a valid/complete zstd frame | `400` | `Malformed compressed body` |
| Payload's `wazuh.agent.id` (H line) missing/malformed/non-numeric, or doesn't match the authenticated `agent-id` | `400` | `Invalid event batch` |
| Downstream rejected the batch (bad H/E) | `400` | `Invalid event batch` |
| Out of capacity, or downstream unreachable/errored | `503` | `Service unavailable` |
| Endpoint handler raised an unexpected error | `500` | `Internal server error` |

The payload-identity check runs **before** the batch is forwarded: a mismatch never reaches the
engine at all, and (by design) shares the same `400 Invalid event batch` message as a batch the
engine itself rejects, so a client cannot distinguish the two causes.

Requests larger than the 20 MiB transport cap are dropped at the TLS/HTTP layer (the connection is
closed) before authentication runs, so they never receive a clean `413`.

The server bounds capacity in two phases and sheds excess load with a plain **`503 Service
Unavailable`** (server-side load-shedding, not per-client rate-limiting; the connection is closed; no
`Retry-After` — the agent runs its own retry/backoff): the **in-flight byte budget** bounds total
unprocessed payload in memory, and the **deferred-work limiter** bounds how many requests are parked
awaiting the downstream service. The liveness `GET /` is exempt from the byte budget, so it stays
`200` under pressure. See the memory settings below.

## Endpoints

- **`GET /`** — unauthenticated health probe. Returns `200` with
  `{"status":"ok","module":"remoted"}`.
- **`POST /stateless`** — authenticated event ingestion. Once the signature is verified, the module
  cross-checks the H line's `wazuh.agent.id` against the authenticated `agent-id` (**`400`** on a
  missing/malformed header or a mismatch); only then does it forward the H/E batch to the engine's
  event ingress over a Unix-domain socket (`POST /events/enriched`) and reply from the downstream
  result: **`202 Accepted`** (engine enqueued the batch), **`400`** (engine rejected the batch),
  **`413`**, or **`503`** (out of capacity or the engine is unreachable/errored). Auth failures
  return the errors above.
- **`POST /control`** — authenticated agent lifecycle and control messages. Once the signature is
  verified, the module processes the agent's control message (`startup`, `notify`, or `shutdown`),
  updates agent metadata in wazuh-db, retrieves pending tasks from task-manager, and returns
  configuration state and pending work. Handles agent initial connection state (`startup` with
  limits, cluster info, and groups), periodic keepalive every 10 seconds (`notify` with hash-based
  change detection for config and settings), and clean disconnection (`shutdown`). Returns **`200
  OK`** with a JSON response on success, **`400`** on malformed requests, **`401`** on auth
  failures, or **`503`** when wazuh-db/task-manager are unreachable. See
  [Control endpoint](#control-endpoint-post-control) below for details.
- **`POST /stateful`** — authenticated inventory synchronization. Once the signature is verified,
  the module relays the body opaquely (stamping the authenticated identity as `X-Wazuh-Agent-Id`)
  to the [Inventory Sync Server](../inventory-sync-server/README.md) over its Unix-domain socket
  (`queue/sockets/inventory-sync.sock`) and returns the downstream answer verbatim — the response
  IS the session result (see the server's
  [response contract](../inventory-sync-server/api-reference.md)). The wait for the downstream
  answer is bounded by `remoted.downstream_stateful_response_timeout`
  (see [configuration](configuration.md)). Bodies may be zstd-compressed
  (`Content-Encoding: zstd`); remoted decompresses before relaying.
- **`POST /scan/vd`** — authenticated on-demand Vulnerability Detection re-scan request, sent by an
  agent once it notices (via `notify`'s `vd_feed_offset`) that this node's feed has moved past what
  it last synced against. Returns **`200 OK`** (queued) when the request's `feed_offset` matches
  this node's current offset, **`409 Conflict`** (carrying the real offset to retry with) on a
  mismatch, **`400`** on malformed requests, **`401`** on auth failures, or **`503`** when the
  manager-side scan tracking table is full. See
  [Scan endpoint](#scan-endpoint-post-scanvd) below for details.

The machine-readable contract is published as OpenAPI — see the
[endpoint reference](stateless-api-reference.html) (source: [`stateless-api.yaml`](stateless-api.yaml)).

## Configuration

Advanced RESTinio tuning knobs (threading, timeouts, message limits) resolve as **caller value →
built-in default**. `remoted` populates the caller value by reading the `remoted.http_*` internal
options (`etc/wazuh-manager-internal-options.conf`) in `secure.c` and passing the result to
`remoted_module` through its C-ABI struct; an option present in the file but out of range (or
non-numeric) prevents `remoted` from starting, same as every other internal option. See
[Internal Options](configuration.md#internal-options) for the full reference (allowed ranges,
notes).

| Setting | Default | Internal option |
|---|---|---|
| I/O threads | `cpp_get_nproc()` | `remoted.http_io_threads` |
| Handler worker threads | `2 * cpp_get_nproc()` | `remoted.http_worker_threads` |
| Read / handshake timeout | `10 s` | `remoted.http_read_timeout` |
| Write timeout | `10 s` | `remoted.http_write_timeout` |
| Request timeout | `30 s` | `remoted.http_request_timeout` |
| Max URL size | `2048 B` | `remoted.http_max_url_size` |
| Max header name size | `256 B` | `remoted.http_max_header_name_size` |
| Max header value size | `8192 B` | `remoted.http_max_header_value_size` |
| Max header count | `64` | `remoted.http_max_header_count` |
| Max pipelined requests per connection | `4` | `remoted.http_max_pipelined_requests` |
| Concurrent TCP accepts | `2` | `remoted.http_concurrent_accepts` |
| Socket read buffer size | `8192 B` | `remoted.http_buffer_size` |
| Accept `Content-Encoding: zstd` | enabled | `remoted.http_content_encoding_enabled` |

I/O threads and handler worker threads are thread-count settings: a `<=0` value (including "not
set" in `wazuh-manager-internal-options.conf`) resolves via `cpp_get_nproc()`
(`shared_modules/utils/proc.hpp`, cgroup-aware on Linux) instead of a fixed constant, so the pool
sizes track the host/container's available CPUs. The handler worker pool is oversubscribed (`2x`)
because that work can block (AES-CMAC verification, `client.keys` file I/O), unlike the purely
async I/O threads.

Bind address, port, max body size, the certificate/private key paths, and the mTLS settings (CA,
ciphers, client verification mode) are **not** internal options -- they are regular, user-facing
`<remote><https>` settings (`wazuh-manager.conf`). All resolve as **`<https>` tag value → built-in
default**; an absent `<https>` block, or an absent individual option within it, falls back to the
built-in default below. See
[Configuration Reference — HTTPS Configuration](configuration.md#https-configuration) for the full
`<https>` tag reference and examples (including mutual TLS). Threading (`io_threads`,
`http_worker_threads`) is not exposed in `<https>` and remains an internal option (see the table
above).

| Setting | `<https>` tag | Default |
|---|---|---|
| Bind address (IPv4 or IPv6, see [above](#bind-address-ipv4-ipv6-and-dual-stack)) | `bind_addr` | `127.0.0.1` |
| Dual-stack override (IPv6 `bind_addr` only) | `dual_stack` | `no` (force IPv6-only) |
| Port | `port` | `1517` |
| Transport max body size | `max_body_size` | `20 MiB` |
| TLS certificate chain | `certificate` | `etc/certs/remoted.pem` |
| TLS private key | `key` | `etc/certs/remoted-key.pem` |
| Client CA bundle | `ca` | `etc/certs/root-ca.pem` |
| Client verification mode | `verification_mode` | `none` (auto-upgraded to `certificate` if `<ca>` is set in XML without `<verification_mode>`) |
| TLS 1.3 ciphersuites | `ciphers` | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256` |

> There is no `enabled` toggle: the listener always attempts to start and self-gates on the
> presence of a valid certificate/key, same as before this configuration surface existed.

The **memory-management / capacity** settings are a separate, third group: `remoted` sets them
directly on the C-ABI struct in `secure.c` (→ built-in default when unset) and they are
deliberately **not** internal options -- they bound in-memory resource usage rather than tune the
transport, so they don't go through `remoted_module_https_config()`/the internal-options table
above.

| Setting | Default | Source |
|---|---|---|
| Max in-flight payload bytes (→ `503`) | `256 MiB` | remoted config `max_inflight_bytes` |
| Max simultaneous connections | `512` | remoted config `max_parallel_connections` |
| Max deferred requests awaiting downstream (→ `503`) | `256` | remoted config `max_deferred_requests` |

The capacity limits are **layered**: the transport max body size caps a single request's peak
(RESTinio rejects an oversized `Content-Length` early by closing the connection), the max connections
caps how many bodies can be read at once (peak ≈ max connections × max body size), the in-flight byte
budget caps the total accepted-but-unprocessed payload in memory, and the deferred-request limiter
caps how many requests are parked awaiting a downstream service. Exhausting either budget → a plain
`503` (the agent retries; the liveness `GET /` is exempt from the byte budget).

### Downstream client and auth middleware

A fourth group of internal options tunes the deferred-forwarding downstream UDS client
(`downstream/downstreamConfig.hpp`/`.cpp`) and the auth middleware's timestamp window / body cap
(`auth/authTypes.hpp`/`.cpp`). Same resolution pattern as the RESTinio settings above: `secure.c`
reads each `remoted.*` option and passes it through the C-ABI struct;
`remoted::downstream::buildDownstreamConfig()`/`remoted::auth::buildAuthConfig()` apply the
built-in default on `<=0`. The three timeouts are configured in **seconds** and converted to
milliseconds internally.

| Setting | Default | Internal option |
|---|---|---|
| Downstream connect timeout | `2 s` | `remoted.downstream_connect_timeout` |
| Downstream write timeout | `5 s` | `remoted.downstream_write_timeout` |
| Downstream response timeout | `5 s` | `remoted.downstream_response_timeout` |
| Downstream client I/O threads | `cpp_get_nproc()` | `remoted.downstream_io_threads` |
| Downstream post-processing threads | `cpp_get_nproc()` | `remoted.downstream_post_process_threads` |
| Max downstream response body | `10 MiB` | `remoted.downstream_max_response_body_size` |
| Auth max request age | `300 s` | `remoted.auth_max_request_age` |
| Auth max future skew | `30 s` | `remoted.auth_max_future_skew` |
| Auth max body size | `10 MiB` | `remoted.auth_max_body_size` |

The two thread-count fields above resolve a `<=0` value via `cpp_get_nproc()` the same way
`http_io_threads`/`http_worker_threads` do (no `2x` oversubscription here -- both pools are either
a purely async I/O reactor or documented as non-blocking work). The downstream client's events
socket path (`eventsSocketPath`) and the auth middleware's `supportedProtocolVersion` are not
internal options -- the former is an installation detail (mirrors the classic C forwarder's
socket), the latter a protocol constant.

### client.keys hot-reload

`Keystore` (the agent key lookup behind the AES-CMAC auth layer) watches `client.keys` in the
background and reloads it on change, so an agent enrolled or removed after `remoted` starts is
picked up without a restart. An `inotify` subscription reacts immediately; the poll cadence used as
a fallback (in case a notification is ever missed) is `remoted.keyupdate_interval` -- the same
option the classic pipeline's own key-reload thread (`rem_keyupdate_main`) already uses, see
[Internal Options](configuration.md#internal-options) -- not a separate internal option.
Change detection hashes the file's content (not mtime, which is only second-granularity) and
`reload()` re-checks the hash before and after parsing, discarding and retrying a parse caught
mid-write rather than adopting a torn read.

## Diagnosing rejections and capacity problems

Every condition where a setting may need changing is logged to `wazuh-manager.log ` and names the setting.
Because these are per-request conditions, repeated occurrences are collapsed to **one line per 90
seconds per condition**, with the suppressed count folded into the message, so a burst or an outage
produces a readable summary instead of thousands of identical lines:

```
wazuh-manager-remoted:forwarder: WARNING: Deferred-work slots exhausted (capacity 256): shed 4812
request(s) with 503 in the last 90 s. Consider increasing the value of 'max_deferred_requests', or
investigate why the downstream service is not keeping up.
```

| Symptom in `wazuh-manager.log ` | Setting to review |
|---|---|
| In-flight request memory budget exhausted | `max_inflight_bytes` |
| Deferred-work slots exhausted | `max_deferred_requests` |
| Timed out connecting to / sending to / waiting for the downstream service | `remoted.downstream_connect_timeout`, `_write_timeout`, `_response_timeout` |
| Downstream response exceeded the configured cap | `remoted.downstream_max_response_body_size` |
| Timestamps outside the accepted window (agent clock drift) | `remoted.auth_max_request_age`, `remoted.auth_max_future_skew` |
| Body exceeded the authenticated-body cap (413) | `remoted.auth_max_body_size` (uncompressed body), or `max_inflight_bytes` (`Content-Encoding: zstd`) |
| Downstream timeouts add up past `http_request_timeout` | `remoted.http_request_timeout` |

Three more that are not about tuning:

- **`Loaded N agent key(s) from '<path>'`** at startup and after every hot-reload. `N` counts keys
  that can actually authenticate — a key that fails to decode is reported separately and is **not**
  counted, so this number can be trusted. If `client.keys` is unreadable, that is logged explicitly:
  otherwise it presents only as every agent being rejected as unknown, with nothing explaining why.
- **`AES-CMAC is unavailable…`** (ERROR) means the OpenSSL provider is broken and *every* agent will
  fail to authenticate. Previously indistinguishable from one agent having a corrupt key.
- **The HTTPS server failing to start** is an ERROR naming which of the two is the problem (the
  certificate or the private key). There is no retry: remoted must not start without the HTTPS
  transport up, so a missing or unreadable certificate/key is fatal to the whole daemon, not just
  this module — the certificate is expected to already be in place by then (auto-generated at
  install time, see [Transport and TLS](#transport-and-tls)). The module opens the configured
  `certificate`/`key`/`ca` paths itself, after `remoted` has already dropped root privileges, so
  "unreadable" most often means a permission/ownership mismatch against the `wazuh-manager` user,
  not a missing file.

Client-side rejections (malformed or unauthenticated requests) are logged at debug level only —
visible with `remoted.debug=2` — because an unauthenticated peer controls how many it can trigger.
Transport-level diagnostics reported by the HTTP library itself (TLS handshake errors, malformed
HTTP, socket resets, and breaches of the `remoted.http_max_*` limits) are logged at
`remoted.debug=1`, not surfaced by default: these are per-connection events driven overwhelmingly by
client behavior — a portscanner, or negative-test traffic like `tools/send_stateless.py --all` — not
a manager-side problem, so they are not logged unthrottled at warning/error level the way
`max_inflight_bytes`/`max_deferred_requests` exhaustion or a genuine startup failure are. The one
exception, the HTTPS server failing to bind, is already covered above.

## Control endpoint (`POST /control`)

The `/control` endpoint manages agent lifecycle events and periodic keepalive for 5.x agents,
replacing the legacy TCP-based control messages (`#!-agent startup`, `#!-agent shutdown`) used by
4.x agents. It handles three message types: **startup** (agent initial connection), **notify**
(periodic keepalive every 10 seconds), and **shutdown** (clean agent disconnection).

### Message types

All requests carry a JSON body with a `type` field indicating the message type. Authentication and
error handling follow the same AES-CMAC mechanism as `/stateless` (see
[Authentication](#authentication-aes-cmac) above).

#### Startup

Sent by the agent on initial connection. The manager marks the agent as connected in global.db,
records the connection time, and returns limits (FIM, Syscollector, SCA quotas), cluster
information (name), and the agent's assigned groups. The agent stores this data locally.
No hashes are included in the startup response.

**Request:**
```json
{
  "type": "startup",
  "version": "5.0.0"
}
```

**Response (`200 OK`):**
```json
{
  "limits": {
    "fim": {"file": 100000, "registry_key": 100000, "registry_value": 100000},
    "syscollector": {"packages": 50000, "processes": 50000, "ports": 50000},
    "sca": {"checks": 10000}
  },
  "cluster": {
    "name": "wazuh-cluster"
  },
  "agent": {
    "groups": ["default", "web-servers"]
  }
}
```

#### Notify (keepalive)

Sent every 10 seconds. The agent includes metadata (version) and optionally host information
(hostname, architecture, IP, OS details). The manager calculates two hashes: `settings_hash` (SHA-256
of limits + cluster + groups from the startup data) and `config_hash` (SHA-256 of the agent's
`merged.mg` file), queries task-manager for pending tasks, and returns the hashes along with any
tasks.

The manager throttles wazuh-db writes per agent (default 300s): when the throttle window has expired,
it writes a full update (`updateAgentData`) if host metadata is present in the request, or a
lightweight keepalive (`updateKeepalive`) otherwise.

If tasks are found, the manager marks them as delivered (updates status to `delivered` and records
delivery time). Task delivery status is **local only** (not broadcast to the cluster).

The agent compares the received hashes against its local copies: if `settings_hash` differs, it
sends a new `startup` request; if `config_hash` differs, it downloads the new `merged.mg` file via
`/download`.

The response also carries `vd_feed_offset`: this node's current Vulnerability Detection feed
offset, always present (0 if the feed has never completed an update, or if the VD module is
temporarily unreachable — see [Scan endpoint](#scan-endpoint-post-scanvd) below). The agent
persists the highest offset it has seen; when a fresh notify reports a strictly higher offset than
its stored value, that's this node's signal that the feed changed since the agent last synced, and
the agent requests its own re-scan via `POST /scan/vd`. This offset comparison — not a manager-
initiated push — is what replaced the old node-affinity full-rescan (every node querying global.db
for "its" agents over a persistent TCP/UDP connection and rescanning all of them on every feed
update), which had no equivalent once agent-manager connections became stateless HTTPS. See
[Scan endpoint](#scan-endpoint-post-scanvd) for the full mechanism.

**Request:**
```json
{
  "type": "notify",
  "agent": {
    "version": "5.0.0"
  },
  "host": {
    "hostname": "ubuntu-test",
    "architecture": "x86_64",
    "ip": "192.168.1.100",
    "os": {
      "name": "Ubuntu",
      "version": "20.04",
      "platform": "ubuntu",
      "type": "linux"
    }
  }
}
```

**Response without tasks (`200 OK`):**
```json
{
  "agent": {
    "groups": ["web-servers"],
    "config_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "settings_hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
  "vd_feed_offset": 12345678
}
```

**Response with tasks (`200 OK`):**
```json
{
  "agent": {
    "groups": ["web-servers"],
    "config_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "settings_hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
  "vd_feed_offset": 12345678,
  "tasks": [
    {
      "task_id": "a3f5e2d1-4c6b-8a9e-1f2d-3c4b5a6e7d8f",
      "task_type": "active_response",
      "payload": {
        "wazuh": {
          "active_response": {
            "name": "firewall-drop",
            "executable": "firewall-drop",
            "extra_arguments": "192.168.1.100"
          }
        },
        "rule": {"id": 5503},
        "data": {"srcip": "192.168.1.100"}
      }
    }
  ]
}
```

#### Shutdown

Sent when the agent cleanly disconnects (e.g., service stop, not a crash). The manager updates the
agent status in global.db to "disconnected" and records the disconnection time.

**Request:**
```json
{
  "type": "shutdown"
}
```

**Response (`200 OK`):**
```json
{}
```

### Architecture

The `/control` endpoint integrates with two backend services over Unix-domain sockets:

- **wazuh-db** (`queue/db/wdb`): Agent metadata storage. The handler writes agent info (OS, version,
  hostname, etc.) via `agent <id> set <field> <value>` commands, updates connection status, and
  reads back the agent's groups. Dedicated worker threads with bounded request queues and async I/O
  prevent blocking the HTTP worker threads.
- **task-manager** (`queue/tasks/task`): Task delivery. The handler queries pending tasks for the
  agent via JSON API (`{"action":"get_pending_tasks","agent_id":"001"}`). Returned tasks are
  included in the response. Task state is local to the node; cluster broadcast is handled separately
  by the task-manager service.
- **vulnerability_scanner module** (`queue/sockets/modulesd`, `GET /vulnerability-detector/offset`):
  queried by `VdClient` (`remoted_module/src/common/vdClient.hpp`) to populate `vd_feed_offset`.
  Cached with a short TTL and a single-flight refresh (only one caller ever performs the actual UDS
  round trip; every concurrent caller gets the last-known-good value instead of blocking) so a slow
  or unreachable VD module can never serialize this hot path down to one request at a time. Falls
  back to the last known offset (or 0) if the module is unreachable — see
  [Scan endpoint](#scan-endpoint-post-scanvd) below, which shares this same client.

A thread-safe **agent registry** (8-shard hash table) caches agent metadata (groups, last activity
timestamp, last keepalive update timestamp) to minimize wazuh-db round-trips during the hot path
(`notify` every 10 seconds per agent). Entries are evicted periodically based on inactivity TTL.

### Error handling

Errors follow the same pattern as `/stateless` (see [Error responses](#error-responses) above).
Control-specific conditions:

| Condition | HTTP | `error` message |
|---|---|---|
| Body empty or exceeds 64 KiB | `400` | `invalid_body` |
| Malformed JSON body | `400` | `invalid_json` |
| Invalid agent ID format | `400` | `invalid_agent_id` |
| Unknown message type | `400` | `unknown_message_type` |
| Invalid agent version (startup only) | `400` | `invalid_version` |
| Invalid host info format (notify only) | `400` | `invalid_host_info` |
| wazuh-db error during startup (get groups) | `500` | `database_error` |

Auth failures (`401`) and body-too-large at transport layer (`413`) reuse the same responses as
`/stateless`. Throttled logging (one message per 90 seconds per condition) prevents log flooding
from repeated errors; see
[Diagnosing rejections and capacity problems](#diagnosing-rejections-and-capacity-problems).

## Scan endpoint (`POST /scan/vd`)

`/scan/vd` is the on-demand re-scan request an agent sends once it notices (via `vd_feed_offset` in
a `/control` notify response, see above) that this node's Vulnerability Detection feed has moved
past the offset the agent last synced against. It replaces the pre-HTTPS mechanism, where each
manager node held a persistent TCP/UDP connection to a fixed set of agents and, on every feed
update, queried global.db for "its" agents and rescanned all of them — a mechanism that assumed a
stable agent-to-node mapping. Stateless HTTPS load-balances every request independently, so no node
can know in advance which agents are "its own"; instead, the agent is the one source of truth for
"do I need a re-scan," and it asks whichever node the load balancer routes it to.

### Request

```json
{
  "type": "feed_update",
  "feed_offset": 12345678
}
```

`type` is currently always `"feed_update"` — reserved for other trigger reasons the design
anticipates but does not yet implement (e.g. a manually requested scan). `feed_offset` is the
offset the agent is asking to be scanned against — normally the value it most recently received
from `/control`.

### Responses

**Accepted (`200 OK`):**
```json
{}
```

The request is queued (see [Manager-side queue](#manager-side-queue) below) and the agent should
consider the offset it sent as handled — it clears any persisted retry state for that offset.

**Version mismatch (`409 Conflict`):**
```json
{
  "error": "version_mismatch",
  "current_version": 12345680
}
```

Returned when `feed_offset` does not equal this node's current offset — either because the agent's
value is stale (a different, newer node already advanced it) or, more rarely, ahead of this node's
own feed (this node hasn't finished applying an update the agent already saw elsewhere). Either way,
the agent updates its stored offset from `current_version` only if it is strictly greater than what
the agent already has (offsets only ever move forward) and retries. It never overwrites a newer
local value with an older `current_version`.

### Error handling

| Condition | HTTP | `error` message |
|---|---|---|
| Body empty or exceeds 4 KiB | `400` | `invalid_body` |
| Malformed JSON body | `400` | `invalid_json` |
| Invalid agent ID format | `400` | `invalid_agent_id` |
| Missing or non-string `type` | `400` | `missing_type` |
| `type` other than `"feed_update"` | `400` | `invalid_type` |
| Missing or non-unsigned `feed_offset` | `400` | `missing_feed_offset` |
| `feed_offset` != current offset | `409` | `version_mismatch` (carries `current_version`) |
| Scan tracking table at capacity | `503` | `scan_queue_full` |

Auth failures (`401`) reuse the same responses as `/stateless`. This endpoint's body cap (4 KiB) is
far tighter than `/control`'s (64 KiB) since a scan request only ever carries `type` and
`feed_offset`.

### Manager-side queue

Accepting a request does not scan synchronously — `scanVdHandler.cpp` maintains a per-agent state
table and a small pool of worker threads (sized to the host's available CPUs) that:

1. Re-validate the offset immediately before dispatching the scan to the `vulnerability_scanner`
   module (`POST /vulnerability-detector/scan` over the same UDS socket `VdClient` uses). The feed
   may have moved on again while the request was queued; a stale task is discarded, not run — the
   agent will notice the newer offset on its next `/control` notify and re-request.
2. Retry a *retryable* failure (e.g. the scanner briefly unready) with exponential backoff (1s, 2s,
   4s), up to 3 attempts, then give up and let the agent's next notify cycle re-trigger it.
3. Collapse duplicate requests for the same agent into one another: a fresh request for an
   already-tracked agent just updates the tracked offset (retrying immediately if the agent was
   mid-backoff) rather than queuing a second entry.

Duplicate scans across different nodes (the agent asks node A, doesn't get a timely reply, and asks
node B too) are accepted as a rare, low-impact trade-off rather than solved with cross-node
coordination.

Disconnected agents (never reachable, so they can never notice `vd_feed_offset` or call this
endpoint themselves) are not covered by `/scan/vd` at all — they're swept separately, once per feed
update, by the cluster's master node only (`VulnerabilityScannerFacade::rescanDisconnectedAgents()`
in the `vulnerability_scanner` module).

## Testing

`src/remoted/remoted_module/tools/send_stateless.py` signs and sends `POST /stateless` requests the
same way the manager verifies them (AES-CMAC over the canonical sequence, key read from
`client.keys`). Requires `pip install -r requirements.txt` (in the same `tools/` directory).

```bash
# one valid signed request -> 202
python3 send_stateless.py --agent-id 1001

# tamper the body after signing -> 401 (invalid MAC)
python3 send_stateless.py --agent-id 1001 --tamper

# run every success/failure scenario and check the expected status codes, including
# Content-Encoding: zstd (valid, malformed, and a body decompressing past the 10 MiB auth cap --
# which is accepted, since that cap does not apply to decompressed bodies) and the unsupported gzip
python3 send_stateless.py --all
# options: --url (default https://127.0.0.1:1517), --body, --client-keys
```

`src/remoted/remoted_module/tools/send_scan_vd.py` does the same for `POST /scan/vd`, and can
discover the manager's current offset for you instead of guessing it:

```bash
# looks up the current vd_feed_offset via /control, then sends a matching request -> 200
python3 send_scan_vd.py --auto-offset

# a deliberately wrong offset -> 409, prints the manager's real current_version to retry with
python3 send_scan_vd.py --feed-offset 1

# run every success/failure scenario (missing/invalid type, missing/negative feed_offset,
# oversized body, auth failures, ...), including the matching- and mismatched-offset cases
python3 send_scan_vd.py --all
# options: --url (default https://127.0.0.1:9443), --agent-id, --client-keys
```

## References

- [Event Protocol Specification](event-protocol.md) — the `H`/`E` wire format for event batches.
- [Configuration](configuration.md) — classic `remoted` (`<remote>`) options and internal options.
- [Architecture](architecture.md) — where the HTTPS listener sits in the `remoted` pipeline.
- Endpoint contract: [`stateless-api.yaml`](stateless-api.yaml) /
  [ReDoc reference](stateless-api-reference.html).
