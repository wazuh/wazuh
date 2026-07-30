# HTTPS Events API

`remoted` embeds a self-contained C++ module (`remoted_module`) that runs an **HTTPS listener**
for agent-authenticated event ingestion, in addition to the classic AES-encrypted TCP/UDP channel
on port `1514`. The listener is built on RESTinio + OpenSSL and authenticates every request with a
per-agent **AES-CMAC** signature derived from the agent's pre-shared key.

> **Experimental / work in progress.** The endpoint today performs **authentication and request
> validation only** — it does **not** parse the H/E payload or ingest events yet. A successful
> request is authenticated and answered `200` with an empty body; nothing is forwarded downstream.
> The listener **requires** a TLS certificate and key to be present (see
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
  `etc/https-manager.cert`, `etc/https-manager.key`, and `etc/https-manager-ca.pem` — i.e. host paths
  `/var/wazuh-manager/etc/https-manager.cert`, `/var/wazuh-manager/etc/https-manager.key`, and
  `/var/wazuh-manager/etc/https-manager-ca.pem`. These paths are opened by the module itself,
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
`authd` uses for `sslmanager.cert`/`sslmanager.key` — now shared code, invoked through remoted's
own binary, and chowned to `wazuh-manager:wazuh-manager` afterward so the module can read it once
`remoted` drops privileges:

```bash
wazuh-manager-remoted -C 365 -B 2048 \
  -K /var/wazuh-manager/etc/https-manager.key \
  -X /var/wazuh-manager/etc/https-manager.cert \
  -S "/C=US/ST=California/CN=Wazuh/"
chown wazuh-manager:wazuh-manager /var/wazuh-manager/etc/https-manager.key /var/wazuh-manager/etc/https-manager.cert
chmod 640 /var/wazuh-manager/etc/https-manager.key /var/wazuh-manager/etc/https-manager.cert
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

### Error responses

On rejection the body is `{"error":"<message>","code":<status>}`. Credential-related failures all
collapse to a **single generic `401`** so a client cannot tell which specific check failed.

| Condition | HTTP | `error` message |
|---|---|---|
| Missing `protocol-version` header | `400` | `Missing required header: protocol-version` |
| Unsupported `protocol-version` | `400` | `Unsupported protocol-version` |
| Missing / malformed `Authorization`, unknown agent, unusable key, expired or future timestamp, invalid MAC | `401` | `Invalid client authentication` |
| Body exceeds the auth body limit (10 MiB) | `413` | `Request payload is too large` |
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
| TLS certificate chain | `certificate` | `etc/https-manager.cert` |
| TLS private key | `key` | `etc/https-manager.key` |
| Client CA bundle | `ca` | `etc/https-manager-ca.pem` |
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
| Body exceeded the authenticated-body cap (413) | `remoted.auth_max_body_size` |
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

## Testing

`src/remoted/remoted_module/tools/send_stateless.py` signs and sends `POST /stateless` requests the
same way the manager verifies them (AES-CMAC over the canonical sequence, key read from
`client.keys`). Requires `pip install requests cryptography`.

```bash
# one valid signed request -> 200
python3 send_stateless.py --agent-id 1001

# tamper the body after signing -> 401 (invalid MAC)
python3 send_stateless.py --agent-id 1001 --tamper

# run every success/failure scenario and check the expected status codes
python3 send_stateless.py --all
# options: --url (default https://127.0.0.1:1517), --body, --client-keys
```

## References

- [Event Protocol Specification](event-protocol.md) — the `H`/`E` wire format for event batches.
- [Configuration](configuration.md) — classic `remoted` (`<remote>`) options and internal options.
- [Architecture](architecture.md) — where the HTTPS listener sits in the `remoted` pipeline.
- Endpoint contract: [`stateless-api.yaml`](stateless-api.yaml) /
  [ReDoc reference](stateless-api-reference.html).
