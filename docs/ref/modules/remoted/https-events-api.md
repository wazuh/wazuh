# HTTPS Events API

`remoted` embeds a self-contained C++ module (`remoted_module`) that runs an **HTTPS listener**
for agent-authenticated event ingestion, in addition to the classic AES-encrypted TCP/UDP channel
on port `1514`. The listener is built on RESTinio + OpenSSL and authenticates every request with a
per-agent **AES-CMAC** signature derived from the agent's pre-shared key.

> **Experimental / work in progress.** The endpoint today performs **authentication and request
> validation only** — it does **not** parse the H/E payload or ingest events yet. A successful
> request is authenticated and answered `200` with an empty body; nothing is forwarded downstream.
> The listener also only starts when a TLS certificate and key are present (see
> [Transport and TLS](#transport-and-tls)); on a default install it is effectively off.

## Overview

- A C++17 module linked into `wazuh-manager-remoted` exposes the HTTPS server. It is **Linux
  manager only** (agents and Windows do not build it).
- The transport (RESTinio) sits behind an internal interface, so the endpoint contract and the
  authentication layer are independent of the HTTP library.
- The server is started **lazily** by the module's worker thread and retried on every heartbeat
  (every 60 s): if the certificate/key are missing it logs a warning and tries again later, so a
  missing certificate never blocks `remoted` startup.
- Authentication and endpoint handlers run on a bounded worker pool, off the I/O threads.

## Transport and TLS

- **Bind address / port:** `127.0.0.1:9443` by default.
- **TLS:** minimum version TLS 1.2; the server loads a PEM certificate chain and private key and
  verifies that the key matches the certificate.
- **Certificate paths (evaluated after `remoted` enters its chroot):**
  `/etc/remoted-https/server.crt` and `/etc/remoted-https/server.key` — i.e. host paths
  `/var/wazuh-manager/etc/remoted-https/server.{crt,key}`. The private key must be readable by the
  `wazuh` user that `remoted` runs as.
- **Message limits and timeouts:** max URL 2048 B, max header name 256 B, max header value 8192 B,
  max 64 header fields, and a transport body cap of 16 MiB by default; read/handshake timeout 10 s,
  write timeout 10 s, request timeout 30 s. All tunable via `remoted.http_*` internal options -- see
  [Configuration](#configuration) below.

Generate a self-signed certificate for testing:

```bash
mkdir -p /var/wazuh-manager/etc/remoted-https
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=localhost" \
  -keyout /var/wazuh-manager/etc/remoted-https/server.key \
  -out   /var/wazuh-manager/etc/remoted-https/server.crt
chown wazuh /var/wazuh-manager/etc/remoted-https/server.key
```

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

Requests larger than the 16 MiB transport cap are dropped at the TLS/HTTP layer (the connection is
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

Advanced RESTinio settings resolve as **caller value → built-in default**. `remoted` populates the
caller value by reading the `remoted.http_*` internal options
(`etc/wazuh-manager-internal-options.conf`) in `secure.c` and passing the result to
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

Bind address, port, max body size and the certificate/private key paths are **not** internal
options -- these belong in the regular `<remote>` configuration (`wazuh-manager.conf`), not
`wazuh-manager-internal-options.conf` (bind address/port/max body size are regular, user-facing
settings; the certificate/private key paths have no string-valued internal-option mechanism to use
even if they were advanced tuning). That `<remote>` wiring doesn't exist yet, so all five resolve as
**caller value (C-ABI struct) → built-in default**, and `remoted` currently leaves those C-ABI
fields unset -- in practice the built-in defaults below apply.

| Setting | Default |
|---|---|
| Bind address | `127.0.0.1` |
| Port | `9443` |
| Transport max body size | `16 MiB` |
| TLS certificate chain | `/etc/remoted-https/server.crt` |
| TLS private key | `/etc/remoted-https/server.key` |

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

> There is no `ossec.conf` (`<remote>`) setting for the HTTPS listener yet; configuration is
> limited to the internal options above, the memory-management settings, and the certificate
> files on disk.

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
# options: --url (default https://127.0.0.1:9443), --body, --client-keys
```

## References

- [Event Protocol Specification](event-protocol.md) — the `H`/`E` wire format for event batches.
- [Configuration](configuration.md) — classic `remoted` (`<remote>`) options and internal options.
- [Architecture](architecture.md) — where the HTTPS listener sits in the `remoted` pipeline.
- Endpoint contract: [`stateless-api.yaml`](stateless-api.yaml) /
  [ReDoc reference](stateless-api-reference.html).
