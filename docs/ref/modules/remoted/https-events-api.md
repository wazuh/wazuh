# HTTPS Agent API

`remoted` embeds a self-contained C++ module (`remoted_module`) that runs an **HTTPS listener** on
port `1517`. This is the agent-manager transport in 5.0: a 5.x agent enrolls, reports and receives
work over it exclusively. The classic AES-encrypted TCP/UDP channel on port `1514` still exists, but
only to keep serving 4.x agents, and only when it is explicitly enabled with `<remote><legacy>` —
see [Configuration](configuration.md).

The listener is built on RESTinio + OpenSSL and authenticates every request with a per-agent
**`wazuh-agent+jwt` bearer token** (HS256) the agent self-signs with its pre-shared `client.keys` key.

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
  unmaps this back to plain IPv4 before it's used anywhere (e.g. `HttpRequest::remoteIp`), which is
  what lets the registered-address check below compare it against the `ip` column in `client.keys`
  without either side having to handle the mapped form.

A self-signed certificate/key pair is generated automatically at install time (source install,
`.deb` and `.rpm` all wire this in) via the shared `generate_cert()` routine, invoked through
remoted's own binary, and chowned to `wazuh-manager:wazuh-manager` afterward so the module can read
it once `remoted` drops privileges:

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

## Authentication (JWT bearer)

**Single exception: `POST /enroll`.** Every other endpoint on this page requires the agent<->manager
bearer token described in this section, keyed by an agent's pre-shared `client.keys` entry. An
enrolling agent has no such entry yet, so `/enroll` cannot use it — it authenticates with an
independent, per-listener credential instead (a client certificate, a password-derived bearer of its
own, or neither). See [Enrollment endpoint](#enrollment-endpoint-post-enroll) below.

Every other request MUST carry two headers:

```text
protocol-version: 1
Authorization: Bearer <JWS compact serialization>
```

The token is a JSON Web Signature ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) in compact
form — `base64url(header) "." base64url(claims) "." base64url(signature)`, base64url **without
padding** — following the closed profile **`wazuh-agent+jwt`**. "Closed" means nothing is negotiable:
a token is either exactly this profile or it is rejected.

| Part | Value |
| --- | --- |
| JOSE header | exactly `{"alg":"HS256","kid":"<agent-id>","typ":"wazuh-agent+jwt"}` — no other member, `kid` in the canonical zero-padded form of the agent id (`001`, not `1`) |
| Claims | exactly six: `exp`, `iat`, `iss` (`wazuh-agent/<agent-id>`), `jti`, `nbf` (= `iat`), `sub` (= `<agent-id>`). No `aud`: the `typ` fixes the domain of the token, and a fixed audience value would add nothing an operator could vary |
| `iat`/`nbf`/`exp` | UNIX seconds, integers; `exp - iat` is **always 60 s** — a profile constant, not a setting. Acceptance is clock-relative and tunable: `now - iat <= jwt_max_age + jwt_clock_skew` and `iat <= now + jwt_clock_skew` ([`remoted.jwt_max_age`](configuration.md#remotedjwt_max_age) 60 s, [`remoted.jwt_clock_skew`](configuration.md#remotedjwt_clock_skew) 30 s by default) |
| `jti` | 16 CSPRNG bytes, base64url (22 chars), fresh for every request — the agent never reuses a token, and the manager keeps no replay store (see below) |
| Signature | HMAC-SHA256 over `base64url(header) "." base64url(claims)` with the **32-byte key obtained by hex-decoding the 64-character `client.keys` secret** — never the ASCII text of the secret. The key is never transmitted |
| Size | the whole token is at most 4096 bytes; it is parsed only after that bound holds |

The manager resolves the agent key by reading `etc/client.keys` directly (the same id/name/ip/key
format `OS_ReadKeys()` uses); the key column must be exactly **64 lowercase hex characters**
(32 bytes) — the form `authd` generates. A shorter or upper-case key cannot authenticate and the
agent must re-enroll. A removed/disabled agent (`#`/`!`-marked, or simply absent) is treated as unknown.

Verification is fail-closed and happens in a fixed order: size and compact grammar → exact header →
key lookup by `kid` (and the [registered address](#registered-address-ip-column) check) → signature →
exact claim set and types → identity (`sub` and `iss` must name the `kid` agent) → time rules →
`jti` shape. A duplicate JSON member, a non-canonical base64url spelling, a padded segment, a
string where an integer is expected or any extra member anywhere is an invalid token. The JSON text of
both segments is **ASCII** — every value the profile carries is — so any non-ASCII byte (a UTF-8
sequence, a BOM) is an invalid token as well; the parser is bounded by the segment's length and never
inspects encoding beyond that rule.

**What the token does and does not bind.** It authenticates the agent's identity and freshness. It
does **not** cover the HTTP method, the request target or the body — TLS is what protects those
in transit, which is why remoted has no plaintext listener. Two practical consequences:

- A proxy that rewrites the path no longer breaks authentication: the request simply reaches a
  route that does not exist and is answered `404`. Preserving the target and the body end-to-end
  remains the operational recommendation — see [Load balancers](load-balancers/README.md).
- A captured token can be replayed against any route for as long as it is valid (up to
  `jwt_max_age + jwt_clock_skew`, 90 s by default). This is accepted: the transport is TLS, the
  window is short, and `jti` lets a future replay cache be added without changing the wire format.

The same shared implementation (`src/shared_modules/utils/jwt/`) signs on the agent and verifies on
the manager; the Go benchmark simulator and the Python tools reproduce it with their standard
libraries only, and all of them are pinned to the same frozen test vectors
(`tools/manager_benchmark/tool_simulator/internal/wire/testdata/jwt_vectors.json`).

### Registered address (`ip` column)

The same lookup also enforces the entry's `ip` column, matching what the classic listener does through
`OS_IsAllowedDynamicID()`: an agent registered with a fixed address or a range authenticates **only**
from it, while `any` — what `authd` writes when no address was requested — accepts every peer.

The address is checked after the key is resolved and **before** the token's signature is verified, so a peer
that cannot use that identity never costs an HMAC computation. On a mismatch the request is rejected
with the same generic `401` as any other credential failure.

Accepted forms in the column:

| Column | Matches |
|---|---|
| `any` | every peer, both families |
| `10.0.0.5` | that address only (an implicit `/32`) |
| `10.0.0.0/24` | the range |
| `10.0.0.0/255.255.255.0` | the same range, mask written in full |
| `2001:db8::/64` | the IPv6 range (dotted masks are IPv4-only) |
| `::ffff:10.0.0.5` | equivalent to `10.0.0.5`; the mapped form is unmapped before comparing |

Notes:

- Host bits are masked off, so `10.0.0.7/24` describes the `10.0.0.0/24` range rather than matching
  nothing.
- A dotted mask is applied exactly as written, with no contiguity check.
- **A leading `!` is not a negation.** `!10.0.0.5` is read as plain `10.0.0.5`, so the agent is allowed
  *from* that address rather than excluded from it. There is no way to express an exclusion in this
  column.

  This is the classic listener's behavior, kept identical on purpose: `OS_IsValidIP()` strips the `!`
  before storing the address, so `OS_IPFound()`'s negation branch can never fire, and `!IP` has always
  meant positive `IP`. A `client.keys` carried over from 4.x therefore authorizes exactly the same
  agents here — a line that worked before an upgrade does not start being rejected after it.

  `authd` never writes such a value anyway: enrolling with `IP:'!10.0.0.5'` stores `10.0.0.5`, so the
  form only survives in a hand-edited file.
- An agent of one address family never matches an entry of the other.
- An IPv6 zone id is ignored on both sides: a peer reported as `fe80::1%eth0` matches an entry written
  as `fe80::1`, and vice versa. The zone names a local interface, not the address being compared.
- A line whose `ip` column is not a valid address or range is **skipped**, with a warning naming the
  line number, and that agent is then treated as unknown. The rest of the file still loads.
- The peer address is **not** part of the token. A NAT rewrite between agent and manager therefore
  does not invalidate it; the address gates authorization on top of authentication, it is not part
  of it.

> An agent reaching the manager through a **NAT or a load balancer** must be registered with `any` (or
> with the proxy's address): the address the manager observes is the proxy's, not the agent's. This is
> also true of the classic listener; it only becomes visible here because a mismatched fixed address is
> now actually rejected.

### Content-Encoding (zstd)

The request body MAY optionally be compressed with `Content-Encoding: zstd` (case-insensitive). No
other value is accepted — **`gzip` is not supported.** Support can be turned off entirely with
`remoted.http_content_encoding_enabled` (default: enabled) — see [Configuration](#configuration).

**Why zstd and not gzip.** Both were measured on a real 48 MB FIM sync payload before choosing. At
its default level zstd beats gzip's default on all three axes at once, so there is no trade-off to
weigh — and decompression speed is the side that matters here, since agents compress while the
manager decompresses:

| Codec                  | Compressed  | Compress  | Decompress  |
| ---------------------- | ----------- | --------- | ----------- |
| `gzip-6` (default)     | 4.25 MB     | 224 ms    | 44.2 ms     |
| `gzip-9` (max)         | 4.10 MB     | 429 ms    | 43.1 ms     |
| **`zstd-3` (default)** | **3.66 MB** | **55 ms** | **24.0 ms** |
| `zstd-9`               | 3.44 MB     | 157 ms    | 24.3 ms     |

Supporting both was considered and dropped: it would mean two decoders, two dependency chains and
two test matrices for a codec that is dominated on this workload.

- Decompression happens **after** authentication succeeds, never before: the bearer token is verified
  from the headers alone (the body is not part of it — TLS protects it), so an unauthenticated
  request never costs CPU/memory decompressing anything.
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
collapse to a **single generic `401`** so a client cannot tell which specific check failed; every such
`401` carries `WWW-Authenticate: Bearer` ([RFC 6750 §3](https://www.rfc-editor.org/rfc/rfc6750#section-3))
— it names the scheme, never the reason.

| Condition                                                                                                                                                                               | HTTP  | `error` message                             |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | ------------------------------------------- |
| Missing `protocol-version` header                                                                                                                                                       | `400` | `Missing required header: protocol-version` |
| Unsupported `protocol-version`                                                                                                                                                          | `400` | `Unsupported protocol-version`              |
| Missing / malformed `Authorization`, unknown agent, unusable key, peer address not allowed by the agent's `ip` column, invalid token (grammar, header or claims), bad signature, stale token (expired, older than the accepted age, or issued in the future), identity mismatch | `401` | `Invalid client authentication`             |
| Body exceeds the auth body limit (10 MiB) -- or, for `Content-Encoding: zstd`, the decoder's buffers or the decompressed output don't fit in the in-flight capacity free at that moment | `413` | `Request payload is too large`              |
| `Content-Encoding` present but not (case-insensitively) `zstd`                                                                                                                          | `415` | `Unsupported Content-Encoding`              |
| `Content-Encoding: zstd`, but the body isn't a valid/complete zstd frame                                                                                                                | `400` | `Malformed compressed body`                 |
| Payload's `wazuh.agent.id` (H line) missing/malformed/non-numeric, or doesn't match the authenticated `agent-id`                                                                        | `400` | `Invalid event batch`                       |
| Downstream rejected the batch (bad H/E)                                                                                                                                                 | `400` | `Invalid event batch`                       |
| Out of capacity, or downstream unreachable/errored                                                                                                                                      | `503` | `Service unavailable`                       |
| Endpoint handler raised an unexpected error                                                                                                                                             | `500` | `Internal server error`                     |

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

The one `503` that *does* carry a `Retry-After` is relayed, not generated: on `/stateful`, a
digits-only `Retry-After` from the inventory sync server is passed through, since there the
downstream answer **is** the session result.

**Statuses remoted never sends.** `429 Too Many Requests` is not part of this contract — capacity is
shed with `503`, as above. Neither is `426 Upgrade Required`. The agent's client classifies both as
retryable anyway, so an agent that logs one has been answered by something between it and the
manager (a load balancer, a proxy, a WAF) rather than by remoted. Treat either as a sign to look at
the intermediary — see [Load balancers](load-balancers/README.md).

## Endpoints

The listener exposes **nine** agent-facing routes. Every one of them except `GET /` and
`POST /enroll` is authenticated with the bearer token above.

Every path on this page is the endpoint's **logical** path. When
[`remote.https.global_prefix`](configuration.md#httpsglobal_prefix) is configured (freshly
generated configurations ship `/wazuh-manager/`), the server exposes each endpoint under that
prefix — `POST /stateless` becomes `POST /wazuh-manager/stateless`, the health probe becomes
`GET /wazuh-manager/` (with or without the trailing slash) — and the unprefixed paths answer
`404`. The prefixed path is what travels on the wire and what the router matches: agents send the
full prefixed target. The token does not bind it, so a prefix mismatch is a `404`, never a `401`.

The module's own statistics are **not** served here: they live on a separate manager-local Unix
socket (`GET /`, `GET /metrics` on `queue/sockets/remote-admin-http.sock`), so they are never reachable
from an agent — see [the admin socket](README.md#local-admin-socket) and [Metrics](metrics.md).

- **`GET /`** — unauthenticated health probe. Returns `200` with
  `{"status":"ok","module":"remoted"}`.
- **`POST /stateless`** — authenticated event ingestion. Once the signature is verified, the module
  cross-checks the H line's `wazuh.agent.id` against the authenticated `agent-id` (**`400`** on a
  missing/malformed header or a mismatch); only then does it forward the H/E batch to the engine's
  event ingress over a Unix-domain socket (`POST /events/enriched`) and reply from the downstream
  result: **`202 Accepted`** (engine enqueued the batch), **`400`** (engine rejected the batch),
  **`413`**, or **`503`** (out of capacity or the engine is unreachable/errored). Auth failures
  return the errors above. Note the agent sends **no `Content-Type`** on this route — nothing on
  the manager side reads one, and the `application/x-ndjson` label exists only on the downstream hop
  to the engine. Do not configure an intermediary to require or rewrite it.
- **`POST /control`** — authenticated agent lifecycle and control messages. Once the signature is
  verified, the module processes the agent's control message (`startup`, `notify`, or `shutdown`),
  updates agent metadata in wazuh-db, retrieves pending tasks from task-manager, and returns
  configuration state and pending work. Handles agent initial connection state (`startup` with
  limits, cluster info, and groups), periodic keepalive every 10 seconds (`notify` with hash-based
  change detection for config and settings), and clean disconnection (`shutdown`). Returns **`200
  OK`** with a JSON response on success, **`400`** on malformed requests, **`401`** on auth
  failures, **`409`** when the agent's version is higher than this manager allows, or **`503`** when
  wazuh-db/task-manager are unreachable. See
  [Control endpoint](#control-endpoint-post-control) below for details.
- **`POST /stateful`** — authenticated inventory synchronization. Once the signature is verified,
  the module relays the body opaquely (stamping the authenticated identity as `X-Wazuh-Agent-Id`)
  to the [Inventory Sync Server](../inventory-sync-server/README.md) over its Unix-domain socket
  (`queue/sockets/inventory-sync-http.sock`) and returns the downstream answer verbatim — the response
  IS the session result (see the server's
  [response contract](../inventory-sync-server/api-reference.md)). The wait for the downstream
  answer is bounded by `remoted.downstream_stateful_response_timeout`
  (see [configuration](configuration.md)). Bodies may be zstd-compressed
  (`Content-Encoding: zstd`); remoted decompresses before relaying.
- **`POST /download`** — authenticated retrieval of a centralized configuration (`merged.mg`) or a
  WPK upgrade package. The only route that answers with a **streamed** body: HTTP chunked transfer
  encoding, so memory does not grow with file size. Returns **`200 OK`** with
  `Content-Type: application/octet-stream`, **`400`** on a malformed request or a rejected
  identifier, **`404`** when the resource does not exist, or **`500`**. See
  [Download endpoint](#download-endpoint-post-download) below for details.
- **`POST /stats`** — authenticated ingestion of the statistics document an agent reports for all of
  its modules. Relayed to the [Inventory Sync Server](../inventory-sync-server/README.md) over
  `queue/sockets/inventory-sync-http.sock`, stamping the authenticated identity as `X-Wazuh-Agent-Id`.
  Returns **`200 OK`** with a fixed `{}`, **`400`** on an empty or rejected document, **`413`**, or
  **`503`**. See [Reporting endpoints](#reporting-endpoints-post-stats-and-post-config) below.
- **`POST /config`** — authenticated ingestion of the configuration document an agent reports.
  Same pipeline as `/stats`; differs in that a successful answer carries the enriched document back.
  See [Reporting endpoints](#reporting-endpoints-post-stats-and-post-config) below.
- **`POST /scan/vd`** — authenticated on-demand Vulnerability Detection re-scan request, sent by an
  agent once it notices (via `notify`'s `vd_feed_offset`) that this node's feed has moved past what
  it last synced against. Returns **`200 OK`** when the request's `feed_offset` matches this node's
  current offset **and** the VD module queued the scan — the `200` is a promise that the scan will
  run; **`409 Conflict`** (carrying the real offset to retry with) on a mismatch, **`400`** on
  malformed requests, **`401`** on auth failures, or **`503`** when VD did not queue it (dispatch
  lane full, feed mid-update, module stopping or unreachable, no indexer host available). See
  [Scan endpoint](#scan-endpoint-post-scanvd) below for details.
- **`POST /enroll`** — bridges a new agent's self-enrollment request to `authd` (see
  [Authd](../authd/README.md)), which owns all enrollment business logic. Unlike every other
  authenticated endpoint above, it does **not** use the agent<->manager bearer token — the agent
  has no key yet — and it is **always registered**, answering **`403`** rather than a bare `404`
  when enrollment is administratively disabled. Returns **`200 OK`** with the new agent's
  `{id,name,ip,key}` on success, or a mapped `4xx`/`5xx` on failure. See
  [Enrollment endpoint](#enrollment-endpoint-post-enroll) below for details.

The machine-readable contract is published as OpenAPI, covering all nine routes — see the
[endpoint reference](agent-api-reference.html) (source: [`agent-api.yaml`](agent-api.yaml)).

## Configuration

Advanced RESTinio tuning knobs (threading, timeouts, message limits) resolve as **caller value →
built-in default**. `remoted` populates the caller value by reading the `remoted.http_*` internal
options (`etc/wazuh-manager-internal-options.conf`) in `secure.c` and passing the result to
`remoted_module` through its C-ABI struct; an option present in the file but out of range (or
non-numeric) prevents `remoted` from starting, same as every other internal option. See
[Internal Options](configuration.md#internal-options) for the full reference (allowed ranges,
notes).

| Setting                               | Default               | Internal option                         |
| ------------------------------------- | --------------------- | --------------------------------------- |
| I/O threads                           | `cpp_get_nproc()`     | `remoted.http_io_threads`               |
| Handler worker threads                | `2 * cpp_get_nproc()` | `remoted.http_worker_threads`           |
| Read / handshake timeout              | `10 s`                | `remoted.http_read_timeout`             |
| Write timeout                         | `10 s`                | `remoted.http_write_timeout`            |
| Request timeout                       | `30 s`                | `remoted.http_request_timeout`          |
| Max URL size                          | `2048 B`              | `remoted.http_max_url_size`             |
| Max header name size                  | `256 B`               | `remoted.http_max_header_name_size`     |
| Max header value size                 | `8192 B`              | `remoted.http_max_header_value_size`    |
| Max header count                      | `64`                  | `remoted.http_max_header_count`         |
| Max pipelined requests per connection | `4`                   | `remoted.http_max_pipelined_requests`   |
| Concurrent TCP accepts                | `2`                   | `remoted.http_concurrent_accepts`       |
| Socket read buffer size               | `8192 B`              | `remoted.http_buffer_size`              |
| Accept `Content-Encoding: zstd`       | enabled               | `remoted.http_content_encoding_enabled` |

I/O threads and handler worker threads are thread-count settings: a `<=0` value (including "not
set" in `wazuh-manager-internal-options.conf`) resolves via `cpp_get_nproc()`
(`shared_modules/utils/proc.hpp`, cgroup-aware on Linux) instead of a fixed constant, so the pool
sizes track the host/container's available CPUs. The handler worker pool is oversubscribed (`2x`)
because that work can block (token verification, `client.keys` file I/O), unlike the purely
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

| Setting                                                                          | `<https>` tag       | Default                                                                                       |
| -------------------------------------------------------------------------------- | ------------------- | --------------------------------------------------------------------------------------------- |
| Bind address (IPv4 or IPv6, see [above](#bind-address-ipv4-ipv6-and-dual-stack)) | `bind_addr`         | `127.0.0.1`                                                                                   |
| Dual-stack override (IPv6 `bind_addr` only)                                      | `dual_stack`        | `no` (force IPv6-only)                                                                        |
| Port                                                                             | `port`              | `1517`                                                                                        |
| Transport max body size                                                          | `max_body_size`     | `20 MiB`                                                                                      |
| TLS certificate chain                                                            | `certificate`       | `etc/certs/remoted.pem`                                                                       |
| TLS private key                                                                  | `key`               | `etc/certs/remoted-key.pem`                                                                   |
| Client CA bundle                                                                 | `ca`                | `etc/certs/root-ca.pem`                                                                       |
| Client verification mode                                                         | `verification_mode` | `none` (auto-upgraded to `certificate` if `<ca>` is set in XML without `<verification_mode>`) |
| TLS 1.3 ciphersuites                                                             | `ciphers`           | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`                  |

> There is no `enabled` toggle: the listener always attempts to start and self-gates on the
> presence of a valid certificate/key, same as before this configuration surface existed.

The **memory-management / capacity** settings are a separate, third group: `remoted` sets them
directly on the C-ABI struct in `secure.c` (→ built-in default when unset) and they are
deliberately **not** internal options -- they bound in-memory resource usage rather than tune the
transport, so they don't go through `remoted_module_https_config()`/the internal-options table
above.

| Setting                                             | Default   | Source                                    |
| --------------------------------------------------- | --------- | ----------------------------------------- |
| Max in-flight payload bytes (→ `503`)               | `256 MiB` | remoted config `max_inflight_bytes`       |
| Max simultaneous connections                        | `512`     | remoted config `max_parallel_connections` |
| Max deferred requests awaiting downstream (→ `503`) | `256`     | remoted config `max_deferred_requests`    |

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

| Setting                            | Default           | Internal option                             |
| ---------------------------------- | ----------------- | ------------------------------------------- |
| Downstream connect timeout         | `2 s`             | `remoted.downstream_connect_timeout`        |
| Downstream write timeout           | `5 s`             | `remoted.downstream_write_timeout`          |
| Downstream response timeout        | `5 s`             | `remoted.downstream_response_timeout`       |
| Downstream client I/O threads      | `cpp_get_nproc()` | `remoted.downstream_io_threads`             |
| Downstream post-processing threads | `cpp_get_nproc()` | `remoted.downstream_post_process_threads`   |
| Max downstream response body       | `10 MiB`          | `remoted.downstream_max_response_body_size` |
| JWT max accepted token age         | `60 s`            | `remoted.jwt_max_age`                       |
| JWT clock skew                     | `30 s`            | `remoted.jwt_clock_skew`                    |
| Auth max body size                 | `10 MiB`          | `remoted.auth_max_body_size`                |

The two thread-count fields above resolve a `<=0` value via `cpp_get_nproc()` the same way
`http_io_threads`/`http_worker_threads` do (no `2x` oversubscription here -- both pools are either
a purely async I/O reactor or documented as non-blocking work). The downstream client's events
socket path (`eventsSocketPath`) and the auth middleware's `supportedProtocolVersion` are not
internal options -- the former is an installation detail (mirrors the classic C forwarder's
socket), the latter a protocol constant.

### Enrollment bridge (`POST /enroll`)

A fifth, small group of internal options tunes the `/enroll`-to-`authd` bridge
(`AuthdClient`/`PasswordKeySource`, see [Enrollment endpoint](#enrollment-endpoint-post-enroll)
below). Same resolution pattern: `secure.c` reads each option and passes it through the C-ABI
struct.

| Setting                                     | Default                                                | Internal option                          |
| -------------------------------------------- | ------------------------------------------------------ | ----------------------------------------- |
| `etc/authd.pass` hot-reload poll interval     | `10 s`                                                  | `remoted.enroll_password_refresh_interval` |
| `authd` local-socket connect timeout          | `2 s`                                                   | `remoted.authd_connect_timeout`            |
| `authd` local-socket response timeout         | `5 s` on a master, `15 s` on a cluster worker           | `remoted.authd_response_timeout`           |
| Bridge request queue high-water mark          | `256`                                                   | `remoted.authd_max_queue_size`             |
| Concurrent bridge worker threads              | `8`                                                      | `remoted.authd_worker_threads`             |

The response timeout's worker default is longer than the master's on purpose: on a worker, `authd`'s
own forward to the master can retry internally for several seconds before answering, and a shorter
client-side timeout here would cut off a legitimate, still-in-progress worker enrollment as a
spurious `503`. All other enrollment behavior (whether it's enabled, whether a password/client
certificate is required, which agent versions are accepted) is deliberately **not** a separate
`remoted`-owned setting — it's read from `authd`'s own `<auth>` block so the two enrollment paths
can never disagree; see [Enrollment endpoint](#enrollment-endpoint-post-enroll) below.

**Why more than one worker.** `authd`'s local-socket accept loop hands each accepted connection to
its own detached thread (`os_auth/src/local-server.c`'s `handle_local_client`), so several `add`
requests -- including a worker's cluster-forwarded ones, which can legitimately take several
seconds -- now genuinely run concurrently on `authd`'s side too, not just queue one-at-a-time behind
a single dispatcher. A single-worker `remoted` would still only ever have ONE such request in
flight at a time no matter how parallel `authd` itself can go, and would still pay the
connection-setup round trip (connect + send + await reply + close) sitting on the critical path *in
addition to* `authd`'s processing time, for every single request. With several workers, `authd` can
actually work on more than one at once, and another connection is normally already waiting in its
listen backlog (128 slots) by the time it finishes one and calls `accept()` again. Keep this well
under 128 — there's no benefit to more workers than that backlog can hold.

### client.keys hot-reload

`Keystore` (the agent key lookup behind the bearer auth layer) watches `client.keys` in the
background and reloads it on change, so an agent enrolled or removed after `remoted` starts is
picked up without a restart. An `inotify` subscription reacts immediately; the poll cadence used as
a fallback (in case a notification is ever missed) is `remoted.keyupdate_interval` -- the same
option the classic pipeline's own key-reload thread (`rem_keyupdate_main`) already uses, see
[Internal Options](configuration.md#internal-options) -- not a separate internal option.
Change detection hashes the file's content (not mtime, which is only second-granularity) and
`reload()` re-checks the hash before and after parsing, discarding and retrying a parse caught
mid-write rather than adopting a torn read.

## Diagnosing rejections and capacity problems

Every condition where a setting may need changing is logged to `wazuh-manager.log` and names the setting.
Because these are per-request conditions, repeated occurrences are collapsed to **one line per 90
seconds per condition**, with the suppressed count folded into the message, so a burst or an outage
produces a readable summary instead of thousands of identical lines:

```
wazuh-manager-remoted:forwarder: WARNING: Deferred-work slots exhausted (capacity 256): shed 4812
request(s) with 503 in the last 90 s. Consider increasing the value of 'max_deferred_requests', or
investigate why the downstream service is not keeping up.
```

Each of these conditions also has its own counter on the module's
[`GET /metrics`](metrics.md) dump, so the totals (and their rate between polls) quantify what
the throttled log line can only sample:

| Symptom in `wazuh-manager.log` | Setting to review | Metric evidence ([Metrics](metrics.md)) |
|---|---|---|
| In-flight request memory budget exhausted | `remoted.max_inflight_bytes` | `remoted.server.budget.rejected.total` (+ `budget.inflight.bytes` vs the cap) |
| Deferred-work slots exhausted | `remoted.max_deferred_requests` | `remoted.forwarder.deferred.rejected.total` (+ `deferred.inflight` vs `deferred.capacity`) |
| Timed out connecting to / sending to / waiting for the downstream service | `remoted.downstream_connect_timeout`, `_write_timeout`, `_response_timeout` | `remoted.forwarder.error.connect_timeout` / `.write_timeout` / `.response_timeout` |
| Downstream response exceeded the configured cap | `remoted.downstream_max_response_body_size` | `remoted.forwarder.error.response_too_large` |
| Tokens outside the accepted time window (agent clock drift) | `remoted.jwt_max_age`, `remoted.jwt_clock_skew` | `remoted.auth.reject.clock_skew` |
| Body exceeded the authenticated-body cap (413) | `remoted.auth_max_body_size` (uncompressed body), or `remoted.max_inflight_bytes` (`Content-Encoding: zstd`) | `remoted.auth.reject.body_too_large` |
| Downstream timeouts add up past `http_request_timeout` | `remoted.http_request_timeout` | `remoted.http.<endpoint>.latency` percentiles vs the cap |

Two more, about a registered address that no longer matches, both collapsed on the same 90-second
window as everything above:

- **`Rejected N request(s) … from an address the agent is not registered with`** (INFO) names the agent
  id and the address it connected from, and is the line to look for when an agent that used to work
  starts getting `401`s after its address changed. INFO rather than WARNING: the condition is a
  property of the agent's registration, not a fault on the manager side.
- **`client.keys line N: the address '<value>' registered for agent M is not a valid address or
  range`** (WARNING) means that line was skipped, so that agent is now treated as unknown. Fix the
  column or re-enroll the agent.

Three more that are not about tuning:

- **`Loaded N agent key(s) from '<path>'`** at startup and after every hot-reload. `N` counts keys
  that can actually authenticate — a key that fails to decode is reported separately and is **not**
  counted, so this number can be trusted. If `client.keys` is unreadable, that is logged explicitly:
  otherwise it presents only as every agent being rejected as unknown, with nothing explaining why.
- **`Could not derive the enrollment key from 'etc/authd.pass' (HKDF unavailable)`** (ERROR) means the
  OpenSSL KDF provider is broken: every Password-mode enrollment fails closed until it is fixed,
  distinct from an unreadable or invalid password file (a WARNING naming the file).
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
error handling follow the same bearer-token mechanism as `/stateless` (see
[Authentication](#authentication-jwt-bearer) above).

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
    "fim": {"file": 30000, "registry_key": 30000, "registry_value": 30000},
    "syscollector": {
      "hotfixes": 30000, "packages": 30000, "processes": 30000, "ports": 30000,
      "network_iface": 30000, "network_protocol": 30000, "network_address": 30000,
      "hardware": 30000, "os_info": 30000, "users": 30000, "groups": 30000,
      "services": 30000, "browser_extensions": 30000
    },
    "sca": {"checks": 30000}
  },
  "cluster": {
    "name": "wazuh-cluster"
  },
  "agent": {
    "groups": ["default", "web-servers"]
  }
}
```

Every entry under `limits` is the per-module inventory cap the agent must apply, and every one of
them defaults to **30000**. They are not `remoted.*` settings: each is its own internal option under
its module's own namespace — `fim.file_limit`, `fim.registry_key_limit`,
`fim.registry_value_limit`, `syscollector.<name>_limit` for each of the thirteen keys above, and
`sca.checks_limit` — read once at startup from
`wazuh-manager-internal-options.conf` (range `0` to `INT_MAX`). The object is sent verbatim as the
manager built it, so an operator who raises one of those options sees the new value in the next
`startup` response, and a limit renamed or added there appears here with no change to this endpoint.

**Version rejection.** `startup` is the only message whose `version` is validated — `notify`
deliberately skips the check to keep the hot path fast. A rejection also writes
`status_code = invalid_version` to global.db, and answers one of two statuses:

| Cause | HTTP | wazuh-db `version` column |
| --- | --- | --- |
| Version is malformed (not `MAJOR.MINOR.PATCH`) | `400` | `N/A` sentinel — the framework's version parser raises on anything else, which would break the whole agent listing |
| Version is well-formed but higher than the manager's, and `<remote><agents><allow_higher_versions>` is `no` | `409` | stored as reported |

The split matters to the agent: `400` is terminal, while `409` puts it in its `REJECTED` state,
re-trying `startup` on a slow cadence — because a policy rejection can start succeeding with no
change on the agent's side.

#### Notify (keepalive)

Sent every 10 seconds. The agent includes metadata (version) and optionally host information
(hostname, architecture, IP, OS details). The manager calculates two hashes, queries task-manager for
pending tasks, and returns the hashes along with any tasks.

The two hashes cover different things, and the difference matters to an agent implementer:

- **`settings_hash`** — SHA-256 over the manager's `limits` object and `cluster.name` **only**. It is
  a property of the manager, not of the agent: it does **not** include the agent's groups, and it is
  computed once and cached for the process's lifetime, so it is byte-identical in every agent's
  response. A change means the manager was reconfigured and restarted, which is why the agent's
  response to a mismatch is a fresh `startup` (to pick up the new limits and cluster name).
- **`config_hash`** — SHA-256 of the `merged.mg` this agent's group selector resolves to, so it *is*
  per-agent, and it moves whenever that file changes.

A group change therefore does **not** move `settings_hash`. Groups are delivered directly, in
`agent.groups` of this same response, and a group change surfaces to the agent as a `config_hash`
mismatch, since it resolves to a different `merged.mg`.

Alongside the hash, the response carries the identifier the agent must use to actually fetch that
file:

- **`config_token`** — the `resource_id` to send to [`/download`](#download-endpoint-post-download)
  for `resource_type: "config"`. It is **opaque to the agent**: the agent passes it through
  verbatim and must never parse, reorder, split or substitute anything into it. The manager
  guarantees it resolves to the very same `merged.mg` that `config_hash` was computed over, so the
  two can never disagree. Currently its value *is* the agent's group selector — the same
  comma-joined CSV documented under `/download` below — but that is an implementation detail of
  this manager version, not part of the contract: the whole point of the field is that a later
  manager can change what it addresses, and how, without any agent change.

An agent must therefore **not** rebuild the selector from `agent.groups` itself. `agent.groups` is
the agent's group *identity* (it is what tags the events the agent emits); `config_token` is what
names its configuration.

The manager throttles wazuh-db writes per agent (`remoted.control_keepalive_throttle`, default 60s —
see [Configuration](configuration.md#remotedcontrol_keepalive_throttle)): when the window has expired,
it writes a full update (`updateAgentData`) if host metadata is present in the request, or a
lightweight keepalive (`updateKeepalive`) otherwise.

If tasks are found, the manager marks them as delivered (updates status to `delivered` and records
delivery time). Task delivery status is **local only** (not broadcast to the cluster).

The agent compares the received hashes against its local copies: if `settings_hash` differs, it
sends a new `startup` request; if `config_hash` differs, it downloads the new `merged.mg` file via
`/download`, using the response's `agent.config_token` as the request's `resource_id`.

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
    "config_token": "web-servers",
    "config_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "settings_hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
  "tasks": [],
  "vd_feed_offset": 12345678
}
```

Every field above is **always present**, `tasks` included — it is an empty array when the manager has
no work to hand over, never an absent key. `config_hash` is likewise always a string: when the agent's
selector resolves to no `merged.mg`, or the file cannot be hashed, the manager sends the literal `"0"`
rather than omitting the field or sending an empty string. `config_token` is always a **non-empty**
string, including in that unresolved case — the agent still needs something to name on `/download`,
and the next notify re-triggers the attempt.

**Response with tasks (`200 OK`):**
```json
{
  "agent": {
    "groups": ["web-servers"],
    "config_token": "web-servers",
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

- **wazuh-db** (`queue/sockets/wdb.sock`): Agent metadata storage. The handler writes agent info (OS, version,
  hostname, etc.) via `agent <id> set <field> <value>` commands, updates connection status, and
  reads back the agent's groups. Dedicated worker threads with bounded request queues and async I/O
  prevent blocking the HTTP worker threads.
- **task-manager** (`queue/sockets/task.sock`): Task delivery. The handler queries pending tasks for the
  agent via JSON API (`{"action":"get_pending_tasks","agent_id":"001"}`). Returned tasks are
  included in the response. Task state is local to the node; cluster broadcast is handled separately
  by the task-manager service.
- **vulnerability_scanner module** (`queue/sockets/vd-http.sock`, `GET /vulnerability-detector/offset`):
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

| Condition                                  | HTTP  | `error` message        |
| ------------------------------------------ | ----- | ---------------------- |
| Body empty or exceeds 64 KiB               | `400` | `invalid_body`         |
| Malformed JSON body                        | `400` | `invalid_json`         |
| Invalid agent ID format                    | `400` | `invalid_agent_id`     |
| Unknown message type                       | `400` | `unknown_message_type` |
| Malformed agent version (startup only)     | `400` | `invalid_version`      |
| Agent version higher than allowed (startup only) | `409` | `invalid_version` |
| Invalid host info format (notify only)     | `400` | `invalid_host_info`    |
| wazuh-db error during startup (get groups) | `500` | `database_error`       |

The two version rejections deliberately carry different statuses even though they share an `error`
message. A **malformed** version is a bad request: resending the same bytes can never succeed, so the
agent treats it as terminal. A version that is merely **higher than this manager allows** is a
`409 Conflict` — it can start succeeding without the agent changing anything (an operator sets
`<remote><agents><allow_higher_versions>` to `yes`, or the manager is upgraded), so the agent enters
its `REJECTED` state and re-tries `startup` on a slow cadence instead of giving up.

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

The scan is queued in the VD module's bounded dispatch lane and **will run** (see
[Scan dispatch](#scan-dispatch) below) — the `200` is relayed from VD's own admission answer,
never invented on this side. The agent should consider the offset it sent as handled — it clears
any persisted retry state for that offset.

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

| Condition                                        | HTTP  | `error` message                                               |
| ------------------------------------------------ | ----- | ------------------------------------------------------------- |
| Body empty or exceeds 4 KiB                      | `400` | `invalid_body`                                                |
| Malformed JSON body                              | `400` | `invalid_json`                                                |
| Invalid agent ID format                          | `400` | `invalid_agent_id`                                            |
| Missing or non-string `type`                     | `400` | `missing_type`                                                |
| `type` other than `"feed_update"`                | `400` | `invalid_type`                                                |
| Missing or non-unsigned `feed_offset`            | `400` | `missing_feed_offset`                                         |
| `feed_offset` != current offset                  | `409` | `version_mismatch` (carries `current_version`)                |
| VD's scan dispatch lane at capacity              | `503` | `scan_queue_full`                                             |
| Indexer not usable (no healthy host)             | `503` | `indexer_unavailable`                                         |
| VD not ready (feed mid-update, scanner starting) | `503` | `feed_not_ready` / `scanner_not_ready` / `vd_not_initialized` |
| VD stopping or unreachable, or the relay failed  | `503` | `shutting_down` / `vd_unreachable` / `vd_error`               |

Every `503` means the same thing to the agent — not accepted, retry on the next notify cycle —
and its pending state survives; the `error` code exists so an operator reading the exchange sees
the actual cause. During a long indexer outage the agent keeps re-requesting on each notify and
the scan runs once the indexer becomes available again. Auth failures (`401`) reuse the same
responses as `/stateless`. This endpoint's body cap (4 KiB) is far tighter than `/control`'s
(64 KiB) since a scan request only ever carries `type` and `feed_offset`.

### Scan dispatch

remoted holds no scan state: after the offset gate it makes one inline
`POST /vulnerability-detector/scan` to the `vulnerability_scanner` module (over the same UDS
socket `VdClient` uses), which answers at **admission** into its bounded dispatch lane — a
64-slot queue drained by a single worker (scans are serialized by the scanner's own global lock
regardless). VD's admission preflight also checks the indexer's health
(`IndexerConnectorSync::isAvailable()`, a per-host `GET /_cat/health` poll every 60 s; healthy
means at least one host green or yellow) — with no healthy host it answers `503
indexer_unavailable` instead of queueing. VD deduplicates repeated requests for an agent already
waiting in the lane, and a queued scan cannot go stale: the request carries no offset, so the scan
always runs against the feed that is current at execution time. remoted relays VD's answer
verbatim and never retries — the agent's notify cycle is the retry loop, with no second one hidden
behind it.

An indexer outage does not drain what VD already queued: the dispatch worker HOLDS the front of
the lane (nothing popped, nothing dropped) and re-checks availability every 30 s, resuming as soon
as a host answers healthy again; new requests keep getting `indexer_unavailable` at admission
meanwhile, so held work stays bounded by the lane's 64 slots. Only a manager shutdown sheds a held
queue.

Duplicate scans across different nodes (the agent asks node A, doesn't get a timely reply, and asks
node B too) are accepted as a rare, low-impact trade-off rather than solved with cross-node
coordination.

Disconnected agents (never reachable, so they can never notice `vd_feed_offset` or call this
endpoint themselves) are not covered by `/scan/vd` at all — they're swept separately, once per feed
update, by the cluster's master node only (`VulnerabilityScannerFacade::rescanDisconnectedAgents()`
in the `vulnerability_scanner` module).

## Enrollment endpoint (`POST /enroll`)

`/enroll` lets a new agent register over the same HTTPS channel (port 1517) it uses for everything
else afterward, instead of falling back to legacy `authd` on port 1515. It is a **bridge, not a
second implementation**: `authd` keeps 100% of enrollment business logic (name/version/group
validation, key generation, duplicate handling, cluster forwarding on a worker); this endpoint only
authenticates the request and relays it to `authd`'s existing local socket
(`queue/sockets/auth.sock`) — the same interface `manage_agents` and the API's agent-registration
endpoints already use. See [Authd](../authd/README.md) for what happens once a request reaches
that socket, and [`legacy_enrollment`](../authd/configuration.md#legacy_enrollment) for how an
operator can retire port 1515 while keeping `/enroll` (or disable both together via
`remote_enrollment`).

**The route is always registered**, regardless of configuration. When enrollment is
administratively disabled (`<auth><disabled>yes</disabled>`, or `<auth><remote_enrollment>no</auth>`),
it answers **`403`** rather than disappearing — a missing route (`404`) would mean "this manager
doesn't support enrollment at all," which is a different, more permanent statement than "an operator
turned this off."

### Authentication

Unlike every other endpoint on this page, `/enroll` cannot use the agent<->manager bearer (see
[Authentication](#authentication-jwt-bearer) above) — an enrolling agent has no `client.keys`
entry yet to sign with. Two credential checks apply instead, decided once at manager startup and
**independently** of each other (an operator can require either, both, or neither — see below):

- **Client certificate** — purely a property of the HTTPS listener's own `verification_mode`
  (`certificate` or `full`; see [Configuration](configuration.md#https-configuration)). When
  configured, the TLS handshake validates the agent's certificate against the manager's CA
  **before the request ever reaches this endpoint** — there is nothing further for `/enroll` itself
  to check.
- **Password** — required whenever `authd`'s [`use_password`](../authd/configuration.md#use_password)
  is enabled. The request must carry a bearer of the sibling closed profile **`wazuh-enroll+jwt`**:

  ```text
  protocol-version: 1
  Authorization: Bearer <JWS compact serialization>
  ```

  Same core as the agent token — HS256, compact base64url without padding, 4096-byte cap, the same
  time rules under the SAME two internal options `remoted.jwt_max_age` / `remoted.jwt_clock_skew`
  — with a different domain:

  | Part | Value |
  | --- | --- |
  | JOSE header | exactly `{"alg":"HS256","typ":"wazuh-enroll+jwt"}` — **no `kid`**: there is one shared key |
  | Claims | exactly four: `exp`, `iat`, `jti`, `nbf` (= `iat`) — **no `iss`/`sub`**: there is no agent identity to assert yet |
  | Key | `HKDF-SHA256(IKM = password, salt = 32 × 0x00, info = "WAZUH-ENROLL-JWT-KEY" ‖ 0x01, L = 32)` derived from `authd`'s enrollment password (`etc/authd.pass`) — never the password bytes themselves. The `info` label separates this key from the retired AES-CMAC key of the same password |

  A token of either profile presented to the other's verifier is rejected on its header set before
  the signature is even considered. The request body is capped by the same
  `remoted.auth_max_body_size` (10 MiB default) the agent scheme enforces — checked before anything
  else, in **every** mode including Open, so an oversized body is rejected with `413` before the
  credential is looked at. The body is not part of the token (TLS protects it).

  A missing/unreadable/invalid password file fails **closed** — every request is rejected, never
  silently treated as if no password were required. The password is re-derived on change
  (`etc/authd.pass` is hot-reloaded), so rotating it invalidates every token minted from the old
  one within seconds.

Both checks failing to apply (no client-certificate requirement, no password configured) means the
request needs no credential at all, matching `authd`'s own behavior on port 1515 in that
configuration.

Every auth rejection collapses to the same generic response, so a client cannot tell which check
failed: `401` with `{"error":{"code":0,"message":"Invalid client authentication"}}` and
`WWW-Authenticate: Bearer`.

`/enroll` validates the `protocol-version` header first, exactly as every other authenticated route
does, so a missing or unsupported version is rejected with its own `400` (`Missing required header:
protocol-version` / `Unsupported protocol-version`) before any credential is examined. That check
applies in **every** mode, including the credential-less one: the version is a property of the
protocol, not of the credential.

**Worked example** (frozen known-answer vector, shared by every implementation — `"enroll"` in
`tools/manager_benchmark/tool_simulator/internal/wire/testdata/jwt_vectors.json`):

| Input | Value |
| --- | --- |
| Password | `MyEnrollmentSecret123` |
| HKDF-SHA256 derived key | `eeecc651648436211783381e38d0a661bfecc2888a4e23b28c94f415f98616b6` |
| Header JSON | `{"alg":"HS256","typ":"wazuh-enroll+jwt"}` |
| Claims JSON (`iat` 1700000000, `jti` from bytes `00..0f`) | `{"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}` |
| Resulting header | `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH0.Ll9rqCc4D0emY3xUV99-yD-ep0Xp7CI1qKG8Rzkvm8o` |

The key derives from a human-chosen password: a captured token lets an attacker guess that password
offline — HKDF adds no entropy. The defenses are TLS on the
transport, a strong password and the short token lifetime, not the construction itself. There is no
replay store either: a captured token could be replayed inside its window, bounded in practice by
`authd`'s own duplicate-name/IP rejection (unless force-replace is configured to permit it).

### Request

```json
{
  "name": "web-server-01",
  "version": "5.0.0",
  "groups": "default,web-servers",
  "ip": "10.0.0.15"
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `name` | yes | 2-128 chars, no leading `.`, charset `[A-Za-z0-9._-]` only — `OS_IsValidName()`, the same rule the legacy port-1515 path applies, so both enrollment paths accept exactly the same names. `authd`'s local socket separately enforces a looser *storage-safety* floor (no whitespace/control bytes, no leading `#`/`!`, ≤128 chars) for all of its callers, `manage_agents` and the API included; this endpoint holds the tighter line itself rather than relying on that floor. |
| `version` | yes | Rejected if newer than the manager's unless `<remote><agents><allow_higher_versions>` is `yes` — `authd`'s local socket performs no version check of its own, so this endpoint enforces it. |
| `groups` | no | Comma-separated, passed through unchanged. |
| `ip` | no | Syntactic IPv4/IPv6/CIDR check, or one of two sentinels: `any` (no override), or `src` — mirrors legacy port 1515's own wire sentinel (an agent configured with its own client-side `use_source_ip` sends this instead of a literal address); see IP resolution below. |
| `key_hash` | no | Opaque hash of the agent's current key, if it has one — drives `authd`'s force/key-mismatch decision, same as port 1515's `K:` field. |

`force`, `id`, and a raw `key` are never sent, even though `authd`'s local socket accepts all three
for admin/restore use (`manage_agents`): `/enroll` is exclusively for a brand-new agent
self-enrolling, which always gets an auto-assigned ID and an `authd`-generated key.

**IP resolution** mirrors `authd`'s own [`use_source_ip`](../authd/configuration.md#use_source_ip):
if enabled (manager-side), the HTTPS connection's observed peer address is used, overriding
anything the body claims. Otherwise, a body `ip` of `src` (agent-side sentinel) also resolves to
the observed peer address — never forwarded to `authd` literally, since its local socket has no
notion of that sentinel at all (only port 1515's own wire parser does) and would reject it as an
invalid IP. Otherwise the body's `ip` is used if present; otherwise `any`.

### Responses

**Success (`200 OK`):**

```json
{
  "id": "003",
  "name": "web-server-01",
  "ip": "10.0.0.15",
  "key": "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915"
}
```

Verbatim from `authd` — the 64-hex `key` the agent must store and sign every subsequent
`wazuh-agent+jwt` bearer with, under its new numeric `id`.

### Error handling

| Condition | HTTP | Notes |
| --- | --- | --- |
| Enrollment administratively disabled | `403` | Route always exists; see above. |
| Missing or unsupported `protocol-version` | `400` | Validated FIRST, in every mode -- before the credential check and before the body-size cap, matching every other authenticated route. |
| Missing/invalid credential | `401` | Collapsed to one generic message; see Authentication above. |
| Body exceeds `remoted.auth_max_body_size` (10 MiB default) | `413` | Checked once the protocol version is accepted, BEFORE the bearer is checked (and before a credential check, in Open mode too) -- an oversized body is rejected without ever reaching `parseAndValidateBody()`'s own smaller (16 KiB) schema check. |
| Malformed body, missing `name`/`version`, invalid `ip` | `400` | Rejected before `authd` is ever contacted. |
| Agent version newer than allowed | `400` | See `version` in the request table above. |
| `authd` bad function/args/name/ip/groups (9003–9006, 9014, 9017) | `400` | Passed through with `authd`'s own message. `9017` ("Invalid agent name") is unreachable from this endpoint in practice: `isValidName()` above is strictly tighter than the local socket's storage-safety floor, so any name `authd` would reject with `9017` was already refused locally with a `400`. It is mapped for completeness, not as a path clients should expect. |
| `authd` duplicate ip/name/id (9007/9008/9012) | `409` | |
| `authd` internal/parse/key-generation failure (9001/9002/9009) | `500` | |
| `authd` refused a caller-supplied key (9019) | `400` | unreachable from `/enroll` (self-enrollment never sends a key); mapped for completeness |
| `authd` `max_agents` reached (9013) | `503` | Server-wide capacity condition, not a per-client rate limit. |
| Worker rejected the request (9015), or its forward to the master failed (9016, new in 5.0) | `503` | Only reachable via the local-socket bridge — see [Authd's local socket protocol](../authd/README.md#local-socket-enrollment-protocol). |
| `authd` unreachable, or its reply was unparseable/timed out | `503` | `{"error":{"code":-1,"message":"Enrollment service temporarily unavailable"}}` |

Every error the `/enroll` **endpoint itself** produces — every row in the table above, disabled/
credential/body-size/validation/`authd` business and transport failures alike — has the shape
`{"error":{"code":<code>,"message":"<text>"}}`, distinct from every other endpoint's flat
`{"error":"<message>","code":<status>}` shape, since this one passes through `authd`'s own numeric
codes for diagnostics (`code` is `0` for the non-`authd` rows, which carry no numeric code).

A few conditions never reach the endpoint's own code at all — the shared HTTP transport rejects them
first, in the same flat shape it uses for every route, `/enroll` included: an uncaught exception
(`500`), capacity-based load shedding once the module's in-flight byte budget is exhausted (`503`),
or (mTLS mode) a client certificate that doesn't match the connecting peer's address (`403`). These
are the exception to the "always nested" rule above, not a second business-error shape.

## Download endpoint (`POST /download`)

`/download` serves the two files an agent has to pull from the manager: its **centralized
configuration** (`merged.mg`, fetched when `/control`'s `config_hash` stops matching what the agent
holds, and named by the `config_token` that same response carried) and a **WPK upgrade package**
(fetched when a `remote_upgrade` task is dispatched). It replaces the legacy push, where the manager
wrote both down the agent's persistent TCP connection; with stateless HTTPS there is no connection
to push into, so the agent pulls instead.

It is the only route that answers with a **streamed** body. A WPK can be hundreds of megabytes, so
the response uses HTTP chunked transfer encoding with memory that does not grow with file size:
one chunk is resident at a time and a worker slot is held only for the duration of a single read.

### Request

```json
{
  "resource_type": "config",
  "resource_id": "web-servers"
}
```

Exactly two members, both strings — an unknown extra member is a rejection, not something skipped,
so a field a newer agent adds can never be silently ignored by an older manager. The body is capped
at **4 KiB** before parsing (a real request is about 80 bytes), well below the authenticated-body
limit, so an oversized or deeply nested blob costs nothing proportional to its size.

| `resource_type` | `resource_id` | Resolves to |
| --- | --- | --- |
| `config` | one group name | `etc/shared/<group>/merged.mg` |
| `config` | several group names, comma-separated | `var/multigroups/<sha256(resource_id)[0..8)>/merged.mg` |
| `wpk` | a package filename | `var/upgrade/<filename>` |

The comma-separated form is wazuh's own multigroup selector, and it is what lets an agent in several
groups fetch its **effective** configuration rather than one member group's. It needs no database
lookup: the directory name is the first **8 hex characters** (the first four digest bytes) of the
SHA-256 of the selector verbatim, exactly how wazuh-db names the directory (`WDB_GROUP_HASH_SIZE`).

Accepted identifiers:

- **Group name** — non-empty, at most 255 bytes, not exactly `.` or `..`, and drawn from wazuh's own
  group-name set (`a-z A-Z 0-9 . : ; _ - = + ! @ ( )`; note the absence of `/`). In a multigroup
  selector every entry must be valid on its own, which is what rejects a leading, trailing or
  doubled comma. The whole selector is capped at 4096 bytes.
- **WPK filename** — non-empty, at most 255 bytes, must **not** begin with a dot, must end in
  `.wpk`, and is drawn from a stricter set (`a-z A-Z 0-9 . _ -`).

> **There is no group-membership check.** Any authenticated agent can fetch any group's or
> multigroup's merged configuration (protocol decision on #38022). Authentication proves *an* agent
> is asking; it does not constrain *which* configuration it may ask for.

Containment differs per form, by design. The multigroup selector is **hashed, never joined**, so it
cannot traverse by construction. The single-group and WPK forms *do* join agent input into a path, so
there the grammars are the boundary: with no separator admitted, the joined path has exactly one
component below its base directory, and the open is `O_NOFOLLOW` so that component cannot be a
symlink. Loosening either grammar would break that and require a `realpath()` containment check
instead.

### Responses

**`200 OK`** — `Content-Type: application/octet-stream`, body sent with chunked transfer encoding in
`remoted.http_stream_chunk_size` slices (default 64 KiB, see [Configuration](configuration.md)).

### Error handling

| Condition | HTTP | `error` message |
| --- | --- | --- |
| Body empty, over 4 KiB, not a JSON object, wrong member count, or a non-string member | `400` | `Invalid request format` |
| `resource_type` is neither `config` nor `wpk` | `400` | `Invalid resource type` |
| `resource_id` fails the grammar for its type | `400` | `Invalid resource identifier` |
| Resource absent, not a regular file, or `O_NOFOLLOW` rejected a symlink | `404` | `Resource not found` |
| Unexpected `errno` while opening or stat-ing | `500` | `Internal server error` |

A symlink is deliberately indistinguishable from an absent file to the agent. Auth failures reuse the
same responses as `/stateless`.

### Transfer integrity

Two properties matter more than throughput here, because the agent installs what it receives.

**A failed transfer is a truncation, never a short success.** A read error propagates out and the
response builder is dropped *without* being finished, so the terminating `0\r\n\r\n` chunk is never
sent and the agent sees an incomplete body it will retry. Ending the stream cleanly instead would
emit the terminator and hand over a truncated file that looks complete.

**A file rewritten mid-transfer aborts the transfer.** After **every** chunk — not only at
end-of-stream — the descriptor is re-`fstat`ed and its size and mtime compared against what they were
at `open()`. A mismatch means what has been streamed so far is a mix of two versions: shorter is a
truncating rewrite (`c_group()` regenerating `merged.mg`), longer is a package still being staged,
and same-size-but-newer-mtime is a rewrite no byte count could see. Checking per chunk is what bounds
the waste — a writer landing one second into a 1 GiB transfer would otherwise cost the whole
gigabyte before the transfer was abandoned.

This *detects* the modification, it does not prevent it: a rewrite with an identical length inside
the same mtime granularity still slips through. Closing that needs writers to publish atomically by
rename, not a tighter check here.

### Coupling with `/control`

An agent does not choose the `resource_id` for a `config` request: it sends back, verbatim, the
`agent.config_token` `/control` gave it on the notify that reported the mismatching `config_hash`
(see [Notify](#notify-keepalive)). Today that token's value *is* the group selector documented
above, which is why the two sections describe the same identifier — but the token is the contract
and the selector is the current implementation of it.

That makes the invariant the manager's to keep: `/control` must report `config_hash` over the file
that `/download` resolves to **for the token it hands that agent**. If the two disagree — a hash over
one member group's `merged.mg` while the agent is given a multigroup selector, say — the agent
re-downloads its configuration on every notify.

## Reporting endpoints (`POST /stats` and `POST /config`)

The agent periodically reports two aggregated documents: one carrying every module's **statistics**
and one carrying its effective **configuration**. The two ship with **different** defaults (see the
agent's [`<stats_report>` / `<config_report>`](../client/configuration.md)):

| Route | Agent toggle | Enabled by default | Default interval |
| --- | --- | --- | --- |
| `POST /stats` | `<agent><stats_report>` | **no** | 60 s |
| `POST /config` | `<agent><config_report>` | **yes** | 3600 s |

`/config` ships on because the manager needs a configuration snapshot even from an agent whose
configuration nobody has touched; `/stats` is opt-in. An explicit `<enabled>` always overrides the
default. They
replace the pull-style API endpoints of 4.x — the manager no longer asks an agent for its stats, the
agent reports them and the manager indexes what arrives.

**remoted itself does not interpret either document** — but the service behind it does. remoted
authenticates the request and relays the body to the
[Inventory Sync Server](../inventory-sync-server/README.md) over
`queue/sockets/inventory-sync-http.sock`, which validates its shape, rebuilds it into an indexable
document, and writes it: `/stats` into `wazuh-agent-stats` and `/config` into `wazuh-agent-config`.
Both index **one document per agent, keyed by the agent id**, so each push replaces the previous
report rather than appending.

Both routes forward the **authenticated** agent id as an `X-Wazuh-Agent-Id` header. These documents
do not carry a trustworthy id of their own, and the sync server is what writes the authoritative one
in. The value comes from the `Authorization` header that was already verified, never from the body,
so a document claiming a different agent cannot override it — anything the agent's own reporter puts
at the document root is dropped rather than indexed next to it.

### Request

`application/json`, optionally zstd-compressed like any other route. remoted's **only**
endpoint-level check is that the body is **not empty** — parsing is the sync server's job, and doing
it on both sides would walk the payload twice on a periodic path. Rejecting an empty body here still
saves a deferred-work slot and a UDS round trip.

The two bodies have different, specific shapes, and a malformed one is rejected downstream with a
`400` (see [Error handling](#error-handling-3)):

**`POST /stats`** — an object keyed by module:

```json
{"modules": {"agent": {}, "logcollector": {}}}
```

`modules` is moved under `wazuh.agent.statistics` untouched: nothing renames a metric or reshapes a
module's body, since only the agent knows which of its counters are cumulative.

**`POST /config`** — an **array** of one `{module, config}` pair per module:

```json
[
  {"module": "fim", "config": {}},
  {"module": "logcollector", "config": {}}
]
```

Each element is reduced to exactly those two keys — anything else the agent sent is dropped — and the
array becomes an object keyed by module name under `wazuh.agent.configuration.content`, with
`modules` derived from its keys so the two cannot drift apart.

A report is **all or nothing** on both routes: one malformed module rejects the whole document rather
than indexing a partial report the agent could not tell apart from a complete one.

### Responses

The two differ in exactly one way — what a success carries back:

| | `POST /stats` | `POST /config` |
| --- | --- | --- |
| `200 OK` body | fixed `{}` | the sync server's enriched document, passed through |

`/stats` answers a fixed body on purpose: the agent has nothing to read back, and a constant keeps an
arbitrary downstream string off the wire. On **failure** neither route reflects the downstream body —
both collapse to a fixed local message — so an arbitrary downstream string is never returned to an
agent.

> **A `200` means accepted, not indexed.** The sync server answers before the indexer write completes
> (the write is fire-and-forget), so an indexer-side rejection is **silent** to the agent, which
> already has its `200`. This matters most on `/stats`, whose `wazuh-agent-stats` mapping is
> `dynamic: strict` with every leaf declared: a module or metric the template does not declare makes
> the indexer reject the **whole** document with `strict_dynamic_mapping_exception`. So an agent-side
> metric addition needs no change to this endpoint, but it does need one in the index template — and
> if it is missed, statistics stop landing with nothing in the agent's logs to say so. `/config`'s
> template is `dynamic: false` instead, which is far more forgiving: an unrecognized module, or an
> undeclared key inside a known one, is still written and kept in `_source`, just not indexed for
> search. Watch the sync server's own metrics rather than the agent's response to confirm ingestion.

### Error handling

| Condition | HTTP | `error` message |
| --- | --- | --- |
| Empty body, or the sync server rejected the document | `400` | `Invalid stats document` / `Invalid config document` |
| Body over the auth body limit | `413` | `Request payload is too large` |
| Sync server unreachable, no timely answer, or any 5xx/unexpected status | `503` | `Service unavailable` |

Every `503` means the same thing to the agent: not accepted, retry on the next reporting interval.
Auth failures reuse the same responses as `/stateless`. Neither route is timed in the
`remoted.http.*.latency` histograms — they share `/stateful`'s downstream and produce no new answer of
their own; see [Metrics](metrics.md).

## Testing

`src/remoted/remoted_module/tools/send_stateless.py` mints the `wazuh-agent+jwt` bearer and sends
`POST /stateless` requests the way the manager verifies them (shared `wire_jwt.py`, pure Python
standard library, key read from `client.keys`; `python3 wire_jwt.py --self-test` reproduces the frozen
vectors). Requires `pip install -r requirements.txt` (in the same `tools/` directory).

```bash
# one valid request -> 202
python3 send_stateless.py --agent-id 1001

# corrupt the token's signature -> 401 (invalid_signature)
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

`src/remoted/remoted_module/tools/send_download.py` does the same for `POST /download`, and can
resolve the agent's own group for you rather than making you name one:

```bash
# fetch the merged configuration of the agent's first group -> 200 + streamed body
python3 send_download.py --agent-id 001

# a staged WPK package
python3 send_download.py --resource-type wpk --wpk wazuh_agent_v5.0.0_linux_x86_64.wpk

# run every success/failure scenario (bad type, rejected identifier, unknown group -> 404, ...)
python3 send_download.py --all

# concurrency + memory check: N agents downloading at once, sampling remoted's RSS
python3 send_download.py --simulate 50 --repeat 4 --selectors 'default;web,prod' --watch-rss
# options: --url (default https://127.0.0.1:9443), --manager-home, --resource-id, --unknown-group
```

`src/remoted/remoted_module/tools/send_agent_json.py` covers the two reporting routes, `POST /stats`
and `POST /config`, with the same bearer:

```bash
# one /stats report -> 200 + {}
python3 send_agent_json.py

# the same against /config -> 200 + the enriched document
python3 send_agent_json.py --endpoint config

# corrupt the token's signature -> 401 (invalid_signature)
python3 send_agent_json.py --tamper

# every scenario against BOTH routes
python3 send_agent_json.py --all
# options: --url (default https://127.0.0.1:1517), --agent-id, --client-keys, --body
```

`src/remoted/remoted_module/tools/send_enroll.py` does the same for `POST /enroll` — but since an
enrolling agent has no `client.keys` entry to sign with, it works from whatever credential you give
it directly (a password, a client certificate, or neither) rather than reading one from a file:

```bash
# Open mode -- no credential at all
python3 send_enroll.py --name web-01

# Password mode -- mints the wazuh-enroll+jwt bearer from the manager's actual enrollment password
python3 send_enroll.py --name web-01 --password Secret123

# corrupt the bearer's signature -> 401
python3 send_enroll.py --name web-01 --password Secret123 --tamper

# mTLS mode -- the client certificate presented during the handshake is the credential
python3 send_enroll.py --name web-01 --client-cert agent.pem --client-key agent.key

# run every scenario this script can drive without knowing the manager's configured mode in
# advance (body validation always; bearer/timing scenarios too if --password is given)
python3 send_enroll.py --password Secret123 --all
# options: --url (default https://127.0.0.1:1517), --version, --groups, --ip, --key-hash,
#          --password-file (reads /var/wazuh-manager/etc/authd.pass by default)
```

## References

- [Event Protocol Specification](event-protocol.md) — the `H`/`E` wire format for event batches.
- [Configuration](configuration.md) — classic `remoted` (`<remote>`) options and internal options.
- [Architecture](architecture.md) — where the HTTPS listener sits in the `remoted` pipeline.
- [Authd](../authd/README.md) / [Authd Configuration](../authd/configuration.md) — the enrollment
  service `/enroll` bridges to, and the `remote_enrollment`/`legacy_enrollment` flags that gate
  both enrollment paths.
- Endpoint contract: [`agent-api.yaml`](agent-api.yaml) /
  [ReDoc reference](agent-api-reference.html).
