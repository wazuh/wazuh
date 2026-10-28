# HTTPS Agent API

`remoted` embeds a self-contained C++ module (`remoted_module`) that runs an **HTTPS listener** on
port `1517`. This is the agent-manager transport in 5.0: a 5.x agent enrolls, reports and receives
work over it exclusively. The classic AES-encrypted TCP/UDP channel on port `1514` still exists, but
only to keep serving 4.x agents, and only while `<remote><legacy>` is present and enabled: an absent
`<legacy>` block leaves it off, but the installer writes `<enabled>yes</enabled>`, so an installed
manager listens on `1514` until an operator turns it off — see
[`legacy.enabled`](configuration.md#legacyenabled).

The listener is built on RESTinio + OpenSSL and authenticates every request with a per-agent
**`wazuh-agent+jwt` bearer token** (HS256) the agent self-signs with its pre-shared `client.keys` key.

> The listener **requires** a TLS certificate and key to be present (see
> [Transport and TLS](#transport-and-tls)). The credential resolver issues them at installation; to
> use your own PKI, overwrite `/etc/wazuh-manager/certs/remoted.pem`, `/etc/wazuh-manager/certs/remoted-key.pem` and the CA that
> signs them, `/etc/wazuh-manager/certs/root-ca.pem`, with the Wazuh installation assistant's `wazuh-certs-tool` before the
> first start, and the manager fails closed until they are there (see
> [Certificate provisioning and fail-closed start](#certificate-provisioning-and-fail-closed-start)).

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

- **Bind address / port:** `0.0.0.0:1517` by default. Both IPv4 and IPv6 literals are accepted
  (see [Bind address: IPv4, IPv6 and dual-stack](#bind-address-ipv4-ipv6-and-dual-stack) below).
- **TLS:** minimum version TLS 1.3; the server loads a PEM certificate chain and private key and
  verifies that the key matches the certificate.
- **TLS file paths:** `/etc/wazuh-manager/certs/remoted.pem`,
  `/etc/wazuh-manager/certs/remoted-key.pem`, and `/etc/wazuh-manager/certs/root-ca.pem` by default
  (absolute; a relative path written in the configuration resolves against `/var/wazuh-manager`). These paths are opened by the module itself,
  **after** `remoted` has already dropped root privileges (`Privsep_SetUser()`), so the private
  key (and the CA bundle, when `verification_mode` requires one) must be readable by the
  `wazuh-manager` user `remoted` runs as. The pair is provisioned by the operator (see
  [Certificate provisioning and fail-closed start](#certificate-provisioning-and-fail-closed-start))
  and must be owned `root:wazuh-manager`, mode `640` — the installer re-applies that
  ownership to every `.pem` in `/etc/wazuh-manager/certs` on every install; anything the service user cannot read stops
  `remoted` at startup (see
  [Diagnosing rejections and capacity problems](#diagnosing-rejections-and-capacity-problems)).
- **Message limits and timeouts:** max URL 2048 B, max header name 256 B, max header value 8192 B,
  max 64 header fields, and a transport body cap of 10 MiB by default (`<remote><https><max_body_size>`);
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
  an explicit `yes` is ignored, with a warning, for an IPv4 `bind_addr`; `no`, the default, never
  warns.
- **A specific literal** (`10.0.0.5`, `2001:db8::1`, ...) binds only that address/family, same as
  today.
- Internally, an IPv4 client connecting through a dual-stack (`::`) socket is reported by the OS as
  an "IPv4-mapped IPv6" address (`::ffff:10.0.0.5`), not the plain `10.0.0.5` form. `remoted_module`
  unmaps this back to plain IPv4 before it's used anywhere (e.g. `HttpRequest::remoteIp`), which is
  what lets the registered-address check below compare it against the `ip` column in `client.keys`
  without either side having to handle the mapped form.

### Certificate provisioning and fail-closed start

Neither `wazuh-manager-remoted` nor `wazuh-manager-authd` has a certificate-generation mode: the
manager's credential resolver issues the pair once, at installation, and nothing re-examines or
reissues it afterwards. In a distributed deployment the listener
pair is instead a leaf of the deployment's CA, issued by the Wazuh installation assistant's certificate tool
(`wazuh-certs-tool`, the same tool that issues the indexer and dashboard certificates) as
`<node>-remoted.pem`/`<node>-remoted-key.pem`, and deployed by the operator as
`/etc/wazuh-manager/certs/remoted.pem`/`/etc/wazuh-manager/certs/remoted-key.pem` (`root:wazuh-manager 640`) next to the
CA that signed it, `/etc/wazuh-manager/certs/root-ca.pem` (`root:wazuh-manager 640`) — the CA served on
[`GET /cacerts`](#ca-certificate-endpoint-get-cacerts) and pinned by agents. The exact commands are in
[Using certificates issued elsewhere](../../getting-started/installation.md#using-certificates-issued-elsewhere). The installer only
creates `/etc/wazuh-manager/certs` and re-applies the pair's ownership when it is already there; when it is absent
the installer prints nothing (the credential resolver issues it later in the same installation, and a
start without it is refused, see below). An existing pair is never replaced, so upgrades keep theirs.

Without a usable pair the manager **fails closed**, in four layers, from the outside in:

1. **The credential resolver's check** (`wazuh-manager-resolve-credentials --check`, which
   `wazuh-manager-control start` runs before the configuration validator checks any file) follows
   `remote.https.certificate`, `key` and `ca_certificate` and authd's `ssl_manager_cert` and
   `ssl_manager_key`, which must name files directly in `/etc/wazuh-manager/certs`. It refuses a
   certificate or key present without its other half
   (`INVALID /etc/wazuh-manager/certs/remoted-key.pem: half a pair (remoted.pem is missing)`), a file
   that is not `root:wazuh-manager` mode `0640`
   (`UNSAFE /etc/wazuh-manager/certs/remoted-key.pem: group is root, not wazuh-manager`), and a pair
   or bundle that is not valid (key mismatch, issuer, validity window). A pair missing altogether is
   left to the next layer. See [Credentials](../../getting-started/credentials.md).
2. **`wazuh-manager-control start`** runs `wazuh-manager-conf validate` before any daemon; it
   checks that every file the listeners reference exists — `remote.https.certificate`, `key`, `ca`,
   `ca_certificate` and authd's `ssl_manager_cert`, `ssl_manager_key`, `ssl_agent_ca` (empty values
   are skipped) — and refuses to start on the first missing one with, on the console and in
   `logs/wazuh-manager.log`:
   `(1244): Invalid configuration at '/remote/https/certificate': file not found:
   /etc/wazuh-manager/certs/remoted.pem (issued by the credential resolver at installation, or
   provisioned externally, e.g. with wazuh-certs-tool).`
3. **`wazuh-manager-remoted`**, after dropping privileges and before remoted writes its PID file
   (so `wazuh-manager-control status` never reports as running a remoted that is about to exit), probes both paths with `access(R_OK)` and exits with exactly one of
   `Cannot start the HTTPS agent listener: the TLS certificate '<c>' and private key '<k>' are missing
   or unreadable by the service user.`, `… the TLS certificate '<c>' is missing or unreadable by the
   service user.` or `… the TLS private key '<k>' is missing or unreadable by the service user.`,
   each followed by the hint `The pair is issued at installation and is never reissued at start: if the files are present, check that they are root:wazuh-manager and mode 0640, since remoted opens them after dropping privileges; otherwise provision remoted.pem, remoted-key.pem and root-ca.pem under /etc/wazuh-manager/certs (see 'Credentials' in the installation guide).` When `remote.https.verification_mode` is `certificate` or `full`, it also probes the CA that verifies agent client certificates (`remote.https.ca`; empty means `/etc/wazuh-manager/certs/root-ca.pem`) and exits with `Cannot start the HTTPS agent listener: the CA certificate '<ca>', which verifies agent client certificates, is missing or unreadable by the service user.` followed by the hint ` remote.https.verification_mode requires it: if the file is present, check that it is readable by the service user, since remoted opens it after dropping privileges; otherwise point remote.https.ca at the CA that signs the agents' client certificates.` In every mode it then probes the CA certificate it publishes on `GET /cacerts` (`remote.https.ca_certificate`; empty means `/etc/wazuh-manager/certs/root-ca.pem`) and exits with `Cannot start the HTTPS agent listener: the CA certificate '<ca_certificate>' that remoted publishes on /cacerts for agent enrollment is missing or unreadable by the service user.` followed by the hint ` If the file is present, check that it is readable by the service user, since remoted opens it after dropping privileges; otherwise provision it, or point remote.https.ca_certificate at the CA certificate 5.x agents must trust (see 'Credentials' in the installation guide).` For the files the credential resolver follows, a group other than `wazuh-manager` or a
   missing group read bit is already refused by layer 1; this layer is what catches `remote.https.ca`,
   which the resolver does not follow, and any other way the service user is denied a file that root
   can read, since the validator runs as root and cannot tell. `wazuh-manager-authd` fails the same way on the same files (`SSL context
   setup failed (certificate '…', key '…'). authd reuses the HTTPS agent listener's pair, …`).
4. **The module itself** fails to load a pair that passed both probes but is unusable (corrupt PEM,
   key/certificate mismatch): the error names the file it could not load, followed by OpenSSL's
   reason (`Cannot start the HTTPS agent listener: The configured TLS certificate '<c>' cannot be
   loaded (use_certificate_chain_file: no start line (PEM routines))`, and the same with `TLS private key
   '<k>'`, where a key that does not belong to the certificate reads `key values mismatch …`; the
   parenthesised OpenSSL library name at the end varies with the failure) and, as with
   every other startup failure, `remoted` does not start.

`remote.https.ca_certificate` must be readable at start, since 5.x agents bootstrap their trust from
`GET /cacerts`: the credential resolver's check (step 1) refuses it when it is not
`root:wazuh-manager` mode `0640` or does not contain the CA that issued the listener's certificate,
the validator (step 2) refuses a missing one with the same `(1244) … file not found` verdict, and
remoted's probe (step 3) exits when the service user still cannot read it. Only if
it becomes unreadable or disappears after the start does remoted keep running: `GET /cacerts` then
answers `404` (or keeps serving the last bundle it read).

### Renewing the listener certificate

Renewal is an operator task as well — nothing in the manager reissues the pair. The certificate
evaluation, run when the listener starts and every 24 hours after
(see [`GET /cacerts`](#ca-certificate-endpoint-get-cacerts)) logs a WARN once `remoted.pem` is within
30 days of `notAfter` and an ERROR once it has expired; `remoted.server.tls.cert_expiry_days` reads
the countdown. Two cases:

**Leaf renewal from the same CA** (the routine one):

1. Issue a new `<node>-remoted.pem`/`<node>-remoted-key.pem` from the **same** `root-ca.pem` with the
   installation assistant's `wazuh-certs-tool` — or any tooling that signs with that CA's key and
   produces a leaf with `CA:FALSE`, `extendedKeyUsage serverAuth` and a SAN naming the address agents dial.
2. Install them over `/etc/wazuh-manager/certs/remoted.pem`/`/etc/wazuh-manager/certs/remoted-key.pem` as `root:wazuh-manager 640`
   (the `mv`/`chown`/`chmod` steps of
   [Using certificates issued elsewhere](../../getting-started/installation.md#using-certificates-issued-elsewhere)).
3. `systemctl restart wazuh-manager` — the leaf is loaded once, when the listener starts.
4. Check (substitute the certified hostname):
   `sudo openssl s_client -connect mgr.example.com:1517 -servername mgr.example.com -verify_hostname mgr.example.com -verify_return_error -CAfile /etc/wazuh-manager/certs/root-ca.pem </dev/null` prints
   `Verify return code: 0 (ok)`, `GET /cacerts` answers `200`, and `cert_expiry_days` is back to the new
   validity (the WARN is not logged again).

   If the listener requires mutual TLS, also supply its accepted client certificate and key with
   `-cert` and `-key`.

Agents keep verifying throughout: they pin the CA, not the leaf.

**CA rotation** (a new `root-ca.pem`, so every leaf it signed changes with it) is a separate
procedure: the listener serves the CA bundle to agents, so replacing the CA in one step leaves every
agent that pinned the old one unable to verify this manager until it learns the new anchor. Rotate
with `wazuh-manager-certs`, which carries old and new CA side by side while agents catch up; the
ordered procedure, and what the manager logs at each step, is the [CA Rotation Runbook](ca-rotation.md).
A CA and a leaf installed out of step make `GET /cacerts` answer `503` `{"error":"ca_mismatch"}`.

## Authentication (JWT bearer)

**Enrollment uses a separate credential; `GET /` and `GET /cacerts` need no bearer.** The other endpoints require the agent<->manager
bearer token described in this section, keyed by an agent's pre-shared `client.keys` entry. An
enrolling agent has no such entry yet, so `/enroll` cannot use it — it authenticates with an
independent credential instead: a client certificate, a `wazuh-enroll+jwt` bearer of its own (keyed
by the shared enrollment password, by an enrollment token, or — for an agent re-enrolling under its
existing id — by that agent's re-enrollment secret), or neither. See
[Enrollment endpoint](#enrollment-endpoint-post-enroll) below.

Every request using the agent bearer MUST carry two headers:

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
| `iat`/`nbf`/`exp` | UNIX seconds, integers; the agent always emits `exp - iat` = 60 s, and the verifier accepts `0 < exp - iat <= 60` with `nbf = iat`. A token is accepted while `iat <= now + jwt_clock_skew`, `now <= exp + jwt_clock_skew` and `now - iat <= jwt_max_age + jwt_clock_skew` ([`remoted.jwt_max_age`](configuration.md#remotedjwt_max_age) 60 s, [`remoted.jwt_clock_skew`](configuration.md#remotedjwt_clock_skew) 30 s by default). Because `exp` is at most `iat + 60`, raising `jwt_max_age` above 60 s does not widen the window; only `jwt_clock_skew` does |
| `jti` | 16 CSPRNG bytes, base64url (22 chars), fresh for every request — the agent never reuses a token, and the manager keeps no replay store (see below) |
| Signature | HMAC-SHA256 over `base64url(header) "." base64url(claims)` with the **32-byte key obtained by hex-decoding the 64-character `client.keys` secret** — never the ASCII text of the secret. The key is never transmitted |
| Size | the whole token is at most 4096 bytes; it is parsed only after that bound holds |

The manager resolves the agent key by reading `/etc/wazuh-manager/client.keys` directly (the same id/name/ip/key
format `OS_ReadKeys()` uses); the key column must be exactly **64 lowercase hex characters**
(32 bytes) — the form `authd` generates. A shorter or upper-case key cannot authenticate: the agent
is answered `401 invalid_signature` (so it does not re-enroll on its own) and remoted logs a warning
naming the `client.keys` line; the operator has to re-enroll that agent. A removed/disabled agent (`#`/`!`-marked, or simply absent) is treated as unknown.

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
  `min(60, jwt_max_age) + jwt_clock_skew`, 90 s by default). This is accepted: the transport is TLS, the
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
with a `401` of class `invalid_signature` (see [Error responses](#error-responses)): the agent must
not re-enroll over it — the operator fixes the column.

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

Why zstd was chosen over gzip, with the benchmark behind it, and how the decoder's memory is
reserved, are design records kept in the developer README
(`src/remoted/remoted_module/README.md`, section *Why zstd, and not gzip*).

- On routes using the agent bearer, decompression happens **after** authentication succeeds: the bearer token is verified
  from the headers alone (the body is not part of it — TLS protects it), so an unauthenticated
  request never reaches that decoder. `/enroll` can be open and has its own 16 KiB decoded-body cap.
- `remoted.auth_max_body_size` caps the **wire body** at 5 MiB by default, including a compressed
  body. The decoded output on authenticated agent routes has its own cap,
  `remoted.auth_max_decoded_body_size` (32 MiB by default; on `/stateful`, the agent's whole byte
  share `remoted.max_inflight_bytes_per_agent`, because a vulnerability-detection first sync cannot
  be split): a frame that declares more is refused with `413` before anything is allocated, and a
  streamed frame is refused when its output would cross it. The decoded cap is larger than the wire
  cap because the agent sizes its batches before compressing them, so honest bodies decode past
  5 MiB.
- A body is exactly **one** zstd frame. Anything after the first frame (another frame, a skippable
  frame) is a `400`, and a frame declaring a window over 8 MiB is a `413`. Both of the decoder's
  memory costs — its own buffers, sized from the window the frame header declares, and the
  decompressed output — are reserved against the **in-flight byte budget** (`max_inflight_bytes`,
  see [Configuration](#configuration)) *before* they are allocated, so concurrent zstd requests
  compete for the same pool as unprocessed payloads. A request whose reservation does not fit at
  that moment is refused with `413` before the payload is materialized in memory; the reservations
  are released when decompression finishes (decoder buffers) and when the handler is done with the
  body (output).
- A missing `Content-Encoding` header is treated exactly like today: the body is passed through
  unchanged.
- Any `Content-Encoding` value other than `zstd` — including `gzip`, which was intentionally dropped
  in favor of zstd-only support — is rejected with `415`. The same happens to `zstd` itself when
  `remoted.http_content_encoding_enabled` is disabled.
- A `Content-Encoding: zstd` body that isn't a valid, complete zstd frame (bad magic, truncated,
  unreadable header) is rejected with `400`. Note the distinction from `413` above: `400` means the
  frame itself is bad, `413` means the frame is fine but there isn't capacity for it right now.

### Error responses

On rejection the body is `{"error":"<message>","code":<status>}`, except for a `401`, whose `code`
is the **authentication failure class** (a string) and whose `WWW-Authenticate` challenge names the
same class ([RFC 6750 §3](https://www.rfc-editor.org/rfc/rfc6750#section-3)). Every credential
failure keeps the same generic message — the class is the machine-readable part, and it is
deliberately coarser than the manager's own diagnosis (which stays in its log and in the
`remoted.auth.reject.*` metrics): it tells the agent **what to do**, not what failed.

| `code` / `error_description` | `WWW-Authenticate` | Meaning | The agent should |
|---|---|---|---|
| `unknown_agent` | `Bearer error="invalid_token", error_description="unknown_agent"` | the `kid` is not in `client.keys` (never enrolled, removed, or `#`/`!`-marked) | re-enroll |
| `stale_token` | `Bearer error="invalid_token", error_description="stale_token"` | the token is outside the accepted window (expired, older than `jwt_max_age + jwt_clock_skew`, or issued more than `jwt_clock_skew` s in the future) | correct its clock (the `Date` header is the manager's) and retry |
| `invalid_signature` | `Bearer error="invalid_token", error_description="invalid_signature"` | the credential does not work for that identity: bad MAC, not a `wazuh-agent+jwt` (grammar, header or claims), `sub`/`iss` naming another agent, peer address outside the entry's `ip` column, or an entry whose key does not decode | **not** re-enroll; keep the credential and report |
| `invalid_request` | `Bearer error="invalid_request"` | no usable credential was presented: `Authorization` missing, not `Bearer` (the scheme is matched case-insensitively, so `bearer` is accepted), or malformed | send a credential |
| `token_unknown` / `token_expired` / `token_revoked` | `Bearer error="invalid_token", error_description="token_…"` | `POST /enroll` only: the enrollment token's own state | obtain a new token from the operator |
| `enrollment_key_unavailable` | `Bearer` (no error code: the server could not judge the credential) | `POST /enroll` only, Password mode: the manager's enrollment password is not available on this node | retry later; nothing to fix on the agent |

Everything below the `401` rows keeps a numeric `code` equal to the HTTP status.

| Condition                                                                                                                                                                               | HTTP  | `error` message                             |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | ------------------------------------------- |
| Missing `protocol-version` header                                                                                                                                                       | `400` | `Missing required header: protocol-version` |
| Unsupported `protocol-version`                                                                                                                                                          | `400` | `Unsupported protocol-version`              |
| Missing / malformed `Authorization` (class `invalid_request`)                                                                                                                           | `401` | `Invalid client authentication`             |
| Unknown agent (class `unknown_agent`)                                                                                                                                                   | `401` | `Invalid client authentication`             |
| Stale token: expired, older than the accepted age, or issued in the future (class `stale_token`)                                                                                        | `401` | `Invalid client authentication`             |
| Bad signature, invalid token (grammar, header or claims), identity mismatch, peer address not allowed by the agent's `ip` column, unusable key (class `invalid_signature`)               | `401` | `Invalid client authentication`             |
| Body exceeds the auth body limit (5 MiB) -- or, for `Content-Encoding: zstd`, the frame declares a window over 8 MiB, or the decoder's buffers or the decompressed output don't fit in the in-flight capacity free at that moment | `413` | `Request payload is too large`              |
| `Content-Encoding` present but not (case-insensitively) `zstd`                                                                                                                          | `415` | `Unsupported Content-Encoding`              |
| `Content-Encoding: zstd`, but the body isn't a valid/complete zstd frame                                                                                                                | `400` | `Malformed compressed body`                 |
| H line repeats `wazuh`, `wazuh.agent` or `wazuh.agent.id` (names compared after JSON unescaping)                                                                                        | `400` | `Invalid event batch`                       |
| Payload's `wazuh.agent.id` (H line) missing/malformed/non-numeric, `wazuh` or `wazuh.agent` not an object, or not byte-for-byte equal to the authenticated `agent-id` (zero padding included)  | `400` | `Invalid event batch`                       |
| Downstream rejected the batch (bad H/E)                                                                                                                                                 | `400` | `Invalid event batch`                       |
| Out of capacity (byte budget, deferred-work slots, or this agent's own share), or downstream unreachable/errored                                                                        | `503` | `Service unavailable`                       |
| Endpoint handler raised an unexpected error                                                                                                                                             | `500` | `Internal server error`                     |
| `verification_mode full` and the client certificate does not carry the connecting peer's address                                                                                       | `403` | `Client certificate does not match the peer address` |

A path that matches no route is answered `404` with `{"error":"not_found"}` (no `code`) and the
connection is closed. The `429` bodies of the rate-limited routes are documented with each route.

The payload-identity check runs **before** the batch is forwarded: a mismatch never reaches the
engine at all, and (by design) shares the same `400 Invalid event batch` message as a batch the
engine itself rejects, so a client cannot distinguish the two causes.

A header that repeats a step of the identity path is refused outright rather than resolved. JSON
permits repetition, but the manager forwards the batch downstream byte for byte and the engine
re-reads those same bytes under different rules — it keeps the *last* of a repeated name where this
check takes the *first*. Whichever member was validated would therefore not be the one ingested, so
the ambiguous header is rejected instead. The comparison is done on the unescaped names, so
`"wazuh"` and `"\u0077azuh"` count as the same member.

The rule covers `wazuh`, `wazuh.agent` and `wazuh.agent.id` only. A repetition elsewhere in the
header cannot move the identity, because the engine escapes member names when it builds the JSON
Pointer it merges through: a member literally named `wazuh/agent` stays a literal sibling instead of
resolving onto the real one. Such a field may reach the ingested event; it is inert there and the
index template rejects it. A conforming agent is unaffected either way — the protocol has always
specified one occurrence of each field (see [Event protocol](event-protocol.md#rules)).

Requests larger than the 10 MiB transport cap are dropped at the TLS/HTTP layer (the connection is
closed) before authentication runs, so they never receive a clean `413`.

The server bounds capacity in two phases and sheds excess load with a plain **`503 Service
Unavailable`** (server-side load-shedding, not rate limiting -- that is the `429` below; no
`Retry-After` — the agent runs its own retry/backoff): the **in-flight byte budget** bounds total
unprocessed payload in memory (its `503` also closes the connection), and the **deferred-work
limiter** bounds how many requests are parked awaiting the downstream service (its `503` is answered
on the open connection). The liveness `GET /` and the trust-bootstrap `GET /cacerts` are
exempt from the byte budget: its exhaustion does not reject either route. Connection limits and
TLS checks still apply. See the memory settings below.

Rate limiting is a **separate** mechanism and answers **`429 Too Many Requests`** with a
`Retry-After`. It applies to the two routes no credential can gate, `POST /enroll` and
`GET /cacerts`, and only to those: every other route is already bounded by what the presented agent
key permits. The bucket belongs to the **endpoint** (`POST /enroll` has two of the same rate, one
for requests that verified a password or enrollment token and one for the rest), so the configured
rate is a ceiling for every caller of this node rather than an allowance per agent — one client
asking fast enough can consume the route's budget. See
[the `remote.https` rate options](configuration.md#rate-limits-of-the-unauthenticated-routes)
for the defaults and for how to size them.

`/stateful` is the one route whose `503` can carry a `Retry-After`, in two cases: a digits-only
`Retry-After` of at most 6 digits that the inventory sync server sent is passed through, since there
the downstream answer **is** the session result; and the `503` remoted answers when
`remoted.downstream_stateful_response_timeout` elapses carries
[`remoted.downstream_stateful_retry_after`](configuration.md#remoteddownstream_stateful_retry_after)
(20 s by default, `0` omits it), because the sync server is still applying that session.

**Statuses remoted never sends.** `426 Upgrade Required` is not part of this contract, and `429`
is answered only on the two rate-limited routes above — capacity is shed with `503`, never `429`.
The agent's client classifies both as retryable anyway, so an agent that logs a `426`, or a `429`
on any other route, has been answered by something between it and the manager (a load balancer, a
proxy, a WAF) rather than by remoted. Treat it as a sign to look at the intermediary — see
[Load balancers](load-balancers/README.md).

## Endpoints

The listener exposes **ten** agent-facing routes. Every one of them except `GET /`, `GET /cacerts`
and `POST /enroll` is authenticated with the bearer token above.

Every path on this page is the endpoint's **logical** path. The server exposes each endpoint under
[`remote.https.global_prefix`](configuration.md#httpsglobal_prefix) — `/wazuh-manager/` by default,
also when the option is absent; only a prefix of `/` leaves the paths bare — so `POST /stateless` becomes `POST /wazuh-manager/stateless`, the health probe becomes
`GET /wazuh-manager/` (with or without the trailing slash) — and the unprefixed paths answer
`404`. The prefixed path is what travels on the wire and what the router matches, exactly:
case-sensitive (`/WAZUH-MANAGER/cacerts` is a `404`) and never percent-decoded (any `%`-encoded
path, such as `/wazuh-manager/%63acerts`, is a `404`); the only tolerances are a single trailing `/`,
a query string and a fragment, which are accepted and ignored (`/wazuh-manager/cacerts?x=1` and
`/wazuh-manager/cacerts#x` are `/cacerts`).
Agents send the full prefixed target. The token does not bind it, so a prefix mismatch is a `404`,
never a `401`.

The module's own statistics and readiness are **not** served here: they live on a separate
manager-local Unix socket (`GET /`, `GET /metrics`, `GET /status`, `GET /tls` on
`queue/sockets/remote-admin-http.sock`), so they are never reachable from an agent — see
[the admin socket](README.md#local-admin-socket), [Metrics](metrics.md) and
[Certificate validity](certificate-validity.md) (`GET /tls`).

- **`GET /`** — unauthenticated health probe. Returns `200` with
  `{"status":"ok","module":"remoted"}`.
- **`GET /cacerts`** — unauthenticated CA distribution: the PEM configured as
  [`remote.https.ca_certificate`](configuration.md#httpsca_certificate) (the CA that signs the
  listener certificate), served as re-serialised certificates with
  `Content-Type: application/x-pem-file`, so an agent can bootstrap trust in the manager before it
  holds any credential. Returns **`200`** with the PEM,
  **`404`** `{"error":"not_found"}` when the file was never readable or is readable but carries no
  certificate (a file that stops being readable after it was served keeps the last good bundle in
  service), or **`503`** `{"error":"ca_mismatch"}` when the certificate this listener serves does not chain to
  the configured CA — refusing to hand out a CA that would make every verifying agent fail. See
  [CA certificate endpoint](#ca-certificate-endpoint-get-cacerts) below.
- **`POST /stateless`** — authenticated event ingestion. Once the signature is verified, the module
  cross-checks the H line's `wazuh.agent.id` against the authenticated `agent-id` (**`400`** on a
  missing/malformed header, an H-line JSON over 8 KiB, or a mismatch; the agent drops `groups` from
  an H line that would exceed 8 KiB, and keeps only the id if it still does); only then does it forward the H/E batch to the engine's
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
  wazuh-db is unreachable (a task-manager failure still answers `200`, with an empty `tasks`). See
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
  identifier, **`403`** when a `config` request names a selector that is not the requesting agent's
  own, **`404`** when the resource does not exist, or **`500`**. See
  [Download endpoint](#download-endpoint-post-download) below for details.
- **`POST /stats`** — authenticated ingestion of the statistics document an agent reports for all of
  its modules. Relayed to the [Inventory Sync Server](../inventory-sync-server/README.md) over
  `queue/sockets/inventory-sync-http.sock`, stamping the authenticated identity as `X-Wazuh-Agent-Id`.
  Returns **`200 OK`** with a fixed `{}`, **`400`** on an empty or rejected document, **`413`**, or
  **`503`**. See [Reporting endpoints](#reporting-endpoints-post-stats-and-post-config) below.
- **`POST /config`** — authenticated ingestion of the configuration document an agent reports.
  Same pipeline as `/stats`, and the same `200 OK` with `{}` on success.
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
  `{id,name,ip,key,reenroll_secret}` on success (`reenroll_secret` absent only when `authd` sent none), or a mapped `4xx`/`5xx` on failure. See
  [Enrollment endpoint](#enrollment-endpoint-post-enroll) below for details.

The machine-readable contract is published as OpenAPI, covering all ten routes:
[`agent-api.yaml`](agent-api.yaml), rendered by the ReDoc viewer `agent-api-reference.html` that
ships next to it in the book.

## Configuration

Every setting of this listener is documented once, in the [Configuration Reference](configuration.md):

- the user-facing `<remote><https>` options — bind address, port, `global_prefix`, `max_body_size`,
  the certificate, key and CA paths, `verification_mode`, `ciphers`, `dual_stack` and the two rate
  limits — in [HTTPS Configuration](configuration.md#https-configuration). There is no `enabled`
  toggle: the listener always starts, and remoted refuses to start without its certificate and key;
- the `remoted.*` internal options (`/etc/wazuh-manager/wazuh-manager-internal-options.conf`) —
  the transport's threads, timeouts and message limits (`remoted.http_*`), the capacity limits
  (`remoted.max_inflight_bytes`, `remoted.max_parallel_connections`,
  `remoted.max_handshakes_per_source`, `remoted.max_deferred_requests`,
  `remoted.max_requests_per_agent`, `remoted.max_inflight_bytes_per_agent`), the downstream client
  (`remoted.downstream_*`), the token window and body caps (`remoted.jwt_*`, `remoted.auth_*`), the
  `/control` clients (`remoted.control_*`), the `/enroll` bridge (`remoted.enroll_password_refresh_interval`,
  `remoted.authd_*`) and the `/scan/vd` client (`remoted.vd_scan_*`) — in
  [HTTPS Agent Server](configuration.md#https-agent-server-remoted_module), each with its default
  and range. A value out of range or not numeric stops `remoted` at start, and
  `wazuh-manager-remoted -t` reports it without starting the daemon.

The capacity limits are **layered**: the transport max body size caps a single request's peak
(the connection is closed on an oversized `Content-Length`), the max connections caps how many
bodies can be read at once (peak ≈ max connections × max body size), the in-flight byte budget caps
the total accepted-but-unprocessed payload in memory, and the deferred-request limiter caps how many
requests are parked awaiting a downstream service. Those four are shared by every agent, so the
per-agent share stops one agent from holding all of them: it counts the requests each authenticated
agent has open and the decoded bytes they hold, refusing one more request before its body is
decoded and a body that does not fit what is left of the agent's share. Exhausting any of them → a
plain `503` (the agent retries; `GET /` and `GET /cacerts` are exempt from the byte budget).

All other enrollment behavior (whether it is enabled, whether a password or a client certificate is
required, which agent versions are accepted) is not a `remoted` setting: it is read from `authd`'s
own `<auth>` section, so the two enrollment paths can never disagree; see
[Enrollment endpoint](#enrollment-endpoint-post-enroll) below.

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
Because these are per-request conditions, repeated occurrences are collapsed to **at most one line
per 90 seconds per condition**, so a burst or an outage produces a readable summary instead of
thousands of identical lines. The first occurrence is logged at once. Later ones inside the window
are counted, not logged, and are reported by the **next occurrence after the window** — there is no
timer flushing them — so that line's count covers everything since the previous line, which can be
longer than 90 s when the condition paused. Every such line names the period its count really
covers: `in the last T s`, T being the time since the previous line, or `so far` on the first (the
rate-limit lines: "refused N request(s) with 429 since the previous report T s ago"); for an exact
total at any moment, read the counter on [`GET /metrics`](metrics.md):

```
wazuh-manager-remoted:forwarder: WARNING: Deferred-work slots exhausted (capacity 128): shed 4812
request(s) with 503 in the last 140 s. Consider increasing the value of 'max_deferred_requests', or
investigate why the downstream service is not keeping up.
```

Each of these conditions also has its own counter on the module's
[`GET /metrics`](metrics.md) dump, so the totals (and their rate between polls) quantify what
the throttled log line can only sample:

| Symptom in `wazuh-manager.log` | Setting to review | Metric evidence ([Metrics](metrics.md)) |
|---|---|---|
| In-flight request memory budget exhausted | `remoted.max_inflight_bytes` | `remoted.server.budget.rejected.total` (+ `budget.inflight.bytes` vs the cap) |
| Deferred-work slots exhausted | `remoted.max_deferred_requests` | `remoted.forwarder.deferred.rejected.total` (+ `deferred.inflight` vs `deferred.capacity`) |
| Closed connection(s) that did not complete the TLS handshake in time | `remoted.http_read_timeout` — usually a client holding connection slots without speaking TLS, not a setting to raise | `remoted.server.handshake.timeouts.total` (+ `connections.handshaking`) |
| Refused connection(s): too many TLS handshakes in progress from one address | `remoted.max_handshakes_per_source` | `remoted.server.handshake.rejected_per_source.total` |
| Timed out connecting to / sending to / waiting for the downstream service | `remoted.downstream_connect_timeout`, `_write_timeout`, `_response_timeout` | `remoted.forwarder.error.connect_timeout` / `.write_timeout` / `.response_timeout` |
| Downstream response exceeded the configured cap | `remoted.downstream_max_response_body_size` | `remoted.forwarder.error.response_too_large` |
| Tokens outside the accepted time window (agent clock drift) | `remoted.jwt_max_age`, `remoted.jwt_clock_skew` | `remoted.auth.reject.clock_skew` |
| Body exceeded the authenticated-body cap (413) | `remoted.auth_max_body_size` (wire body, compressed or not), `remoted.auth_max_decoded_body_size` (zstd output; on `/stateful`, `remoted.max_inflight_bytes_per_agent`), or `remoted.max_inflight_bytes` (zstd decoding memory) | `remoted.auth.reject.body_too_large` |
| One agent already held its share (503) | `remoted.max_requests_per_agent` or `remoted.max_inflight_bytes_per_agent` — but investigate the agent first; an honest one never reaches the defaults | `remoted.auth.reject.agent_busy` |
| Downstream timeouts add up past `http_request_timeout` | `remoted.http_request_timeout` | `remoted.http.<endpoint>.latency` percentiles vs the cap |

Two more, about a registered address that no longer matches:

- **`Rejected N request(s) … from an address the agent is not registered with`** (INFO) names the agent
  id and the address it connected from, and is the line to look for when an agent that used to work
  starts getting `401`s after its address changed. INFO rather than WARNING: the condition is a
  property of the agent's registration, not a fault on the manager side. Collapsed on the same
  90-second window as everything above.
- **`client.keys line N: the address '<value>' registered for agent M is not a valid address or
  range`** (WARNING) means that line was skipped, so that agent is now treated as unknown. Fix the
  column or re-enroll the agent. Not throttled: logged once per offending line each time
  `client.keys` is (re)loaded.

Four more that are not about tuning:

- **`Loaded N agent key(s) from '<path>'.`** at startup, and **`Reloaded N agent key(s) from
  '<path>'.`** after every hot-reload. `N` counts keys
  that can actually authenticate — a key that fails to decode is reported separately and is **not**
  counted, so this number can be trusted. If `client.keys` is unreadable, that is logged explicitly:
  otherwise it presents only as every agent being rejected as unknown, with nothing explaining why.
- A missing or unreadable `/etc/wazuh-manager/authd.pass`, at `remoted` startup or on a later poll, is normally a
  **WARNING** naming the file. The exception is a cluster worker within about a minute of starting:
  there, the file not having synced down from the master yet is expected, so it logs at **DEBUG1**
  instead ("Waiting for the enrollment password to be synchronized from the master node …"). A worker
  still missing the file past that window, or a master hitting this path at all, still warns.
- **`Could not derive the enrollment key from '/etc/wazuh-manager/authd.pass' (HKDF unavailable)`** (ERROR) means the
  OpenSSL KDF provider is broken: every Password-mode enrollment fails closed until it is fixed,
  distinct from an unreadable or invalid password file (see above).
- **`Cannot start the HTTPS agent listener: the TLS certificate '…' / private key '…' is missing
  or unreadable by the service user.`** (ERROR, then `remoted` exits; with `verification_mode` `certificate` or `full` the same preflight also reports `the CA certificate '…', which verifies agent client certificates, is missing or unreadable by the service user.`, and in every mode `the CA certificate '…' that remoted publishes on /cacerts for agent enrollment is missing or unreadable by the service user.`) is remoted's own preflight,
  run after it has dropped privileges and before remoted writes its PID file. A missing file rarely
  gets this far — `wazuh-manager-control start` refuses first with the validator's `(1244) … file
  not found` verdict — so this almost always means an ownership/mode mismatch against the
  `wazuh-manager` user (the validator runs as root and cannot tell). Nothing reissues the pair at
  start; the message ends with the provisioning hint. There is no retry: remoted must not
  start without the HTTPS transport up, so this is fatal to the whole daemon, not just this module.
  A pair that passes the preflight but cannot be loaded (corrupt PEM, key/certificate mismatch)
  fails inside the module with an ERROR naming which of the two is the problem. See
  [Certificate provisioning and fail-closed start](#certificate-provisioning-and-fail-closed-start).

Rejections of unauthenticated requests (no bearer, an unknown agent, a bad signature) are logged at
debug level only — visible with `remoted.debug=2` — because an unauthenticated peer controls how many
it can trigger. A malformed request from an agent that **did** authenticate (an invalid `/control` or
`/scan/vd` body, an unknown `/control` type, a payload naming another agent) and the rejections that
point at a manager-side setting (a token outside the clock-skew window, a body over the
authenticated-body cap, an unusable key in `client.keys`) are logged as throttled `WARNING`s instead:
one line per cause and 90 seconds, the rest folded into the next line, which counts them —
`… 12 request(s) in the last 140 s …`, or `… so far` on the first. A peer outside the agent's
[registered address](#registered-address-ip-column) is logged the same way at `INFO`.
Transport-level diagnostics reported by the HTTP library itself (TLS handshake errors, malformed
HTTP, socket resets, and breaches of the `remoted.http_max_*` limits) are logged at
`remoted.debug=1`, not surfaced by default. The client of such a request gets no HTTP answer: an
oversized URL, header or header count, a request carrying both `Content-Length` and
`Transfer-Encoding`, or a bare-LF line ending closes the connection with no `400` or `431`. They are
not surfaced by default because these are per-connection events driven overwhelmingly by
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

Sent by the agent on initial connection. The manager marks the agent as `pending` in global.db,
records the connection time, and returns limits (FIM, Syscollector, SCA quotas), cluster
information (name), and the agent's assigned groups. The agent stores this data locally.
No hashes are included in the startup response.

**Request:**
```json
{
  "type": "startup",
  "version": "v5.0.0"
}
```

**Response (`200 OK`):**
```json
{
  "agent": {
    "groups": ["default", "web-servers"]
  },
  "cluster": {
    "name": "wazuh-cluster"
  },
  "limits": {
    "fim": {"file": 30000, "registry_key": 30000, "registry_value": 30000},
    "sca": {"checks": 30000},
    "syscollector": {
      "browser_extensions": 30000, "groups": 30000, "hardware": 30000, "hotfixes": 30000,
      "network_address": 30000, "network_iface": 30000, "network_protocol": 30000,
      "os_info": 30000, "packages": 30000, "ports": 30000, "processes": 30000,
      "services": 30000, "users": 30000
    }
  }
}
```

Every entry under `limits` is the per-module inventory cap the agent must apply, and every one of
them defaults to **30000**. They are not `remoted.*` settings: each is its own internal option under
its module's own namespace — `fim.file_limit`, `fim.registry_key_limit`,
`fim.registry_value_limit`, `syscollector.<name>_limit` for each of the thirteen keys above, and
`sca.checks_limit` — read once at startup from
`wazuh-manager-internal-options.conf` (range `0` to `INT_MAX`). The object is sent verbatim as the
manager built it, so an operator who raises one of those options sees the new value in the first
`startup` response after restarting the manager, and a limit renamed or added there appears here with
no change to this endpoint.

**Version rejection.** `startup` is the only message whose `version` is validated — `notify`
deliberately skips the check to keep the hot path fast. A rejection also writes
`status_code = invalid_version` to global.db, and answers one of two statuses:

| Cause | HTTP | wazuh-db `version` column |
| --- | --- | --- |
| Version is malformed (empty, over 64 characters, or not `[v]MAJOR[.MINOR[.PATCH[.EXTRA]]]` with an optional `+`/`-` suffix) | `400` | `N/A` sentinel — the framework's version parser raises on anything else, which would break the whole agent listing |
| Version is well-formed but has a higher major or minor than the manager's (a higher patch alone is accepted), and `<remote><agents><allow_higher_versions>` is `no` | `409` | stored with a `v` prefix (`5.1.0` as `v5.1.0`) |

Whatever spelling the agent sends — `5.0.0`, `v5.0.0` or `V5.0.0`, all accepted — the manager writes
the version to wazuh-db as `v5.0.0`, on `startup` and on `notify` alike, so one version never
appears under two spellings in the agent listing.

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
lightweight keepalive (`updateKeepalive`) otherwise. The throttle does not apply to the first
notify after a `startup`, nor to the first one that carries host metadata.

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
    "version": "v5.0.0"
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
  "ca_generation": 1758000000,
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

**`ca_generation` (issue #39319, RF-3) is present too, but it is the one field whose value may be
`null`, and it is not interchangeable across its three states.** It carries the generation the CA bundle
[`GET /cacerts`](#ca-certificate-endpoint-get-cacerts) would serve right now, at no extra cost to
this hot path: a timestamp once a guard vouched for that bundle; `0` when there is a bundle to serve
and no guard vouched for it (an unstamped file, or one a guard refused); and `null` when there is no
servable bundle at all (nothing configured, or the configured file yields no certificate). `nlohmann::json` serialises object keys alphabetically, so on
the wire `ca_generation` lands between `agent` and `settings_hash`, exactly as in the examples above.

**Response with tasks (`200 OK`):**
```json
{
  "agent": {
    "groups": ["web-servers"],
    "config_token": "web-servers",
    "config_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "ca_generation": 1758000000,
  "settings_hash": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
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
  ],
  "vd_feed_offset": 12345678
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
  hostname, etc.), keepalives, status codes and connection status via `global update-agent-data`,
  `update-keepalive`, `update-status-code` and `update-connection-status` queries with a JSON
  argument, and reads back the agent's groups with `global select-agent-group <id>`. Dedicated worker threads with bounded request queues and async I/O
  prevent blocking the HTTP worker threads.
- **task-manager** (`queue/sockets/task-http.sock`): Task delivery. The handler sends
  `POST /v1/tasks/pending` with `{"agent_id":"001"}`; that route hands over the agent's pending tasks
  and marks them delivered, and they are included in the response. A failed fetch answers `200`
  with an empty `tasks` array. Task state is local to the node; cluster broadcast is handled separately
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
(`notify` every 10 seconds per agent). Entries idle for 6 hours are evicted by a sweep that runs
every 300 seconds.

### Error handling

Authentication (`401`) and transport rejections (`413`, `429`, `503` when shed) follow the same
pattern as `/stateless` (see [Error responses](#error-responses) above). The endpoint's own
rejections below do **not**: their body is `{"error":"<code>"}` alone, with no numeric `code` member,
and the `503` adds the dependency that is not answering —
`{"error":"dependency_unavailable","dependency":"wazuh-db"}`.
Control-specific conditions:

| Condition                                  | HTTP  | `error` message        |
| ------------------------------------------ | ----- | ---------------------- |
| Body empty or exceeds 64 KiB               | `400` | `invalid_body`         |
| Malformed JSON body                        | `400` | `invalid_json`         |
| Invalid agent ID format                    | `400` | `invalid_agent_id`     |
| Unknown message type                       | `400` | `unknown_message_type` |
| Malformed agent version (startup only)     | `400` | `invalid_version`      |
| Agent version higher than allowed (startup only) | `409` | `invalid_version` |
| `host` block invalid (notify only): `host` or `host.os` not an object, a `host`/`host.os` field not a string, or a string over its bound (hostname 255, ip 45, the others 128 bytes); an absent or `null` field is accepted | `400` | `invalid_host_info` |
| wazuh-db unavailable (get groups)          | `503` | `dependency_unavailable` |

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

The scan is recorded as a durable task and **will run** (see [Scan dispatch](#scan-dispatch)
below) — the `200` is relayed from VD's own admission answer, never invented on this side. The agent should consider the offset it sent as handled — it clears
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

Like `/control`'s own rejections, every row below answers `{"error":"<code>"}` with no numeric
`code` member (the `409` adds `current_version`); only the authentication and transport rejections
take the `/stateless` shape described in [Error responses](#error-responses).

| Condition                                        | HTTP  | `error` message                                               |
| ------------------------------------------------ | ----- | ------------------------------------------------------------- |
| Body empty or exceeds 4 KiB                      | `400` | `invalid_body`                                                |
| Malformed JSON body                              | `400` | `invalid_json`                                                |
| Invalid agent ID format                          | `400` | `invalid_agent_id`                                            |
| Missing or non-string `type`                     | `400` | `missing_type`                                                |
| `type` other than `"feed_update"`                | `400` | `invalid_type`                                                |
| Missing or non-unsigned `feed_offset`            | `400` | `missing_feed_offset`                                         |
| `feed_offset` != current offset                  | `409` | `version_mismatch` (carries `current_version`)                |
| VD's pending-scan queue at capacity              | `503` | `scan_queue_full`                                             |
| Indexer not usable (no healthy host)             | `503` | `indexer_unavailable`                                         |
| VD not ready (feed mid-update, scanner starting) | `503` | `feed_not_ready` / `scanner_not_ready` / `vd_not_initialized` |
| VD could not record the scan task                | `503` | `task_create_failed`                                          |
| VD unreachable, or any other VD answer           | `503` | `vd_unreachable` / `vd_error`, or VD's own error code         |

Every `503` means the same thing to the agent — not accepted, retry on the next notify cycle —
and its pending state survives; the `error` code exists so an operator reading the exchange sees
the actual cause. During a long indexer outage the agent keeps re-requesting on each notify and
the scan runs once the indexer becomes available again. Auth failures (`401`) reuse the same
responses as `/stateless`. This endpoint's body cap (4 KiB) is far tighter than `/control`'s
(64 KiB) since a scan request only ever carries `type` and `feed_offset`.

### Scan dispatch

remoted holds no scan state: after the offset gate it makes one inline
`POST /vulnerability-detector/scan` to the `vulnerability_scanner` module (over the same UDS
socket `VdClient` uses), which answers at **admission**. VD first checks its readiness — feed
loaded, scanner initialized, and the indexer's health (at least one host green or yellow and not
throttled with HTTP 429, from the indexer connector's periodic health poll); with no such host it answers `503
indexer_unavailable` instead of admitting. It then records the scan as a durable `vd_scan`
[manager task](../task_manager/manager-tasks.md) in the Task Manager: one pending scan per agent
(a repeated request coalesces into it and is still answered `200`), at most one running at a time,
and a bounded number pending (`scan_queue_full` beyond it). A recorded scan cannot go stale: it
carries no offset, so it always runs against the feed that is current at execution time. remoted
relays VD's error code inside a `503` and never retries — the agent's notify cycle is the retry
loop, with no second one hidden behind it.

The Task Manager dispatcher runs the task against the inventory sync server; if the indexer is
unavailable when the scan runs, the task is retried under the Task Manager's retry policy rather
than dropped (see [Retry, deferral and giving up](../task_manager/manager-tasks.md#retry-deferral-and-giving-up)).

Duplicate scans across different nodes (the agent asks node A, doesn't get a timely reply, and asks
node B too) are accepted as a rare, low-impact trade-off rather than solved with cross-node
coordination.

Disconnected agents (never reachable, so they can never notice `vd_feed_offset` or call this
endpoint themselves) are not covered by `/scan/vd` at all — they're swept separately, once per feed
update, by the cluster's master node only (`VulnerabilityScannerFacade::rescanDisconnectedAgents()`
in the `vulnerability_scanner` module).

## Enrollment endpoint (`POST /enroll`)

`/enroll` lets a new agent register over the same HTTPS channel (port 1517) it uses for everything
else afterward, instead of falling back to legacy `authd` on port 1515 — and lets an already
enrolled agent **re-enroll under its existing id** (new key, new re-enrollment secret, nothing
removed) when it presents its re-enrollment credential. It is a **bridge, not a second
implementation**: `authd` keeps 100% of enrollment business logic (name/version/group validation,
key generation, duplicate handling, cluster forwarding on a worker, enrollment-token use counting,
re-enrollment verification); this endpoint only authenticates the request and relays it to `authd`'s
existing local socket
(`queue/sockets/auth.sock`) — the same interface the server API's agent-registration endpoints
already use. See [Authd](../authd/README.md) for what happens once a request reaches
that socket — or [the enrollment lifecycle](../authd/enrollment-lifecycle.md) for the whole path in
order, from minting a token to the agent's row reaching `global.db` — and
[`legacy_enrollment`](../authd/configuration.md#legacy_enrollment) for how an
operator can retire port 1515 while keeping `/enroll` (or disable both together via
`remote_enrollment`).

**The route is always registered**, regardless of configuration. When enrollment is
administratively disabled (`<auth><disabled>yes</disabled>`, or `<auth><remote_enrollment>no</remote_enrollment></auth>`),
it answers **`403`** rather than disappearing — a missing route (`404`) would mean "this manager
doesn't support enrollment at all," which is a different, more permanent statement than "an operator
turned this off."

### Authentication

Unlike every other endpoint on this page, `/enroll` cannot use the agent<->manager bearer (see
[Authentication](#authentication-jwt-bearer) above) — an enrolling agent has no `client.keys`
entry yet to sign with. Two credential checks apply instead, decided once at manager startup and
**independently** of each other (an operator can require either, both, or neither — see below), and
the second one — the bearer — understands **three credentials**, all `wazuh-enroll+jwt` tokens told
apart by their header's `kid`:

- **Client certificate** — purely a property of the HTTPS listener's own `verification_mode`
  (`certificate` or `full`; see [Configuration](configuration.md#https-configuration)). When
  configured, the TLS handshake validates the agent's certificate against the manager's CA
  **before the request ever reaches this endpoint** — there is nothing further for `/enroll` itself
  to check.
- **Bearer** — a token of the sibling closed profile **`wazuh-enroll+jwt`**:

  ```text
  protocol-version: 1
  Authorization: Bearer <JWS compact serialization>
  ```

  Same core as the agent token — HS256, compact base64url without padding, 4096-byte cap, the same
  time rules under the SAME two internal options
  [`remoted.jwt_max_age`](configuration.md#remotedjwt_max_age) /
  [`remoted.jwt_clock_skew`](configuration.md#remotedjwt_clock_skew) — with a different domain:

  | Part | Value |
  | --- | --- |
  | JOSE header | exactly `{"alg":"HS256","typ":"wazuh-enroll+jwt"}`, plus an **optional `kid`** that selects the key (below). A `kid` of neither shape, or any other member, is not a `wazuh-enroll+jwt` at all |
  | Claims | exactly four: `exp`, `iat`, `jti`, `nbf` (= `iat`) — **no `iss`/`sub`** in any form: a re-enrolling agent asserts its identity through `kid`, an enrolling one has none yet |
  | Key | one HKDF-SHA256 construction — `HKDF-SHA256(IKM, salt = 32 × 0x00, info = <label> ‖ 0x01, L = 32)` — with the input and label the `kid` selects; never the secret bytes themselves |

  | Header `kid` | Credential | `IKM` / `info` label | Who verifies it | When it applies |
  | --- | --- | --- | --- | --- |
  | none | the **shared enrollment password** | the password (`/etc/wazuh-manager/authd.pass`) / `WAZUH-ENROLL-JWT-KEY` | the manager the request reaches | required whenever `authd`'s [`use_password`](../authd/configuration.md#use_password) is enabled; with `use_password` off, a shared-key bearer (or no bearer at all) is ignored and the request passes |
  | a 22-character base64url string — a 16-byte **enrollment token id** | an **enrollment token** minted by the operator | the token's 16-byte secret / `WAZUH-ENROLL-TOKEN-KEY` | the manager the request reaches, **in every mode** — a presented token is never ignored, `use_password` or not — against its replica of `authd`'s token store (`/etc/wazuh-manager/enrollment_tokens.json`, written on the master and synchronized to every worker like `client.keys`); then `authd` on the master consumes one use of the token | whenever presented |
  | the agent's canonical id (`001`) | **re-enrollment** — the agent's own re-enrollment secret | the 32-byte `reenroll_secret` the agent received when it enrolled / `WAZUH-REENROLL-KEY` | **`authd` on the master node only**: the secret is stored in the master's database and nowhere else, so the manager the request reaches forwards the bearer verbatim and unverified, and `authd` judges it | whenever presented, in every mode |

  An **enrollment token** is checked in a fixed order — lookup, signature, expiry, revocation — so
  the token's state (`token_expired`, `token_revoked`) is only ever disclosed to a caller that holds
  the token's secret; an id that is not in the store (never minted, minted without a credential,
  or not yet synchronized to this node) is `token_unknown`. Before refusing an unknown id the manager
  re-reads the store once (rate-limited to one re-read per second), so a token minted on the master a
  moment earlier is picked up on a worker even ahead of the periodic reload. Uses are counted by
  `authd` alone: a token whose uses are exhausted, or that `authd` finds revoked or expired after the
  manager's own check passed, is refused with `403` and `authd`'s code (see Error handling).

  A **re-enrollment** bearer keeps the agent's id: on success `authd` rotates that agent's key and
  re-enrollment secret in place — same `id`, no removal, no deletion task, no indexer purge — and the
  response carries the new pair. The same `remoted.jwt_max_age` / `remoted.jwt_clock_skew` window
  applies; `authd` reads the same two internal options.

  A token of either profile presented to the other's verifier is rejected on its header set before
  the signature is even considered. The request body is capped by the same
  `remoted.auth_max_body_size` (5 MiB default) the agent scheme enforces — checked right after the
  `protocol-version` header, in **every** mode including Open, so an oversized body is rejected with `413` before the
  credential is looked at. The body is not part of the token (TLS protects it).

  A missing/unreadable/invalid password file fails **closed** — every shared-key request is
  rejected (`enrollment_key_unavailable`), never silently treated as if no password were required.
  The password is re-derived on change (`/etc/wazuh-manager/authd.pass` is hot-reloaded), so rotating it
  invalidates every token minted from the old one within seconds. The token store fails closed the
  same way, with one deliberate difference: an **absent** `/etc/wazuh-manager/enrollment_tokens.json` is an empty
  store (no token has been minted, or the worker has not received it yet — every token bearer is
  `token_unknown`), while a **malformed** one keeps the previously loaded tokens in service rather
  than revoking a fleet's enrollment over a corrupt or hand-edited file (visible as
  [`remoted.enroll.token_store.reload_failures.total`](metrics.md#agent-enrollment--remotedenroll)
  and `enrollment_tokens.last_reload_ok` on `GET /status`). Neither file is ever written by
  `remoted`.

Both gates failing to apply (no client-certificate requirement, no password configured) means a
request that presents no `kid` credential needs no credential at all, matching `authd`'s own behavior
on port 1515 in that configuration — an enrollment token or a re-enrollment bearer is still checked
when presented.

Every credential rejection is a `401` with the same generic message, `Invalid client authentication`,
and names its **class** twice: as the string `error.code` of the nested body and as the
`error_description` of the `WWW-Authenticate` challenge — the same vocabulary every other route uses
(see [Error responses](#error-responses)); the table under Error handling below lists the classes
`/enroll` can produce.

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
  "version": "v5.0.0",
  "groups": "default,web-servers",
  "ip": "10.0.0.15"
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `name` | yes | 2-128 chars, no leading `.`, charset `[A-Za-z0-9._-]` only — `OS_IsValidName()`, the same rule the legacy port-1515 path applies, so both enrollment paths accept exactly the same names. `authd`'s local socket separately enforces a looser *storage-safety* floor (no whitespace/control bytes, no leading `#`/`!`, ≤128 chars) for all of its callers, the API included; this endpoint holds the tighter line itself rather than relying on that floor. |
| `version` | yes | Must be well formed — an optional `v`/`V`, one to four dot-separated numbers and an optional `-`/`+` suffix of letters, digits, `.` and `-`, 64 bytes at most — or the answer is `400` (port 1515 answers `ERROR: Invalid version` to the same values). Rejected if its major or minor is higher than the manager's (a higher patch alone is accepted, as on port 1515) unless `authd`'s own `<auth><agents><allow_higher_versions>` is `yes` (not `remote`'s, which governs `/control`; this keeps `/enroll` in step with port 1515) — `authd`'s local socket performs no version check of its own, so this endpoint enforces it. |
| `groups` | no | Comma-separated, forwarded unchanged; `authd` drops repeated names. A list that names no group (`""`, `","`) is the same as no `groups` field: the agent joins `default`. Empty members next to real names (`"default,"`, `",default"`) are accepted and the agent's groups are recorded without them, whereas port 1515 refuses such a `G:` with `ERROR: Invalid group name`. |
| `ip` | no | The grammar port 1515 accepts: an IPv4 or IPv6 address, optionally a network — `/<prefix>`, or for IPv4 a dotted mask (`10.5.0.0/255.255.0.0`) that is forwarded as its prefix length (`10.5.0.0/16`), the form the registry records either way. An empty prefix (`10.0.0.0/`), a prefix past 32/128, a non-contiguous mask and a leading `!` are `400`, and port 1515 refuses the same values (`ERROR: Invalid IP`). A full-length mask (`/32`, `/128`) names a single host: it is registered as the bare address, answered in that form, and refused with `409` when another agent already holds that address, exactly like the bare spelling. Networks (`10.5.0.0/16`) are never duplicates of one another, overlapping or not. Or one of two sentinels: `any` (no override), or `src` — mirrors legacy port 1515's own wire sentinel (an agent configured with its own client-side `use_source_ip` sends this instead of a literal address); see IP resolution below. |
| `key_hash` | no | Opaque hash of the agent's current key, if it has one — drives `authd`'s force/key-mismatch decision, same as port 1515's `K:` field. |

`force`, `id`, and a raw `key` are never sent, even though `authd`'s local socket accepts all three
for admin/restore use (the server API): `/enroll` is for an agent self-enrolling (auto-assigned ID,
`authd`-generated key) or re-enrolling under its existing ID; that ID travels only as the
re-enrollment bearer's `kid`, never as a free `id` argument.

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
  "key": "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915",
  "reenroll_secret": "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
}
```

Verbatim from `authd`, five fields: the 64-hex `key` the agent must store and sign every subsequent
`wazuh-agent+jwt` bearer with, under its numeric `id`, and the 64-hex **`reenroll_secret`** — the
agent's re-enrollment credential. The agent must keep it next to the key and never send it: it is the
input of the `WAZUH-REENROLL-KEY` derivation above, the only thing that lets the agent re-enroll
later **keeping the same `id`** (after losing its key, or to rotate it) instead of appearing as a new
agent. It is handed out exactly once per enrollment; each successful re-enrollment replaces both
`key` and `reenroll_secret` with a new pair under the same `id`. The field is absent only when the
master node's `authd` predates it.

### Error handling

| Condition | HTTP | Notes |
| --- | --- | --- |
| Enrollment administratively disabled | `403` | Route always exists; see above. |
| Missing or unsupported `protocol-version` | `400` | Validated first after the disabled check, in every mode -- before the credential check and before the body-size cap, matching every other authenticated route. |
| Missing/invalid credential | `401` | Same generic message for every class; `error.code` and the `WWW-Authenticate` challenge name the class: `invalid_request` (Password mode, no usable `Authorization`), `invalid_signature` (a bearer that does not verify with its key: wrong password, wrong token secret, a token of the agent profile, a malformed token), `stale_token` (outside the accepted time window), `token_unknown` / `token_expired` / `token_revoked` (the enrollment token's own state, decided from this manager's replica of the store), `enrollment_key_unavailable` (Password mode and the enrollment password is not available on this node — bare `Bearer` challenge, retry later). See Authentication above. |
| Re-enrollment refused by `authd` on the master (9026 unknown agent or no re-enrollment credential on record / 9027 invalid credential / 9028 outside the accepted time window) | `401` | The bearer travels to `authd` unverified, so its verdict is an authentication failure: mapped onto the classes `unknown_agent` / `invalid_signature` / `stale_token` respectively, with the same generic message and challenge — `authd`'s code and text never reach the wire. |
| `authd` refused the use of a **verified** enrollment token: 9022 not found or revoked, 9023 expired, 9024 uses exhausted | `403` | `{"error":{"code":9022,"message":"Enrollment token not found or revoked"}}`, `{"error":{"code":9023,"message":"Enrollment token expired"}}`, `{"error":{"code":9024,"message":"Enrollment token uses exhausted"}}`. `403` rather than `401` because the bearer did verify — re-signing fixes nothing; the operator has to mint a new token. 9022/9023 are reachable only when this manager's replica lagged behind `authd`'s store (a revocation or expiry landing between the two checks, a worker copy not yet synchronized); 9024 is decided by `authd` alone, which owns the use counter. |
| Body exceeds `remoted.auth_max_body_size` (5 MiB default) | `413` | Checked once the protocol version is accepted, BEFORE the bearer is checked (and before a credential check, in Open mode too) -- an oversized body is rejected without ever reaching `parseAndValidateBody()`'s own smaller (16 KiB) schema check. |
| `Content-Encoding` other than `zstd` | `415` | `{"error":{"code":0,"message":"Unsupported Content-Encoding"}}`. Checked after the credential (and, for a request that verified no credential, after its rate limit), before the body is parsed. |
| `Content-Encoding: zstd` but not a valid, complete frame | `400` | `{"error":{"code":0,"message":"Malformed compressed body"}}`. Same point as the `415`. |
| Empty or over 16 KiB once decoded, malformed JSON, missing or invalid `name`/`version`, a non-string `groups`/`key_hash`, invalid `ip` | `400` | Rejected before `authd` is ever contacted. A zstd body that would decode past 16 KiB is a `413` instead. |
| Agent version newer than allowed | `400` | See `version` in the request table above. The manager logs a throttled `WARNING` naming the agent, its address and both versions. |
| `authd` bad function/args/name/ip/groups (9003–9006, 9014, 9017) | `400` | Passed through with `authd`'s own message. `9017` ("Invalid agent name") is unreachable from this endpoint in practice: `isValidName()` above is strictly tighter than the local socket's storage-safety floor, so any name `authd` would reject with `9017` was already refused locally with a `400`. It is mapped for completeness, not as a path clients should expect. |
| `authd` duplicate ip/name/id (9007/9008/9012) | `409` | The address is compared in its registered form, so `10.0.0.15/32` duplicates `10.0.0.15`. |
| `authd` internal/parse/key-generation failure (9001/9002/9009) | `500` | |
| `authd` refused a caller-supplied key or id (9019/9020) | `400` | unreachable from `/enroll` (self-enrollment never sends a key or an id); mapped for completeness |
| Any other `authd` error code | `500` | Passed through with `authd`'s own code and message. |
| `authd` `max_agents` reached (9013) | `503` | Server-wide capacity condition, not a rate limit — that one is the `429` row below. |
| Endpoint rate limit exceeded | `429` | Decided by remoted after the request passed its own checks (credential, body, version) and before `authd` is contacted, from the bucket of what the request proved: a verified password or enrollment token, or not (a re-enrollment, or no credential). Carries `Retry-After` in whole seconds. Each ceiling is node-wide, so during a mass enrollment many agents can see this at once; each retries with its own backoff. See [`https.enroll_rate_limit`](configuration.md#httpsenroll_rate_limit). |
| Re-enrollment already in progress (9030) | `409` | Retry after the pending rotation is committed; no second rotation is performed. |
| Identity transition could not be recorded (9031) | `503` | No credential is handed out. See [journal admission and recovery limitations](../authd/architecture.md#the-identity-journal). |
| Worker rejected the request (9015), or its forward to the master failed (9016, new in 5.0) | `503` | Only reachable via the local-socket bridge — see [Authd's local socket protocol](../authd/README.md#local-socket-enrollment-protocol). |
| The request never reached `authd` — it was stopping, its queue was full, or the connect itself failed | `503` | `{"error":{"code":-1,"message":"Enrollment service temporarily unavailable"}}`. Safe to retry: nothing was sent. |
| The request reached `authd` but no well-formed answer came back — an I/O error after the send, a response timeout, or an unparseable reply | `503` | `{"error":{"code":-2,"message":"Enrollment outcome unknown: the request reached authd but no answer came back in time -- it may have already been processed"}}`. `authd` may have processed the add anyway — on a worker, possibly forwarding it to and creating it on the master — before the answer was lost. Not safe to assume it did not happen; do not treat a retry under the same name as risk-free (a real add may already exist, answered later with `409`). On a re-enrollment, `authd` may already have rotated the agent's key and re-enrollment secret, so a retry signed with the previous secret gets `409` (9030) while the rotation is pending, or `401` once it is committed. |

Every error the `/enroll` **endpoint itself** produces — every row in the table above, disabled/
credential/body-size/validation/`authd` business and transport failures alike — has the shape
`{"error":{"code":<code>,"message":"<text>"}}`, distinct from every other endpoint's flat
`{"error":"<message>","code":<status>}` shape, since this one passes through `authd`'s own numeric
codes for diagnostics (`code` is `0` for the non-`authd` rows that carry no numeric code, `-1` when
the request never reached `authd`, `-2` when it reached `authd` but no clean answer came back, and — for a `401` only — the authentication failure class as a string,
exactly as on every other route).

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
| `config` | one group name | `/etc/wazuh-manager/shared/<group>/merged.mg` |
| `config` | several group names, comma-separated | `var/multigroups/<sha256(resource_id)[0..32)>/merged.mg` |
| `wpk` | a package filename | `var/upgrade/<filename>` |

The comma-separated form is wazuh's own multigroup selector, and it is what lets an agent in several
groups fetch its **effective** configuration rather than one member group's. It needs no database
lookup: the directory name is the first **32 hex characters** (the first sixteen digest bytes) of the
SHA-256 of the selector verbatim, exactly how wazuh-db names the directory (`WDB_GROUP_HASH_SIZE`).

Accepted identifiers:

- **Group name** — non-empty, at most 255 bytes, not exactly `.` or `..`, and drawn from wazuh's own
  group-name set (`a-z A-Z 0-9 . : ; _ - = + ! @ ( )`; note the absence of `/`). In a multigroup
  selector every entry must be valid on its own, which is what rejects a leading, trailing or
  doubled comma. The whole selector is capped at 4096 bytes.
- **WPK filename** — non-empty, at most 255 bytes, must **not** begin with a dot, must end in
  `.wpk`, and is drawn from a stricter set (`a-z A-Z 0-9 . _ -`).

> **A `config` download is authorized against the requesting agent's own groups.** `resource_id`
> must equal the selector `/control` handed that agent as `config_token` — the same string
> `config_hash` was computed over — and anything else is answered `403`. The manager resolves that
> selector from the agent registry `/control` already maintains, so the check costs no wazuh-db
> round trip; an agent whose membership the manager has never established (it never completed
> `/control/startup`, or its entry was evicted) is **denied, not served**.
>
> The comparison is exact, including the order of a multigroup CSV: `a,b` and `b,a` name different
> merged files, and only one of them is the file `config_hash` refers to.
>
> **`wpk` downloads are not covered.** A package's authority is the agent's pending upgrade task,
> which `/control` does not carry, so any authenticated agent can still fetch any *staged* package.
> Stock packages are Wazuh-signed and the agent verifies them against `wpk_root.pem` before
> installing, which bounds what an unauthorized fetch discloses to *which* package is staged —
> operator-built custom packages are the exception to that reasoning. Closing this properly means
> task-based authorization and is tracked separately.

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
| `resource_type: config` and `resource_id` is not the requesting agent's own selector, or the manager has no established membership for it | `403` | `Forbidden` |
| Resource absent, not a regular file, or `O_NOFOLLOW` rejected a symlink | `404` | `Resource not found` |
| Unexpected `errno` while opening or stat-ing | `500` | `Internal server error` |

The `403` is decided **before** the path is resolved, so a group the agent is not in reads exactly
the same whether or not it exists on the manager — there is no 200-vs-404 oracle for enumerating
group names. Note that a `403` on this route can also come from the shared transport rather than
this endpoint, in mTLS mode, when the client certificate does not match the connecting peer's
address; that one carries its own message and applies to every route.

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
and one carrying its effective **configuration**. The two ship with **different** defaults (the agent's
`<agent><stats_report>` / `<agent><config_report>` options, each with `<enabled>` and `<interval>`):

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

Both bodies require a nonempty `modules` object whose values are objects; a malformed report is rejected downstream with a
`400` (see [Error handling](#error-handling-4)):

**`POST /stats`** — an object keyed by module:

```json
{"modules": {"agent": {}, "logcollector": {}}}
```

`modules` is moved under `wazuh.agent.statistics` untouched: nothing renames a metric or reshapes a
module's body, since only the agent knows which of its counters are cumulative.

**`POST /config`** — an object keyed by module, using the same envelope:

```json
{"modules": {"fim": {}, "logcollector": {}}}
```

The `modules` object becomes `wazuh.agent.configuration.content`, with
`wazuh.agent.configuration.modules` derived from its keys.

On both routes the agent's reporter also writes `agent_id`, `cluster` and an `agent` object at the
root. `agent` is the same block the `/stateless` header carries, with the agent's groups and host:

```json
{"agent": {"groups": ["default"],
           "host": {"architecture": "x86_64", "hostname": "web-01",
                    "os": {"name": "Ubuntu", "platform": "ubuntu", "type": "linux", "version": "24.04"}}}}
```

The sync server copies `agent.groups` and `agent.host` into `wazuh.agent.groups` and
`wazuh.agent.host`, field by field; a value that fails validation is left empty instead of rejecting
the report. Every other root member is dropped.

A report is **all or nothing** on both routes: one malformed module rejects the whole document rather
than indexing a partial report the agent could not tell apart from a complete one.

### Responses

Both routes acknowledge the report with an empty JSON object:

| | `POST /stats` | `POST /config` |
| --- | --- | --- |
| `200 OK` body | fixed `{}` | `{}` from the sync server, passed through |

`/stats` answers a fixed body on purpose: the agent has nothing to read back, and a constant keeps an
arbitrary downstream string off the wire. `/config` relays a successful downstream body, so its
`{}` acknowledgement depends on the sync server's contract. On **failure** both routes collapse
the downstream body to a fixed local message.

> **A `200` means accepted, not indexed.** The sync server answers before the indexer write completes
> (the write is fire-and-forget), so an indexer-side rejection is **silent** to the agent, which
> already has its `200`. Both `wazuh-agent-stats` and `wazuh-agent-config` are mapped
> `dynamic: strict_allow_templates`. A module, metric or key the template does not declare under
> `wazuh.agent.statistics` or `wazuh.agent.configuration.content` is mapped by a dynamic template from
> the type of its first value (object, boolean, long, double, or `keyword` for a string), so an
> agent-side addition needs no change to this endpoint, and none in the index template. A key outside
> those paths, or a value whose type conflicts with the existing mapping, makes the indexer reject the
> whole document, and the previous one stays. Watch the sync server's own metrics rather than the
> agent's response to confirm ingestion.

### Error handling

| Condition | HTTP | `error` message |
| --- | --- | --- |
| Empty body | `400` | `Empty request body` |
| Sync server rejected the document | `400` | `Invalid stats document` / `Invalid config document` |
| Body over the auth body limit | `413` | `Request payload is too large` |
| Sync server unreachable, no timely answer, or any 5xx/unexpected status | `503` | `Service unavailable` |

Every `503` means the same thing to the agent: not accepted, retry on the next reporting interval.
Auth failures reuse the same responses as `/stateless`. Neither route is timed in the
`remoted.http.*.latency` histograms — they share `/stateful`'s downstream and produce no new answer of
their own; see [Metrics](metrics.md).

## CA certificate endpoint (`GET /cacerts`)

The listener's certificate is signed by the deployment's CA, `/etc/wazuh-manager/certs/root-ca.pem`: the credential
resolver installs the CA and issues a CA-signed `remoted.pem` at installation, or the operator
provisions both, for instance with the installation assistant's `wazuh-certs-tool` (see
[Certificate provisioning and fail-closed start](#certificate-provisioning-and-fail-closed-start));
the CA is configured as [`remote.https.ca_certificate`](configuration.md#httpsca_certificate). `GET /cacerts` hands that
CA out, so an agent can bootstrap trust in the manager — fetch the CA once, then verify every later
connection against it — without an out-of-band copy of the PEM.

**No authentication, no `protocol-version`, no body.** By construction the caller holds no
credential yet. Anything sent besides the target (a body, an `Authorization` header) is ignored. The
route is exempt from the in-flight byte budget like `GET /`, so the bootstrap is never shed under
memory pressure, and it is served under the [global prefix](#endpoints) like every other route
(`GET /wazuh-manager/cacerts` with the shipped configuration; the bare path answers `404`).

| Outcome | HTTP | Body | Meaning |
| --- | --- | --- | --- |
| Served | `200` | re-serialised certificates, `Content-Type: application/x-pem-file`, plus a `Wazuh-CA-Generation` header (the same value as `ca_generation` on `/control`, `0` when no guard vouched for the bundle) | The CA the listener chains to. A bundle is served as a bundle; private keys and other non-certificate material are omitted |
| No CA | `404` | `{"error":"not_found"}` | The configured file was never readable -- missing, unreadable, too large, or otherwise unparsable -- or it is readable but contains no usable certificates (an emptied file). A file that stops being readable after it was served keeps serving the last good bundle instead. Same body as an unknown route; the manager logs the failure |
| Incoherent CA | `503` | `{"error":"ca_mismatch"}` | The certificate this listener is serving does **not** chain to the configured CA. Refused rather than served: handing it out would make every verifying agent fail its handshake against this very manager |
| Rate limited | `429` | `{"error":"rate_limited"}` + `Retry-After` | Over [`remote.https.cacerts_rate_limit`](configuration.md#httpscacerts_rate_limit) |

**What the coherence check compares.** The leaf is the certificate loaded into the TLS context when
the listener started (constant until a restart); the CA is re-read from disk at each evaluation,
and every `CERTIFICATE` block in the file is offered as a trust anchor — the CA is coherent when the
leaf builds a valid **chain** to *any* of them, so a bundle carrying the issuing CA plus others
passes. It is a full validation (`X509_verify_cert()` with OpenSSL's default flags, the bundle as
its sole trust store), which means:

- a CA that merely **signs** the leaf is not enough: the leaf's own issuer has to be there, so a
  certificate holding the CA's key under a different subject does not count;
- the **validity windows** and the `basicConstraints`/`keyUsage` of everything on the path are
  checked, so an expired CA, a not-yet-valid one, one without `CA:TRUE` — or an expired leaf — make
  the file incoherent;
- the anchor must be **self-signed**, because that is what an agent's own OpenSSL trusts by default,
  so a bundle carrying only a (non-self-signed) intermediate is refused even though that
  intermediate signed the leaf.

None of these could serve a verifying agent, which is why they are refused rather than served
(issue #39319; before this the check was a bare signature and such a bundle was served and even
announced as published).

The manager separately validates the same chain with the server **purpose** added and the anchor
rule relaxed (an anchor need not be self-signed), and logs the result at startup and on every daily
evaluation: a `WARN` when the leaf chains to the bundle and yet fails as a *server* certificate (the
wrong extended key usage, say), an informational line when it only validates because a certificate
of the bundle was treated as an anchor without being self-signed. Neither outcome changes this
endpoint's response.

**Cadence.** Each request reads the CA file and obtains the certificate bundle and coherence verdict
from the same snapshot. Parsing is cached by a hash of those bytes; a changed file is re-parsed even if
its size and modification time stay the same. The verdicts are not cached: the chain validation, and
with it the `503` decision and the published generation, are judged against the clock on every
evaluation from the certificates already parsed. A CA that **expires while the file is untouched**
therefore answers `503` from the next request on (and `ca_generation` drops to `0`), and a CA whose
`notBefore` was still ahead of this node's clock is served, and published, from the request after its
window opens. Either flip is logged once, within a minute: besides the requests, the listener
judges the bundle again every 60 seconds on its own. This matters for the expiry, because an agent
that verifies the manager fails its TLS handshake against an expired CA and never sends the request
that would notice it. A CA file that cannot be
read keeps the last good bundle in service and logs the failure; only a file that was never readable
answers `404`, and a file that reads but carries no certificate answers `404` at once. A replacement
CA the loaded leaf does not chain to answers `503` on the next request. Separately, the certificate
monitor runs at startup and every 24 hours, logging expiry and coherence findings. Rotate the CA and
listener certificate together and restart remoted to load the new leaf. Replace the CA file
atomically (write a sibling, then rename it over the path): a file caught half-written is readable,
and a readable file with no certificate answers `404` at once.

**Trust on first use.** The channel the CA travels over is, by definition, not yet verified. An
agent that already holds a CA MUST NOT replace it from this route, and a deployment that can
distribute the CA out of band SHOULD.

**Observability.** `remoted.cacerts.{served,not_found,ca_mismatch,rate_limited}` count the outcomes,
`remoted.http.cacerts.responses.*` the statuses, and the two `remoted.server.tls.*` pulls publish the
evaluation itself (`cert_expiry_days`, negative once expired, and `ca_matches_leaf`) — see
[Metrics](metrics.md#tls-listener-certificate--remotedservertls).

## Testing

`src/remoted/remoted_module/tools/send_stateless.py` mints the `wazuh-agent+jwt` bearer and sends
`POST /stateless` requests the way the manager verifies them (shared `wire_jwt.py`, pure Python
standard library, key read from `client.keys`; `python3 wire_jwt.py --self-test` reproduces the frozen
vectors). Requires `pip install -r requirements.txt` (in the same `tools/` directory).

Run the following examples from `src/remoted/remoted_module/tools/` with an account that can read
the manager's files. Authenticated senders need an existing `client.keys` entry: most default to
agent `1001`; the download sender defaults to `001`. Override `--agent-id` for your test agent.
The senders read the global prefix from the local manager's XML configuration; when running
elsewhere, pass `--global-prefix /wazuh-manager` for the installed default (or your configured prefix).

```bash
# one valid request -> 202
python3 send_stateless.py --agent-id 1001

# corrupt the token's signature -> 401 (invalid_signature)
python3 send_stateless.py --agent-id 1001 --tamper

# run every success/failure scenario and check the expected status codes, including
# Content-Encoding: zstd (valid, malformed, and a body decompressing to about 6 MiB -- accepted:
# the 5 MiB wire cap does not apply to the decoded body, which is capped at 32 MiB instead) and the
# unsupported gzip
python3 send_stateless.py --all
# options: --url (default https://127.0.0.1:1517), --body, --client-keys
```

`src/remoted/remoted_module/tools/send_control.py` does the same for `POST /control`:

```bash
# a startup, a notify (optionally with host metadata) and a shutdown -> 200
python3 send_control.py --url https://127.0.0.1:1517 --type startup
python3 send_control.py --url https://127.0.0.1:1517 --type notify --with-host
python3 send_control.py --url https://127.0.0.1:1517 --type shutdown

# corrupt the token's signature -> 401 (invalid_signature)
python3 send_control.py --url https://127.0.0.1:1517 --type startup --tamper

# run every success/failure scenario
python3 send_control.py --url https://127.0.0.1:1517 --all
# options: --url (default https://127.0.0.1:1517), --agent-id, --client-keys, --version
```

`src/remoted/remoted_module/tools/send_scan_vd.py` does the same for `POST /scan/vd`, and can
discover the manager's current offset for you instead of guessing it:

```bash
# looks up the current vd_feed_offset via /control, then sends a matching request -> 200
python3 send_scan_vd.py --url https://127.0.0.1:1517 --auto-offset

# 409 if the manager's offset differs from 1; prints current_version to retry with
python3 send_scan_vd.py --url https://127.0.0.1:1517 --feed-offset 1

# run every success/failure scenario (missing/invalid type, missing/negative feed_offset,
# oversized body, auth failures, ...), including the matching- and mismatched-offset cases
python3 send_scan_vd.py --url https://127.0.0.1:1517 --all
# options: --url (default https://127.0.0.1:1517), --agent-id, --client-keys
```

`src/remoted/remoted_module/tools/send_download.py` exercises `POST /download`. Its configuration
selector defaults to `default`; it does not discover the agent's groups:

```bash
# fetch selector default for agent 001 -> 200 + streamed body (requires matching /control state)
python3 send_download.py --url https://127.0.0.1:1517 --agent-id 001

# a staged WPK package
python3 send_download.py --url https://127.0.0.1:1517 --resource-type wpk --resource-id wazuh_agent_v5.0.0_linux_x86_64.wpk

# run every success/failure scenario (bad type, rejected identifier, unknown group -> 403, ...)
python3 send_download.py --url https://127.0.0.1:1517 --all

# concurrency + memory check: N agents downloading at once, sampling remoted's RSS
python3 send_download.py --url https://127.0.0.1:1517 --simulate 50 --repeat 4 --selectors 'default;web,prod' --watch-rss
# options: --url (default https://127.0.0.1:1517), --manager-home, --resource-id, --unknown-group,
#          --other-group (default databases), --selectors, --simulate N, --repeat, --watch-rss
```

Use the `agent.config_token` from `/control` as `--resource-id` when the selector is not `default`.
Simulated agents must already exist and have matching `/control` registry groups. For `--all`,
stage a WPK first; `--wpk` chooses that scenario's filename and is not used by a single download.

`src/remoted/remoted_module/tools/send_agent_json.py` covers the two reporting routes, `POST /stats`
and `POST /config`, with the same bearer:

```bash
# one /stats report -> 200 + {}
python3 send_agent_json.py

# the same against /config -> 200 + {}
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
#          --password-file /etc/wazuh-manager/authd.pass (requires an explicit path),
#          --timeout (default 20 s)
```

`src/remoted/remoted_module/tools/auth_class_matrix.py` checks, on the manager itself and as root,
that each of the eight `401` classes listed under [Error responses](#error-responses) comes back
with its status, `error.code` and `WWW-Authenticate` challenge. Two of its cases change manager
state and put it back: it mints enrollment tokens through `authd` (left in the store, revoked or
expired) and moves `/etc/wazuh-manager/authd.pass` aside for one request.

```bash
sudo python3 auth_class_matrix.py --url https://127.0.0.1:1517 --global-prefix /wazuh-manager
```

## References

- [Event Protocol Specification](event-protocol.md) — the `H`/`E` wire format for event batches.
- [Configuration](configuration.md) — classic `remoted` (`<remote>`) options and internal options.
- [Architecture](architecture.md) — where the HTTPS listener sits in the `remoted` pipeline.
- [Authd](../authd/README.md) / [Authd Configuration](../authd/configuration.md) — the enrollment
  service `/enroll` bridges to, and the `remote_enrollment`/`legacy_enrollment` flags that gate
  both enrollment paths.
- Endpoint contract: [`agent-api.yaml`](agent-api.yaml) (ReDoc viewer: `agent-api-reference.html`,
  next to it in the book).
