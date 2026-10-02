# 04 — Wire protocol

Three transports: enrollment (TCP, plain text over TLS), the agent-facing HTTPS API, and the
module's local Unix socket. None of the 4.x framing (AES/zlib/MD5 over TCP/1514) exists here.

## Enrollment (`agent` mode only)

The fleet's identities come from **`POST /enroll` on the HTTPS listener** with an enrollment-token
bearer (`--bootstrap enroll-token`, the default): the contract is
[16-enroll-https.md](16-enroll-https.md), and the sender **MUST** keep the `id` and `key` of the
`200` record as this agent's identity for the rest of the run. That is the only bootstrap that works
against a manager whose `<use_password>` is the installed default (`yes`, written by the installer's
`etc/templates/config/generic/auth.template`; the schema's own default is `false`), so it is what
the harness uses.

`--bootstrap 1515` selects the legacy path below instead, kept for comparing the two.

authd listens on **TCP/1515** with TLS. The protocol is one line in, one line out:

```text
→  OSSEC A:'bench-0001'\n
←  OSSEC K:'<id> <name> <ip> <key>'\n
```

The sender **MUST** parse the four fields of the answer and keep `<id>` and `<key>`: the key is the
64-hex secret (32 bytes) every later request's bearer token is signed with. It **MUST** treat the TLS certificate as
untrusted-but-accepted (the manager's certificate is self-signed in test environments).

A password-protected authd expects `OSSEC PASS: <password> OSSEC A:'<name>'` instead. The sender
**SHOULD NOT** implement that: this path carries no credential at all, and the answer to a manager
that wants one is the token bootstrap above, not a shared secret in the benchmark. So `--bootstrap
1515` requires an authd opened with `<auth><use_password>no</use_password></auth>`
(`prepare_manager.sh --open-1515`), and a listener that is up: `<auth><legacy_enrollment>`, which
follows `<remote><legacy><enabled>` when unset. If the manager rejects enrollment, the run **MUST**
fail loudly with the manager's own answer rather than retrying blindly (it does: exit `2`, with
authd's `ERROR` line).

`POST /enroll`'s other credential forms are not used here: the shared password (a `wazuh-enroll+jwt`
with no `kid`, HS256 with the HKDF-SHA256 key of the password; vectors under `"enroll"` in
`internal/wire/testdata/jwt_vectors.json`) and re-enrollment (`kid` = the agent's own id) both exist
in the manager's contract, and neither belongs in a fleet the harness mints from scratch.

The fleet **SHOULD** be named with a stable prefix so cleanup can find it (the sender names agents
`bench-<fleet>-<NNNN>`, and `cleanup_agents.sh` deletes `name~bench-`), and
enrollment **SHOULD** be bounded in concurrency: authd is a single-threaded acceptor, and 2000
simultaneous enrollments measure authd, not the sync path. That holds for either bootstrap — both
end at the same `authd` `add` — and is why the sender enrolls the fleet serially, before the
measurement clock starts.

## Request authentication (`wazuh-agent+jwt` bearer)

Every HTTPS request to remoted carries:

```text
protocol-version: 1
Authorization: Bearer <compact JWS>
```

The token is a JWT (RFC 7519) in the manager's closed **`wazuh-agent+jwt`** profile, self-signed by
the agent with HS256 over its client.keys secret. Nothing in it is negotiable — the manager rejects
any deviation with a uniform `401` + `WWW-Authenticate: Bearer`:

```text
header  {"alg":"HS256","kid":"<agent-id>","typ":"wazuh-agent+jwt"}          exactly these three
claims  {"exp":<iat+60>,"iat":<now>,"iss":"wazuh-agent/<agent-id>",
         "jti":"<22 chars base64url of 16 CSPRNG bytes>","nbf":<iat>,"sub":"<agent-id>"}
                                                                            exactly these six; no aud
key     the 32 bytes obtained by hex-decoding the 64-char client.keys secret — NEVER the ASCII text
```

Details that are easy to get wrong and produce an opaque `401`:

- `kid`, `sub` and the `iss` suffix carry the agent id **as client.keys spells it**: decimal,
  zero-padded to three digits (`001`). `1` is a protocol violation, not an alias.
- `iat`, `nbf`, `exp` are integer seconds; `nbf == iat` and `exp == iat + 60` (the lifetime is a
  profile constant, not a choice). The manager accepts a token while `now - iat <= jwt_max_age +
  jwt_clock_skew`, `now <= exp + jwt_clock_skew` and `iat <= now + jwt_clock_skew`
  (`checkTimeRules()` in `src/shared_modules/utils/jwt/jwtCompactGrammar.hpp`). The two knobs are
  remoted internal options, `remoted.jwt_max_age` (default 60 s) and `remoted.jwt_clock_skew`
  (default 30 s), each capped at 43200 s. A drifting clock shows up as uniform `401`s.
- base64url **without padding**, canonical (no `=`, no `%3d`, zero trailing bits); JSON compact
  with members in alphabetical order (Go's `encoding/json` over alphabetically declared structs
  produces exactly that, and so does the manager's own signer — the frozen vector proves it).
- A **fresh token per request**, retries included: new `jti`, new `iat`. Reusing a token is not an
  error within its life (the manager keeps no replay store), but the sender **MUST NOT** rely on it.
- The token binds the agent's identity only: **not** the method, **not** the target, **not** the
  body. Compression, the global prefix and the query string are invisible to authentication. A
  prefix mismatch is therefore always a `404` (the route does not exist), never a `401`.
- Duplicated `Authorization` or `protocol-version` headers (any casing) are refused.

Reference implementations to check a Go port against, byte for byte:
`src/shared_modules/utils/jwt/jwtRequestTokenSigner.hpp` (the agent's and the manager's shared
signer), `src/remoted/remoted_module/tools/wire_jwt.py` (Python stdlib), and the manager's verifier
in `src/shared_modules/utils/jwt/jwtRequestTokenVerifier.hpp`. The frozen vectors all three share
are `internal/wire/testdata/jwt_vectors.json` (mirror of `src/shared_modules/utils/jwt/testVectors.hpp`):
`jwt_test.go` reproduces the vector token byte for byte from the vector key, id, `iat` and `jti`,
which is the interoperability proof — no manager needed.

## HTTPS to remoted (`agent` mode)

- Default port **1517**, TLS. The manager does not require a client certificate by default, so the
  sender **MUST NOT** need one; it **MUST** accept the server certificate without verification
  (equivalent of `InsecureSkipVerify`) since test managers are self-signed.
- Routes used: `POST /control` (see [03](03-control-protocol.md)), `POST /stateful` with
  `Content-Type: application/octet-stream` and the FlatBuffers body, `POST /stateless` with the
  H/E log-event batch (see [13](13-engine-event-streams.md)) when the scenario has an engine lane,
  and, when a scenario has the matching step, `POST /scan/vd` ([14](14-scan-vd.md)),
  `GET /cacerts` ([15](15-cacerts.md)) and `POST /enroll` ([16](16-enroll-https.md)).
- All of those routes are served under the manager's global endpoint prefix
  (`<remote><https><global_prefix>`, default `/wazuh-manager/`), and `--global-prefix` **MUST**
  match it exactly (a mismatch is a `404`, see above). The sender's own default is no prefix;
  `run_benchmark.sh` fills the flag from the local manager's configuration. The uds transport is
  never prefixed: the module's socket is not published under the manager's prefix, so
  `NewUDSClient` takes no prefix at all.
- The sender **MUST NOT** send `X-Wazuh-Agent-Id` on `/stateful`: remoted sets it from the identity
  it authenticated, and the server rejects a session whose `Start.agentid` disagrees with it (`403`).
- Connection reuse across requests of one agent is **RECOMMENDED** (HTTP keep-alive), but the run
  **MUST** record whether it was used: it changes the connection-establishment cost materially and
  therefore the comparability of two runs.

### Content-Encoding: zstd (`agent` mode only)

remoted accepts zstd-compressed request bodies on every authenticated route
(`remoted.http_content_encoding_enabled`, on by default). The sender compresses `/stateful`
sessions **by default in agent mode** — it is what a real 5.x agent does — resolved per transport
from the scenario's `defaults.compression` (`""`/absent = the per-transport default, `"none"` =
off, `"zstd"` = forced) or the `--compression zstd|none` CLI override. The contract has three
load-bearing points:

- **Authentication ignores the body**: the bearer token binds the agent's identity, not the bytes,
  so compression and authentication are independent (compress first or last, same token).
- remoted answers `415` to any other encoding value (or when the feature is disabled), `400` to a
  body that is not a valid zstd frame, and `413` when the decompressed payload does not fit its
  in-flight memory budget. The feature switch is the remoted internal option
  `remoted.http_content_encoding_enabled` (default `1`, `src/remoted/src/secure.c`). It
  **decompresses before relaying**: the inventory sync server receives plaintext with no
  `Content-Encoding` header.
- The UDS ingress has **no decoder**, so in `uds` mode the default resolves to plain bodies; only
  an EXPLICIT `"zstd"` in a uds scenario (a contradiction) is refused at load, rather than letting
  the server answer `400` to FlatBuffers verification of compressed bytes.

This is not an optimization detail: the full-fidelity Windows FIM first sync (~26 MB in one
session) exceeds both of remoted's body caps uncompressed. The authenticated-body cap is
`remoted.auth_max_body_size` (default 5 MiB, `src/remoted/src/secure.c`), answered `413`. The
transport cap is `<remote><https><max_body_size>` (when absent, the module default of 10 MiB in
`src/remoted/remoted_module/src/http_server/httpServerConfig.cpp`), past which the connection is
closed with no response at all. That session only exists on the wire *because* of zstd (~3 MB
compressed), which is the payload class remoted's support was built for. Uncompressed, a 26 MB body
is over the transport cap, so the client sees the connection close (recorded in
`transport_errors`); a body between 5 and 10 MiB gets the `413`. `bytes_sent` counts the wire
(compressed) bytes; `meta.compression` records the mode.
`raw` steps are never compressed: their deliberately invalid bodies must arrive byte-exact.

## HTTP over the Unix socket (`uds` mode)

The module's socket is `queue/sockets/inventory-sync-http.sock`, relative to the manager's home. The
peer contract is narrow and the sender **MUST** follow it exactly:

- HTTP/1.1, `Content-Length` delimited — chunked transfer encoding is answered `411`.
- **One request per connection**, `Connection: close`; no pipelining.
- `X-Wazuh-Agent-Id` is set by the sender here (there is no remoted to set it).
- Routes: `POST /stateful`, `POST /_internal/agents/delete`, and `GET /metrics` for the
  monitor's scrape.

Two operational notes learned the hard way:

- The socket path is subject to the `AF_UNIX` `sun_path` limit (~108 bytes). A run whose working
  directory is deep enough will fail to connect with a confusing error; the sender **SHOULD**
  validate the path length up front and say so. **Not implemented:** the sender does not check it,
  and an over-long `--socket` shows up as transport errors (which fail a `uds` run).
- Writing the head and the body as a single write is **RECOMMENDED**. It is not required by the
  server, but a request split across segments exercises a different server-side path — one that hid
  a genuine race until F9b — so a benchmark that always coalesces measures less than it thinks.
