# 04 — Wire protocol

Three transports: the agent-facing HTTPS API (which also carries the default enrollment,
`POST /enroll`), authd's legacy enrollment listener (TCP/1515, plain text over TLS, only with
`--bootstrap 1515`), and the module's local Unix socket. None of the 4.x framing (AES/zlib/MD5 over
TCP/1514) exists here.

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
  match it exactly (a mismatch is a `404`, see above). The sender normalizes the value once (`""`
  and `/` mean none; otherwise one leading `/`, no trailing one, as `meta.global_prefix` records)
  and only warns about a prefix the manager would refuse (`internal/wire/prefix.go`). The sender's
  own default is no prefix; `run_benchmark.sh` fills the flag from `<global_prefix>` in the local
  manager's configuration only when that tag is present — against a manager relying on the default
  `/wazuh-manager/`, pass it explicitly. The uds transport is never prefixed: the module's socket is
  not published under the manager's prefix, so `NewUDSClient` takes no prefix at all.
- The sender **MUST NOT** send `X-Wazuh-Agent-Id` on `/stateful`: remoted sets it from the identity
  it authenticated, and the server rejects a session whose `Start.agentid` disagrees with it (`403`).
- Connection reuse across requests of one agent is the default (HTTP keep-alive; `--no-reuse`
  turns it off), and the run records which it used in `meta.connection_reuse`: it changes the
  connection-establishment cost materially and therefore the comparability of two runs.

### Content-Encoding: zstd (`agent` mode only)

remoted accepts zstd-compressed request bodies on its authenticated routes (the contract, caps and
status codes are in
[remoted's https-events-api.md](../../../../docs/ref/modules/remoted/https-events-api.md#content-encoding-zstd)).
The sender compresses `/stateful` session bodies — and nothing else — **by default in agent mode**,
because that is what a real 5.x agent does. The effective mode resolves from `--compression
zstd|none` when given, else from the scenario's `defaults.compression` (`""`/absent = the
per-transport default, `"none"` = off, `"zstd"` = forced); `meta.compression` records the result
(`"zstd"` or `""`). Each body is one zstd frame with its decompressed size declared
(`internal/wire/zstd.go`), sent with `Content-Encoding: zstd`.

- **Authentication ignores the body**: the bearer token binds the agent's identity, not the bytes,
  so compression and authentication are independent.
- The UDS ingress has **no decoder**, so in `uds` mode the default resolves to plain bodies; an
  EXPLICIT `"zstd"` in a uds scenario, or `--compression zstd` with uds, is refused at load
  (exit `2`) rather than letting the server answer `400` to FlatBuffers verification of compressed
  bytes.
- `raw` steps are never compressed: their deliberately invalid bodies must arrive byte-exact.
- `bytes_sent` counts the wire (compressed) bytes.

This is not an optimization detail: the full-fidelity Windows FIM first sync (~27 MB of JSON in one
session, a few MB compressed) exceeds both of remoted's wire caps uncompressed. Over the 5 MiB
authenticated-body cap (`remoted.auth_max_body_size`) remoted answers `413`; over the transport cap
(`<remote><https><max_body_size>`, 10 MiB by default) it closes the connection without a response,
which the sender records in `transport_errors`. Compressed, the same session is under both, and its
decoded size is under remoted's separate decoded-body cap (`remoted.auth_max_decoded_body_size`,
32 MiB by default).

## HTTP over the Unix socket (`uds` mode)

The module's socket is `queue/sockets/inventory-sync-http.sock` under the manager's home
(`INV_SYNC_SOCK` in `src/shared/include/defs.h`); `--socket` takes its path, relative to the
sender's working directory. The peer contract is narrow and the sender follows it
(`NewUDSClient` in `internal/wire/client.go`):

- HTTP/1.1, `Content-Length` delimited — the server answers chunked transfer encoding `411`, and
  the sender never sends it (every body is a whole buffer).
- **One request per connection**: keep-alive is disabled, so every request carries
  `Connection: close`; no pipelining.
- `X-Wazuh-Agent-Id` is set by the sender on `/stateful` (there is no remoted to set it).
- Routes the sender uses: `POST /stateful` and `POST /_internal/agents/delete` (whose agent id
  travels in the body, [02](02-functional-requirements.md#deletion-and-control)). The module's
  `GET /metrics` is scraped by the orchestration, never by the sender.

Two operational notes learned the hard way:

- The socket path is subject to the `AF_UNIX` `sun_path` limit (~108 bytes). The sender does not
  check it: an over-long `--socket` shows up as transport errors, which fail a `uds` run.
- How the head and body reach the socket (one write or several) is decided by Go's `net/http`, not
  by the sender. A request split across segments exercises a different server-side path — one that
  hid a genuine race until F9b — so this is worth remembering when a run looks cleaner than
  expected.
