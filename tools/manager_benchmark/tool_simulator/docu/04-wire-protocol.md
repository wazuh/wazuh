# 04 — Wire protocol

Three transports: enrollment (TCP, plain text over TLS), the agent-facing HTTPS API, and the
module's local Unix socket. None of the 4.x framing (AES/zlib/MD5 over TCP/1514) exists here.

## Enrollment (`agent` mode only)

authd listens on **TCP/1515** with TLS. The protocol is one line in, one line out:

```text
→  OSSEC A:'bench-0001'\n
←  OSSEC K:'<id> <name> <ip> <key>'\n
```

The sender **MUST** parse the four fields of the answer and keep `<id>` and `<key>`: the key is the
hex-encoded AES key every later request is signed with. It **MUST** treat the TLS certificate as
untrusted-but-accepted (the manager's certificate is self-signed in test environments).

A password-protected authd expects `OSSEC PASS: <password> OSSEC A:'<name>'` instead. The sender
**SHOULD NOT** implement that: the orchestration prepares the manager with
`<auth><use_password>no</use_password></auth>`, and requiring a password in a benchmark only adds a
shared secret to the run. If the manager rejects enrollment, the run **MUST** fail loudly with the
manager's own answer rather than retrying blindly.

The fleet **SHOULD** be named with a stable prefix (`bench-<n>`) so cleanup can find it, and
enrollment **SHOULD** be bounded in concurrency: authd is a single-threaded acceptor, and 2000
simultaneous enrollments measure authd, not the sync path.

## Request signing (AES-CMAC)

Every HTTPS request to remoted carries:

```text
protocol-version: 1
Authorization: Wazuh <agent-id>:<unix-timestamp>:<mac>
```

`<mac>` is the AES-CMAC of the canonical byte sequence below, hex-encoded **lowercase**, exactly 32
characters (the manager parses that length strictly). The key is the enrollment key decoded from hex
to raw bytes, and its length **MUST** be 16, 24 or 32 bytes (AES-128/192/256).

```text
"WAZUH-REQUEST\n"
<protocol-version> "\n"      e.g. "1\n"
<METHOD> "\n"                uppercase, e.g. "POST\n"
<request-target> "\n"        exactly as sent, query string included, e.g. "/stateful\n"
<agent-id> "\n"              the SAME string used in the Authorization header, e.g. "001\n"
<timestamp> "\n"             the SAME decimal string used in the header
<body>                       the exact request bytes, with NO trailing newline
```

Details that are easy to get wrong and produce an opaque `401`:

- The body is appended raw, with no separator after it.
- The agent id and the timestamp are hashed as the strings that appear in the header. Sending `001`
  in the header and hashing `1` fails.
- The method is uppercase; the target is the raw target, not a normalized path.
- The timestamp **MUST** be within the manager's window: at most 300 s old and at most 30 s in the
  future by default. A sender whose clock drifts will see uniform `401`s.

Reference implementations to check a Go port against, byte for byte:
`src/remoted/remoted_module/tools/send_stateless.py` (`sign_request()`) and the manager side in
`src/remoted/remoted_module/src/auth/authMiddleware.cpp`. The sender **SHOULD** ship a unit test
that reproduces a known MAC from a fixed key, timestamp and body, so a regression is caught without
a manager.

## HTTPS to remoted (`agent` mode)

- Default port **1517**, TLS. The manager does not require a client certificate by default, so the
  sender **MUST NOT** need one; it **MUST** accept the server certificate without verification
  (equivalent of `InsecureSkipVerify`) since test managers are self-signed.
- Routes used: `POST /control` (see [03](03-control-protocol.md)), `POST /stateful` with
  `Content-Type: application/octet-stream` and the FlatBuffers body, and `POST /stateless` with the
  H/E log-event batch (see [13](13-engine-event-streams.md)) when the scenario has an engine lane.
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

- **The CMAC signs the COMPRESSED bytes** — they are the wire bytes. The sender therefore
  compresses *before* signing; a signature over the plaintext would be a `401`.
- remoted answers `415` to any other encoding value (or when the feature is disabled), `400` to a
  body that is not a valid zstd frame, and `413` when the decompressed payload does not fit its
  in-flight memory budget. It **decompresses before relaying**: the inventory sync server receives
  plaintext with no `Content-Encoding` header.
- The UDS ingress has **no decoder**, so in `uds` mode the default resolves to plain bodies; only
  an EXPLICIT `"zstd"` in a uds scenario (a contradiction) is refused at load, rather than letting
  the server answer `400` to FlatBuffers verification of compressed bytes.

This is not an optimization detail: the full-fidelity Windows FIM first sync (~26 MB in one
session) exceeds remoted's 10 MiB `auth_max_body_size` uncompressed — that session only exists on
the wire *because* of zstd (~3 MB compressed), which is the payload class remoted's support was
built for. Uncompressed, the cap rejects it mid-upload: the client may see the `413` or, when the
server closes before the 26 MB finish writing, a connection reset recorded in `transport_errors` —
both are the same contract. `bytes_sent` counts the wire (compressed) bytes; `meta.compression` records the mode.
`raw` steps are never compressed: their deliberately invalid bodies must arrive byte-exact.

## HTTP over the Unix socket (`uds` mode)

The module's socket is `queue/sockets/inventory-sync.sock`, relative to the manager's home. The
peer contract is narrow and the sender **MUST** follow it exactly:

- HTTP/1.1, `Content-Length` delimited — chunked transfer encoding is answered `411`.
- **One request per connection**, `Connection: close`; no pipelining.
- `X-Wazuh-Agent-Id` is set by the sender here (there is no remoted to set it).
- Routes: `POST /stateful`, `DELETE /agents` / `POST /agents/delete`, and `GET /metrics` for the
  monitor's scrape.

Two operational notes learned the hard way:

- The socket path is subject to the `AF_UNIX` `sun_path` limit (~108 bytes). A run whose working
  directory is deep enough will fail to connect with a confusing error; the sender **SHOULD**
  validate the path length up front and say so.
- Writing the head and the body as a single write is **RECOMMENDED**. It is not required by the
  server, but a request split across segments exercises a different server-side path — one that hid
  a genuine race until F9b — so a benchmark that always coalesces measures less than it thinks.
