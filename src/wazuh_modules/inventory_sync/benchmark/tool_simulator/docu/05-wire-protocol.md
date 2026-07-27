# 05 — Wire protocol

Every byte the sender emits is covered here: authd handshake, remoted
framing, crypto stack, control messages. The canonical implementation is in
`internal/wire/` — functions `RegisterAgent`, `DeriveAESKey`,
`EncryptMessage`, `DecryptMessage`, `SendEvent`, `RecvEvent`.

## 1. Authd (TCP/1515) — enrolment

The sender opens a single TLS connection per agent enrolment.

### TLS setup

- TCP connect to `<manager>:1515`.
- Wrap with TLS. Python uses `ssl.create_default_context()` then sets:
  - `check_hostname = False`
  - `verify_mode = ssl.CERT_NONE`
- Protocol: TLS 1.2 or 1.3 negotiated. No client cert.

The Go equivalent:

```go
tls.Dial("tcp", addr, &tls.Config{
    InsecureSkipVerify: true,   // manager cert is self-signed
})
```

### Request

A single line, ASCII, terminated with a newline:

```
OSSEC A:'<name>'\n
```

`<name>` is the agent's hostname-like identifier (e.g. `bench-0001-a1b2c3d4e5f6`).
The single quotes are literal. No length prefix at this layer.

### Response

```
OSSEC K:'<id> <name> <ip> <key>'\n
```

Parsing (the parser MUST be tolerant of leading whitespace and of `\r\n`):

```
trim    response
require prefix "OSSEC K:'"
require suffix "'"
split body by space  -> [id, name, ip, key]
```

Failure handling:

- If the server returns any line not starting with `OSSEC K:'`: treat as
  registration failure, retry up to 3× with 1 s back-off.
- If TLS handshake fails: same retry policy.

Close the TLS connection immediately after parsing the response.

## 2. Key derivation

Done once per agent immediately after enrolment (see `DeriveAESKey` in
`internal/wire/`).

```
sum1 = MD5(MD5_hex(name) || MD5_hex(agentid))           # 16 bytes
sum1 = sum1_hex_string[:15]                             # take first 15 hex chars
sum2 = MD5_hex(manager_key)                             # 32 hex chars (ASCII)
encryption_key = sum2 || sum1                           # 47 ASCII bytes
aes_key        = encryption_key[:32]                    # AES-256 key
```

Notes:

- `MD5_hex(x)` here means `hex(MD5(x))` — i.e. the 32-char lowercase hex
  encoding of the digest, *as bytes* in the final concatenation.
- `manager_key` is the `key` field from `OSSEC K:'…'`.
- The AES key is exactly 32 bytes (the first 32 ASCII bytes of `encryption_key`).
- The Wazuh agent code does the same derivation; do not change it.

## 3. Initialization vector

Fixed for inventory_sync messages:

```
IV = "FEDCBA0987654321"   // 16 ASCII bytes
```

Yes, this is hard-coded on both sender and manager (`os_crypto_blowfish_op.c`
+ `os_crypto_aes_op.c`). Do not parameterise it.

## 4. Remoted (TCP/1514) — frame stack

Outer to inner:

```
┌──────────────────────────────────────────────────────────────┐
│ 4 bytes  length prefix  (uint32 little-endian)               │ ← framing
├──────────────────────────────────────────────────────────────┤
│ N bytes  payload                                             │
└──────────────────────────────────────────────────────────────┘
                          │
                          v
   payload = "!<agent_id>!#AES:" || aes_ciphertext            ← header marker
                          │
                          v
   aes_ciphertext = AES_256_CBC(aes_key, IV, padded_plaintext) ← crypto
                          │
                          v
   padded_plaintext = ('!' × pad_len) || zlib_compressed       ← Wazuh padding
   where pad_len = (8 - (len(zlib_compressed) % 8)) % 8
                          │
                          v
   zlib_compressed = zlib_deflate(inner_event)                 ← compression
                          │
                          v
   inner_event = MD5_hex(msg) || msg                           ← integrity
                          │
                          v
   msg = "55555" || "1234567891" || ":" || "5555" || ":" || identifier_blob
                          │
                          v
   identifier_blob = "s:" || module_id || ":" || flatbuffer_bytes
```

### Where each component comes from

| Element                  | Value                                                                                                                   |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `length prefix`          | `len(payload)` as `uint32` little-endian. Use exactly this; do not include the prefix itself in the count.              |
| `agent_id`               | The decimal string from `OSSEC K:` (e.g. `"001"` zero-padded as the manager returned it; preserve verbatim).            |
| Header literal           | The string `"!"+agent_id+"!#AES:"` — note the surrounding `!` and the `#AES:` separator.                                |
| `aes_key`                | First 32 bytes of `encryption_key` (§2).                                                                                |
| `IV`                     | `FEDCBA0987654321` (§3).                                                                                                |
| Padding bytes            | ASCII `'!'` (0x21) prepended to the zlib output until length is a multiple of 8.                                        |
| zlib level               | Default (6). Either `compress/zlib.DefaultCompression` or `-1` works.                                                   |
| MD5 of inner             | Lowercase hex digest of `msg`, prepended raw.                                                                           |
| Routing prefix           | `"55555"` then `"1234567891"` then `":"` then `"5555"` then `":"`. These are agent-routing magic strings the manager expects. |
| Identifier blob          | `"s:" + module_id + ":" + flatbuffer_bytes`. `module_id` examples: `"syscollector_sync"`, `"fim_sync"`, `"syscollector_vd"`. |

### Engine event variant

The Go sender's `engine` step type uses the same frame stack but with a
different `identifier_blob`:

```
identifier_blob = "1:" + <location> + ":" + <line>
```

No `s:` prefix, no FlatBuffer bytes — the entire payload is a single line
of plain text. The leading `'1'` is the queue byte (a Wazuh legacy
convention: ASCII 49 = syslog-like source). See
[12-engine-event-streams.md](./12-engine-event-streams.md) for the full
reference.

### `module_id` mapping

```
module                     module_id
─────────────────────────  ─────────────────────────────
syscollector_*             syscollector_sync
fim_*                      fim_sync
sca                        sca_sync
vd_*                       syscollector_vd  (when option = VDFirst/VDSync)
```

The exact mapping lives in `MODULE_TO_SYNC_TAG` in `internal/wire/`.
The sender MUST implement this table.

### Inbound frames

Format is identical end-to-end. The sender reads one frame at a time from
the socket:

1. Read 4 bytes length prefix (little-endian uint32).
2. Read exactly that many bytes.
3. Strip header `!<agent_id>!#AES:`.
4. AES-decrypt with `aes_key` and the fixed IV.
5. Strip the leading `!` padding.
6. zlib-inflate.
7. The first 32 bytes of the result are an MD5 hex digest; the rest is the
   `msg`.
8. Inside `msg`, the prefix `"55555"+"1234567891"+":"+"5555"+":"` is constant;
   strip it.
9. Parse the identifier blob `"s:<module_id>:<flatbuffer_bytes>"`.
10. The trailing bytes are a FlatBuffer `Message` — see
   [06-flatbuffers-messages.md](./06-flatbuffers-messages.md).

The reader MUST NOT validate the MD5 — any corruption shows up as a
zlib/AES failure before reaching the digest check. The reader SHOULD verify
it for diagnostic logging only.

## 5. Control message (post-connect)

Immediately after the TCP connect to remoted, before any inventory_sync
traffic, the sender sends:

```
identifier_blob = "#!-agent startup {\"version\":\"5.0.0\",\"name\":\"<name>\",\"id\":\"<id>\"}"
```

Same wrapping as any other frame (zlib + AES + length-prefix). This puts the
agent in the `active` state in the manager's `keys` table.

Notes:

- The literal prefix `#!-` is required by remoted to recognise control.
- The JSON object's `version` is set to a hard-coded `"5.0.0"`.
  Keep the literal unless a protocol change requires otherwise.

### Periodic keepalive

After startup, the agent emits a control keepalive every
`--keepalive-interval` (default 20 s, matches the real agent's
`NOTIFY_TIME`):

```
identifier_blob = "#!-{\"version\":\"1.0\",\"agent\":{\"id\":\"<id>\",\"name\":\"<name>\",\"version\":\"5.0.0\",\"merged_sum\":\"<md5 or empty>\",\"groups\":[\"default\"]}}"
```

The Go simulator emits the **minimal** payload — only the `agent.*` subobject
without `host`/`os`/`cluster`. The manager accepts this; the extra fields
are optional and the real agent only includes them when metadata is
available.

`merged_sum` starts at `""` until the manager pushes the shared file:

### Inbound: shared-file push

When the manager detects a `merged_sum` mismatch (or empty) for the
agent's group, it pushes the file in a single frame:

```
"#!-up file <md5_hex_32> merged.mg\n<file body>"
```

The simulator's reader detects the `#!-up file ` prefix, extracts the
32-character hex MD5 and stores it on the `Conn`. The file body is
discarded. Subsequent keepalives report this MD5, so the manager
transitions the agent from `not synced` to `synced` and stops resending
the file. See [`agent/conn.go`](../internal/agent/conn.go) `parseFileUpdate`.

### Farewell shutdown

Immediately before disconnecting, the agent emits:

```
identifier_blob = "#!-agent shutdown "
```

No payload, just the literal (trailing space included — that's how
[`client-agent/src/start_agent.c`](../../../../client-agent/src/start_agent.c#L863)
`send_agent_stopped_message()` formats it). The manager marks the agent
as disconnected as soon as it parses this control frame.

## 6. Hexdump example (illustrative)

A minimal `Start` for `module=syscollector_packages`, `agent_id=001`,
flatbuffer bytes of length 96, after each stage:

```
flatbuffer_bytes :  [00 00 10 00 ... 96 bytes]
msg              :  35 35 35 35 35 31 32 33 34 35 36 37 38 39 31 3a   "55555 1234567891:"
                    35 35 35 35 3a 73 3a 73 79 73 63 6f 6c 6c 65 63   "5555:s:syscollec"
                    74 6f 72 5f 73 79 6e 63 3a [flatbuffer ...]
inner_event      :  <32 bytes of hex md5> || msg
zlib_compressed  :  78 9c ... (zlib stream)
padded           :  21 21 ... 21 || zlib_compressed   (pad up to %8 == 0)
aes_ciphertext   :  AES_256_CBC(aes_key, IV, padded)
payload          :  "!001!#AES:" || aes_ciphertext
length_prefix    :  len(payload) as uint32 LE
frame on wire    :  length_prefix || payload
```

Exact bytes depend on the per-agent key; reproduce the chain and the wire
output must match Python byte-for-byte given the same `(name, id, key,
flatbuffer_bytes)`.

## 7. Common failure modes

| Symptom                                                          | Likely cause                                                  |
| ---------------------------------------------------------------- | ------------------------------------------------------------- |
| `wazuh-remoted` logs `Bad message format`                        | Length prefix endianness / extra/missing header bytes         |
| `wazuh-remoted` logs `Decoding error`                            | AES key/IV mismatch                                           |
| `wazuh-remoted` logs `inflate error`                             | zlib not applied or wrong padding                             |
| `wazuh-remoted` logs `Invalid checksum`                          | MD5_hex missing or computed over the wrong slice              |
| Manager never sees the agent come online                         | Control message missing or sent before `OSSEC A:` succeeded   |
| `Status_Error` on every Start                                    | `module_id` does not match a registered handler in the manager |
