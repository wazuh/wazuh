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
- **Message limits (fixed):** max URL 2048 B, max header name 256 B, max header value 8192 B, max
  64 header fields, and a transport body cap of 16 MiB. Handshake/read timeouts are 10 s, request
  timeout 30 s.

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
| Endpoint handler raised an unexpected error | `500` | `Internal server error` |

> **Planned / not yet implemented:** H/E batch validation (`400 Invalid event batch`) and the
> check that the payload's `wazuh.agent.id` matches the authenticated `agent-id`
> (`PayloadAgentMismatch`) are part of the target contract but are **not** performed today, because
> the endpoint does not parse the payload yet.

Requests larger than the 16 MiB transport cap are dropped at the TLS/HTTP layer (the connection is
closed) before authentication runs, so they never receive a clean `413`.

## Endpoints

- **`GET /`** — unauthenticated health probe. Returns `200` with
  `{"status":"ok","module":"remoted"}`.
- **`POST /stateless`** — authenticated event ingestion endpoint (see status note above). On a
  valid signature it returns `200` with an empty body; otherwise it returns the error above.

The machine-readable contract is published as OpenAPI — see the
[endpoint reference](stateless-api-reference.html) (source: [`stateless-api.yaml`](stateless-api.yaml)).

## Configuration

All settings resolve as **caller value (C-ABI struct) → environment variable → built-in default**.
`remoted` currently leaves the C-ABI fields unset, so in practice values come from the environment
or the defaults below.

| Setting | Default | Environment override |
|---|---|---|
| Bind address | `127.0.0.1` | `WAZUH_REMOTED_HTTPS_ADDRESS` |
| Port | `9443` | `WAZUH_REMOTED_HTTPS_PORT` |
| I/O threads | `2` | `WAZUH_REMOTED_HTTPS_IO_THREADS` |
| Handler worker threads | `4` | `WAZUH_REMOTED_HTTPS_WORKER_THREADS` |
| Transport max body size | `16 MiB` | `WAZUH_REMOTED_HTTPS_MAX_BODY_SIZE` |
| TLS certificate chain | `/etc/remoted-https/server.crt` | `WAZUH_REMOTED_HTTPS_CERTIFICATE` |
| TLS private key | `/etc/remoted-https/server.key` | `WAZUH_REMOTED_HTTPS_PRIVATE_KEY` |

> There is no `ossec.conf` (`<remote>`) setting for the HTTPS listener yet; configuration is
> limited to the environment variables above and the certificate files on disk.

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
