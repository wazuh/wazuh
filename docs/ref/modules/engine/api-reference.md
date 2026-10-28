# API Reference

The Wazuh Engine (`wazuh-manager-analysisd`) serves two local HTTP APIs over Unix sockets:

| Socket | Contract | Routes |
|---|---|---|
| `/var/wazuh-manager/queue/sockets/engine-api-http.sock` (`analysisd.server_api_socket`) | [Public API Reference](public-api-reference.md): endpoints consumed by supported external integrations such as `wazuh-indexer` in standalone mode | `/status`, `/logtest`, `/content/validate/*`, `/content/ioc/*`, `/metrics/*` |
| same socket | [Private API Reference](private-api-reference.md): internal-only endpoints used by development tooling, testing, and maintenance workflows | `/_internal/*` |
| `/var/wazuh-manager/queue/sockets/engine-ingest-http.sock` (`analysisd.server_enriched_events_socket`) | [API Events Reference](api-events-reference.md): event ingestion | `POST /events/enriched` |

Neither socket authenticates its callers: access is controlled by the socket file's permissions.

OpenAPI sources, each with a ReDoc viewer the book publishes beside this page for the interactive reference:

- [`public-api.yaml`](public-api.yaml) (viewer: `public-api-redoc.html`)
- [`private-api.yaml`](private-api.yaml) (viewer: `private-api-redoc.html`)
- [`spec-events.yaml`](spec-events.yaml) (viewer: `api-events-redoc.html`)

## Conventions of the engine API socket

These apply to every route on `engine-api-http.sock`:

- Request bodies are JSON. Unknown fields are ignored, and an empty body is read as an empty request, whether it
  is sent with `Content-Length: 0` or with no `Content-Length` (and no `Transfer-Encoding`) at all; the handler
  then names the missing field. `POST /content/validate/policy` is the exception: it reads `full_policy` from the
  raw body, so an empty body is rejected with 400 and `Error parsing request body: <details>`.
  A body that does not parse is rejected with 400 and `Failed to parse protobuff json request: <details>`.
  A request the server cannot read at all is answered 400 with the plain-text body
  `Bad request: the request could not be read.` before any handler runs.
- Responses carry a JSON body with a `status` field (`OK` or `ERROR`) and, on error, an `error` message.
  The metrics routes repeat a requested metric or space name in their errors cut to its first 128 characters,
  followed by `... (<n> bytes)`.
  The server labels these bodies `Content-Type: application/json`.
- Validation failures are 400. A handler whose backing component is gone answers 500 with
  `Error: Handler is not initialized`; an exception escaping a handler is answered 500 with the plain-text
  body `Internal server error`.
- A body larger than `analysisd.server_api_payload_max_bytes` (default `0`, unlimited) is answered with 413 and a
  plain-text message (`Payload too large. Max allowed: <n> bytes (<n/1024> KiB).`), before any handler runs. This is
  the only server-wide size limit, whatever the request's `Content-Type`. Routes with their own per-type limits
  (the content routes) answer their 413 with a JSON body.
- Send `Content-Type: application/json`. The server does not require it, but `curl -d` otherwise labels the body
  `application/x-www-form-urlencoded`.

The internal options named here are described in [Engine Configuration Reference](configuration.md).

## Example

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock http://localhost/status

curl --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/list \
  -H "Content-Type: application/json" -d '{}'
```
