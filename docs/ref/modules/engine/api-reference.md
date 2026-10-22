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

- Request bodies are JSON. Unknown fields are ignored, and an empty body is read as an empty request.
  A body that does not parse is rejected with 400 and `Failed to parse protobuff json request: <details>`.
- Responses carry a JSON body with a `status` field (`OK` or `ERROR`) and, on error, an `error` message.
  The server labels these bodies `Content-Type: plain/text`, not `application/json`.
- Validation failures are 400. A handler whose backing component is gone answers 500 with
  `Error: Handler is not initialized`; an exception escaping a handler is answered 500 with the plain-text
  body `Internal server error`.
- A body larger than `analysisd.server_api_payload_max_bytes` (default `0`, unlimited) is answered with 413 and a
  plain-text message.

The internal options named here are described in [Engine Configuration Reference](configuration.md).

## Example

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock http://localhost/status
```
