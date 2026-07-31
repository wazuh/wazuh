# Inventory Sync Server API Reference

All routes are served over a Unix domain socket at `queue/sockets/inventory-sync.sock`, relative to the
installation directory. There is no TCP listener.

The only production peer is [Remoted](../remoted/README.md), which authenticates the agent and forwards
the request. Requests are HTTP/1.1, `Content-Length` delimited, one request per connection
(`Connection: close`); chunked transfer encoding is rejected.

## Routes

| Method | Path | Success | Notes |
|---|---|---|---|
| `GET` | `/` | `200` | Liveness probe. Exempt from the in-flight byte budget, so it keeps answering under memory pressure. |
| `POST` | `/inventory/sync` | `202` | **Provisional.** Accepts and discards the payload; the ingestion pipeline is not implemented yet. |
| `POST` | `/stats` | `200` | **Temporary.** Echoes the enriched document back. |
| `POST` | `/config` | `200` | **Temporary.** Echoes the enriched document back. |

`/stats` and `/config` exist to prove the enrichment dependencies reach the handler; they will be
rewritten when the real payloads are defined.

## Request headers

| Header | Required | Meaning |
|---|---|---|
| `X-Wazuh-Agent-Id` | Yes, for `/inventory/sync`, `/stats` and `/config` | The agent identity remoted authenticated. Its absence is a contract violation, not agent input, so it is answered `400`. |
| `Content-Type` | No | Recorded, not interpreted. |

## Enrichment

For `/stats` and `/config`, the module overwrites four fields on the document before echoing it. All four
are authoritative and replace whatever the agent sent:

| JSON pointer | Source |
|---|---|
| `/wazuh/agent/id` | The authenticated `X-Wazuh-Agent-Id` header |
| `/wazuh/cluster/name` | `<cluster><name>` in the manager configuration |
| `/wazuh/cluster/node` | `<cluster><node_name>` |
| `/@timestamp` | The manager's clock, ISO 8601 with milliseconds, UTC |

A cluster name or node name containing bytes that are not valid UTF-8 is sanitized once at startup, with
a warning, rather than being allowed to break the serialization of every request.

## Status codes

These can be returned on any route, by the transport rather than by a handler:

| Status | Cause |
|---|---|
| `400` | Malformed HTTP, a body that is not a JSON object, or a missing agent id header |
| `404` | Unknown path |
| `405` | Known path, wrong verb. Carries an `Allow` header listing that path's verbs |
| `411` | Chunked transfer encoding, which is not supported |
| `413` | Body over `max_body_size` |
| `414` | Request target over `max_url_size` |
| `431` | A header name or value over its cap, or more than 32 header lines |
| `500` | A route handler threw. The server keeps serving |
| `503` | No healthy indexer host (`/stats`, `/config`), the in-flight byte budget is exhausted, the connection cap is reached, or the module is shutting down |
| `504` | A handler was dispatched but never answered within `response_timeout` |

A `503` is retryable and a `400` is not: validation runs BEFORE the indexer availability check on
purpose, so a malformed document is never masked as a transient failure the agent would retry forever.

## Manual testing

`tools/send_sync.py` in the module's source directory drives every route over the socket. The equivalent
with curl:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync.sock http://localhost/
```
