# Public API Reference

This page documents the Wazuh Engine public API, served on `/var/wazuh-manager/queue/sockets/engine-api-http.sock`.

- OpenAPI source: [`public-api.yaml`](public-api.yaml); the book also publishes a ReDoc viewer of it beside this page, `public-api-redoc.html`, for the interactive reference

Use this contract for supported external consumers, including `wazuh-indexer` when the engine runs in standalone mode.
The conventions shared by every route (body parsing, status codes, content type) are in [API Reference](api-reference.md#conventions-of-the-engine-api-socket).

| Method and path | Purpose |
|---|---|
| `GET /status` | Engine readiness and the sync state of content spaces, IOC and geo databases |
| `POST /content/validate/policy` | Validate a full policy document and optionally load it into a tester session |
| `POST /content/validate/resource` | Validate a single decoder, filter, integration or KVDB |
| `POST /content/ioc/update` | Schedule an IOC synchronization from an nd-json file |
| `GET /content/ioc/state` | IOC synchronization state |
| `POST /logtest` | Run one event through a tester session |
| `DELETE /logtest` | Delete a tester session and its namespace |
| `POST /metrics/enable` | Enable or disable a metric |
| `POST /metrics/get` | Read one metric |
| `POST /metrics/list` | List metric names |
| `POST /metrics/dump` | Dump every metric with its value |
