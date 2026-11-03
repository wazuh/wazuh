# Private API Reference

This page documents the Wazuh Engine private API, served on `/var/wazuh-manager/queue/sockets/engine-api-http.sock`.

- OpenAPI source: [`private-api.yaml`](private-api.yaml); the book also publishes a ReDoc viewer of it beside this page, `private-api-redoc.html`, for the interactive reference

All endpoints in this contract are internal-only: every route takes `POST` and its path starts with `/_internal/`.
The conventions shared by every route are in [API Reference](api-reference.md#conventions-of-the-engine-api-socket).

| Path prefix | Purpose |
|---|---|
| `/_internal/router/` | Production routes (`route/post`, `route/delete`, `route/get`, `route/reload`, `route/patchPriority`, `table/get`) |
| `/_internal/tester/` | Tester sessions (`session/post`, `session/delete`, `session/get`, `session/reload`, `table/get`) and test runs (`run/post`) |
| `/_internal/content/` | Namespaces (`namespace/list`, `namespace/create`, `namespace/delete`, `namespace/import`), policies (`policy/upsert`, `policy/delete`) and resources (`list`, `get`, `upsert`, `delete`) |
| `/_internal/geo/` | Geolocation lookup (`db/get`) and loaded databases (`db/list`) |
| `/_internal/event-dumper/` | Event dumper (`activate`, `deactivate`, `status`) |
| `/_internal/raweventindexer/` | Raw event indexer state (`status`); registered only when the raw event indexer exists |
