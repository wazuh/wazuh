# API Events Reference

This page documents the Wazuh Engine events ingestion API.

- OpenAPI source: [`spec-events.yaml`](spec-events.yaml); the book also publishes a ReDoc viewer of it beside this page, `api-events-redoc.html`, for the interactive reference

Use this contract to ingest enriched security events into the engine through the
local ingestion socket (`queue/sockets/engine-ingest-http.sock`).

Every request must supply exactly one `X-Wazuh-Agent-Id` header naming the same canonical agent ID
as the H line. Missing or invalid identity context, ambiguous identity members, dotted identity
aliases, and malformed H/E payloads return HTTP `400`. Identity failures are rejected before any
event is enqueued. Successful batches return HTTP `200`; unavailable internal services return
HTTP `500`. See the [events specification](spec-events.yaml) for the complete request and error contract.
