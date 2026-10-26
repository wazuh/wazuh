# API Events Reference

This page documents the Wazuh Engine events ingestion API.

- OpenAPI source: [`spec-events.yaml`](spec-events.yaml); the book also publishes a ReDoc viewer of it beside this page, `api-events-redoc.html`, for the interactive reference

Use this contract to ingest enriched security events into the engine through the
local ingestion socket, `/var/wazuh-manager/queue/sockets/engine-ingest-http.sock`
(`analysisd.server_enriched_events_socket`), with `POST /events/enriched`. The socket exists only while
`analysisd.server_enable_event_processing` is `true` (the default).

Every request must supply exactly one `X-Wazuh-Agent-Id` header naming the same canonical agent ID
as the H line. Missing or invalid identity context, ambiguous identity members, dotted identity
aliases, and malformed batch framing or H line return HTTP `400`. Identity failures are rejected before any
event is enqueued. Unavailable internal services return HTTP `500`. See the
[events specification](spec-events.yaml) for the complete request and error contract.

A request is answered 200 once its batch is split and queued: the identity, the header line and the batch framing are
checked synchronously (400 on failure), but each event line is parsed later by a router worker, so a malformed
event is dropped with the log line `Failed processing queued event in router worker: <reason>` while the
request still succeeds.
