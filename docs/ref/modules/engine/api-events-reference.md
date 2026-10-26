# API Events Reference

This page documents the Wazuh Engine events ingestion API.

- OpenAPI source: [`spec-events.yaml`](spec-events.yaml); the book also publishes a ReDoc viewer of it beside this page, `api-events-redoc.html`, for the interactive reference

Use this contract to ingest enriched security events into the engine through the
local ingestion socket, `/var/wazuh-manager/queue/sockets/engine-ingest-http.sock`
(`analysisd.server_enriched_events_socket`), with `POST /events/enriched`. The socket exists only while
`analysisd.server_enable_event_processing` is `true` (the default).

A request is answered 200 once its batch is split and queued: the header line and the batch framing are
checked synchronously (400 on failure), but each event line is parsed later by a router worker, so a malformed
event is dropped with the log line `Failed processing queued event in router worker: <reason>` while the
request still succeeds.

Each event receives a reception timestamp when it is queued, taken from a process-wide clock (nanoseconds since the
epoch, strictly increasing): the events of a batch keep their order and two events never share a stamp. The router
worker formats that stamp into `@timestamp` (UTC, nine fractional digits) before policy processing, and decoders can
overwrite it. Only the order in which stamps are assigned is guaranteed, not the network arrival order of concurrent
requests.

The engine emits reception timestamps with nine fractional digits, but indices mapped as `date` retain only millisecond precision for indexing and sorting, so events within the same millisecond can still tie until the separate indexer change provides `date_nanos` mappings for new backing indices.
