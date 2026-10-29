# API Events Reference

This page documents the Wazuh Engine events ingestion API.

- OpenAPI source: [`spec-events.yaml`](spec-events.yaml); the book also publishes a ReDoc viewer of it beside this page, `api-events-redoc.html`, for the interactive reference

Use this contract to ingest enriched security events into the engine through the
local ingestion socket, `/var/wazuh-manager/queue/sockets/engine-ingest-http.sock`
(`analysisd.server_enriched_events_socket`), with `POST /events/enriched`. The socket exists only while
`analysisd.server_enable_event_processing` is `true` (the default).

A request is answered 200 once its batch is split and queued: the header line and the batch framing are
checked synchronously (400 on failure; the engine logs the first rejected batch as the WARNING
`[API::Event] Failed to parse request: '<reason>'`, then at most one line per minute that also reports how many
requests it rejected since its previous report), but each event line is parsed later by a router worker, so a malformed
event is dropped while the request still succeeds. Each dropped line is counted in the `router.events.malformed`
metric; each router worker logs the first one as the WARNING `Dropped a malformed event: <reason>`, then at most one
line per minute that also reports how many it dropped since its previous report. A line whose queue byte is
outside `0x01`..`0x7F` is malformed: `0x00` is no queue (`/logtest` refuses queue `0` too), and the indexer maps
`wazuh.protocol.queue` as a signed byte, so it would refuse a value above `0x7F`.

On a manager the router overwrites `wazuh.cluster.name` and `wazuh.cluster.node` in every event with the receiving
node's `cluster.name` and `cluster.node_name`, whatever the batch header carries.

Each event receives a reception timestamp when it is queued, taken from a process-wide clock (nanoseconds since the
epoch, strictly increasing within one engine process): the events of a batch keep their order and two events never share a stamp in that process. The router
worker formats that stamp into `@timestamp` (UTC, nine fractional digits) before policy processing, and decoders can
overwrite it. Only the order in which stamps are assigned is guaranteed, not the network arrival order of concurrent
requests.

If the wall clock steps backwards by Δ (an NTP correction, or a start with the clock ahead), the reception stamps do not go back with it: every event gets the last stamp plus one nanosecond until the wall clock catches up, so for up to Δ of real time the stamps run ahead of the wall clock and a dashboard time window may not show those events until then. Ordering and uniqueness are kept on purpose over wall-clock fidelity; a restart or another cluster node starts its own sequence.

The engine emits reception timestamps with nine fractional digits, but indices mapped as `date` retain only millisecond precision for indexing and sorting, so events within the same millisecond can still tie there. The wazuh-indexer data stream templates map `@timestamp` as `date_nanos` since [wazuh-indexer-plugins#1738](https://github.com/wazuh/wazuh-indexer-plugins/pull/1738); backing indices created before that template keep `date` until the data stream rolls over. A `date_nanos` field only stores dates from `1970-01-01T00:00:00Z` to `2262-04-11T23:47:16.854775807Z`: the engine rejects a date outside that range when a map operation copies a `date` value (for example a reference to a `date` field) into a `date_nanos` field, but a date parsed into one, by `parse_date` or a decoder's parse expression, is not range-checked yet (nor is a copy between two `date_nanos` fields), and the indexer rejects that document.
