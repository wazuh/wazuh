## [v5.0.1]

### Manager

#### Added

| Issue | Comment |
|-------|---------|
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Added entry and byte limits to the engine's agent metadata cache: `analysisd.agent_metadata_cache_max_entries` (default 50000) and `analysisd.agent_metadata_cache_max_bytes` (default 128 MiB of accounted bytes; `0` disables either). A header that does not fit is still parsed and used, but not retained; the cache never evicts another agent to make room. New metrics `agent.cache.bytes`, `agent.cache.max_entries`, `agent.cache.max_bytes`, `agent.cache.bypass.max_entries`, `agent.cache.bypass.max_bytes` and `agent.cache.rejected.identity`, and a throttled warning while the cache is full. |
| [#40657](https://github.com/wazuh/wazuh/issues/40657) | Added three internal options that size the engine's event ingest server: `analysisd.server_enriched_events_max_body_bytes` (default 64 MiB), `analysisd.server_enriched_events_max_connections` (default 1024) and `analysisd.server_enriched_events_max_inflight_bytes` (default 256 MiB), validated at start-up. New `server.ingest.*` metrics report its in-flight bytes and requests, open connections, handler queue and the `413`/`503` answers by cause. |

#### Changed

| Issue | Comment |
|-------|---------|
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Changed the engine's enriched-event ingest (`POST /events/enriched` on `engine-ingest-http.sock`) to require exactly one canonical `X-Wazuh-Agent-Id` header and an H line whose `wazuh.agent.id` matches it; other batches are answered `400`. remoted (`/stateless` and the legacy channel) and the vulnerability scanner send it; local tools posting to that socket must add it. remoted no longer parses the H line itself, and caches agent metadata by that trusted id. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Changed the engine's handling of unsigned internal options: a negative value in `wazuh-manager-internal-options.conf` now stops start-up, and a negative environment value is ignored with a warning, instead of wrapping to a huge number or silently falling back to the default. |
| [#40657](https://github.com/wazuh/wazuh/issues/40657) | Changed the engine's event ingest server (`POST /events/enriched` on `engine-ingest-http.sock`) to the manager's shared HTTP-over-UDS server. Its listen backlog is now the system maximum instead of 5, so producers no longer get refused connections under load; a request over the body cap gets `413`, overload gets a counted `503`, the server answers one request per connection and `Expect: 100-continue`, and refuses chunked bodies with `411`. On stop it gives admitted requests up to 10 s. |

#### Removed

| Issue | Comment |
|-------|---------|

#### Fixed

| Issue | Comment |
|-------|---------|
| [#40657](https://github.com/wazuh/wazuh/issues/40657) | Documented the event ingest transport's `503` error bodies and `504` response backstop, including the shared JSON error schema and the risk of duplicate events when retrying after work may have started. |
| [#40657](https://github.com/wazuh/wazuh/issues/40657) | Preserved the first final HTTP response while `100 Continue` is being written, preventing a response timeout or late handler answer from replacing it. A handler whose answer is already pending no longer produces a response-timeout warning. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Aligned enriched-event examples, response documentation and developer comments with engine-side identity validation, and grouped cache operation metrics in the engine dashboard's Cache section. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Updated the standalone enriched-event senders to derive raw identity headers from each H line, preserve complete batches from raw files, and support an explicit expected agent ID. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Rejected dotted aliases of the agent identity in enriched-event metadata before enqueueing, including escaped member names. |

### Agent

#### Added

| Issue | Comment |
|-------|---------|

#### Changed

| Issue | Comment |
|-------|---------|

#### Removed

| Issue | Comment |
|-------|---------|

#### Fixed

| Issue | Comment |
|-------|---------|

## Prior versions

- [v5.0.0](https://github.com/wazuh/wazuh/blob/v5.0.0/CHANGELOG.md)
