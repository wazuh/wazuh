## [v5.0.1]

### Manager

#### Added

| Issue | Comment |
|-------|---------|
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Added entry and byte limits to the engine's agent metadata cache: `analysisd.agent_metadata_cache_max_entries` (default 50000) and `analysisd.agent_metadata_cache_max_bytes` (default 128 MiB of accounted bytes; `0` disables either). A header that does not fit is still parsed and used, but not retained; the cache never evicts another agent to make room. New metrics `agent.cache.bytes`, `agent.cache.max_entries`, `agent.cache.max_bytes`, `agent.cache.bypass.max_entries`, `agent.cache.bypass.max_bytes` and `agent.cache.rejected.identity`, and a throttled warning while the cache is full. |

#### Changed

| Issue | Comment |
|-------|---------|
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Changed the engine's enriched-event ingest (`POST /events/enriched` on `engine-ingest-http.sock`) to require exactly one canonical `X-Wazuh-Agent-Id` header and an H line whose `wazuh.agent.id` matches it; other batches are answered `400`. remoted (`/stateless` and the legacy channel) and the vulnerability scanner send it; local tools posting to that socket must add it. remoted no longer parses the H line itself, and caches agent metadata by that trusted id. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Changed the engine's handling of unsigned internal options: a negative value in `wazuh-manager-internal-options.conf` now stops start-up, and a negative environment value is ignored with a warning, instead of wrapping to a huge number or silently falling back to the default. |
| [#41104](https://github.com/wazuh/wazuh/pull/41104) | Changed the Server API to answer an unauthenticated request to a path or method it does not declare with the 401 of a declared route, instead of a 404, 405, 307, 417 or 413, so that routes can no longer be enumerated without credentials. A 405, and a 404 when `max_request_per_minute` is 0, now count against `max_unauthenticated_request_per_minute`. |

#### Removed

| Issue | Comment |
|-------|---------|

#### Fixed

| Issue | Comment |
|-------|---------|
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Aligned enriched-event examples, response documentation and developer comments with engine-side identity validation, and grouped cache operation metrics in the engine dashboard's Cache section. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Updated the standalone enriched-event senders to derive raw identity headers from each H line, preserve complete batches from raw files, and support an explicit expected agent ID. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Rejected dotted aliases of the agent identity in enriched-event metadata before enqueueing, including escaped member names. |
| [#38916](https://github.com/wazuh/wazuh/issues/38916) | The initial vulnerability-feed download resumes from the last durable cursor after a failed request or a manager restart instead of starting again from the first document, and logs the reason of every failed attempt. |

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
