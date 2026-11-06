## [v5.0.1]

### Manager

#### Added

| Issue | Comment |
|-------|---------|
| [#38944](https://github.com/wazuh/wazuh/issues/38944) | Built the Linux curl dependency with Brotli support and made the HTTP client's `Accept-Encoding` configurable per request (`ConfigurationParameters::acceptEncoding`; default: every encoding the linked curl decodes). |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Added entry and byte limits to the engine's agent metadata cache: `analysisd.agent_metadata_cache_max_entries` (default 50000) and `analysisd.agent_metadata_cache_max_bytes` (default 128 MiB of accounted bytes; `0` disables either). A header that does not fit is still parsed and used, but not retained; the cache never evicts another agent to make room. New metrics `agent.cache.bytes`, `agent.cache.max_entries`, `agent.cache.max_bytes`, `agent.cache.bypass.max_entries`, `agent.cache.bypass.max_bytes` and `agent.cache.rejected.identity`, and a throttled warning while the cache is full. |

#### Changed

| Issue | Comment |
|-------|---------|
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Changed the engine's enriched-event ingest (`POST /events/enriched` on `engine-ingest-http.sock`) to require exactly one canonical `X-Wazuh-Agent-Id` header and an H line whose `wazuh.agent.id` matches it; other batches are answered `400`. remoted (`/stateless` and the legacy channel) and the vulnerability scanner send it; local tools posting to that socket must add it. remoted no longer parses the H line itself, and caches agent metadata by that trusted id. |
| [#39590](https://github.com/wazuh/wazuh/issues/39590) | Changed the engine's handling of unsigned internal options: a negative value in `wazuh-manager-internal-options.conf` now stops start-up, and a negative environment value is ignored with a warning, instead of wrapping to a huge number or silently falling back to the default. |
| [#41051](https://github.com/wazuh/wazuh/issues/41051) | Changed remoted's two calls to the vulnerability scanner (`GET /vulnerability-detector/offset` and `POST /vulnerability-detector/scan` on `vd-http.sock`) from cpp-httplib to remoted's own UDS HTTP client: each call has a fixed 1-second connect deadline and a 64 KiB cap on the answer, and its warning names the failure (`Failed to query VD offset: connect_failed`, `vd_unreachable (connect_failed)`). The `/scan/vd` budget checked against `remoted.http_request_timeout` at start-up now counts both connect deadlines (14 seconds with the defaults). The manager no longer ships cpp-httplib, and `THIRD-PARTY-NOTICES` no longer lists it. |

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
| [#40192](https://github.com/wazuh/wazuh/issues/40192) | Fixed the UndefinedBehaviorSanitizer `vptr` reports of the engine. The binary linked two fmt versions (`external/fmt` 8.1.1 and the 10.2.1 bundled in spdlog) that share include guards, so the first one included silently voided the other; since `namespace spdlog` is unversioned and the engine uses spdlog header-only, the same spdlog classes were defined over different fmt types under identical mangled names. `SPDLOG_FMT_EXTERNAL` is now defined on the imported spdlog target so every engine translation unit uses the same fmt. `bk::taskf::Controller` and `bk::rx::Controller` no longer downcast the tracer to `TracerImpl`, an empty subclass that was never instantiated. |

### Agent

#### Added

| Issue | Comment |
|-------|---------|
| [#38514](https://github.com/wazuh/wazuh/issues/38514) | Added zstd decoding of `POST /download` configuration responses: the agent offers `Accept-Encoding: zstd` and libcurl decodes the reply. |

#### Changed

| Issue | Comment |
|-------|---------|

#### Removed

| Issue | Comment |
|-------|---------|

#### Fixed

| Issue | Comment |
|-------|---------|
| [#38514](https://github.com/wazuh/wazuh/issues/38514) | Fixed the Windows agent leaving a temporary file behind after a failed `/stateful` body compression, and a failed `fclose()` passing a truncated compressed body as complete. |

## Prior versions

- [v5.0.0](https://github.com/wazuh/wazuh/blob/v5.0.0/CHANGELOG.md)
