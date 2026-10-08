# Quick Reference

The listeners, sockets, commands and counters of both remoted channels on one page. Every entry
links to the reference page that explains it.

## Listeners

| Channel | Port | Serves | Enabled |
|---|---|---|---|
| HTTPS agent API | `1517` ([`remote.https.port`](configuration.md#httpsport)) | 5.x agents | always |
| Legacy AES channel | `1514` TCP ([`remote.legacy.port`](configuration.md#legacyport), [`protocol`](configuration.md#legacyprotocol)) | 4.x agents | when [`remote.legacy.enabled`](configuration.md#legacyenabled) is `yes` — as the installer writes it |

Every HTTPS route is served under [`https.global_prefix`](configuration.md#httpsglobal_prefix)
(`/wazuh-manager/` by default); the routes are listed in [Architecture](architecture.md#endpoints)
and specified in [HTTPS Agent API](https-events-api.md).

## Local sockets

All under `/var/wazuh-manager/queue/sockets/`:

| Socket | Owner | Used for |
|---|---|---|
| `remote-admin-http.sock` | `remoted_module` | `GET /`, `/metrics`, `/status`, `/tls` — [Local admin socket](README.md#local-admin-socket) |
| `remote.sock` | remoted (C) | `getstats`, `getconfig`, legacy agent requests — [Local request socket](README.md#local-request-socket) |
| `engine-ingest-http.sock` | engine | where both channels post event batches (`POST /events/enriched`) — [Event Protocol](event-protocol.md) |

## Commands

```bash
# HTTPS agent server: metrics, readiness, served certificates
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/status
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/tls

# Check the configuration and every remoted.* internal option without starting the daemon
/var/wazuh-manager/bin/wazuh-manager-remoted -t

# Follow remoted's log lines
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep wazuh-manager-remoted
```

Through the Server API, per cluster node:

```text
GET /cluster/{node_id}/daemons/stats?daemons_list=wazuh-manager-remoted   # both channels' counters
GET /cluster/{node_id}/status                                            # readiness, from /status
GET /cluster/{node_id}/daemons/remoted/tls                               # the /tls resource
GET /cluster/{node_id}/configuration/request/remote                      # effective <remote>
```

## What to watch

| Question | Metric or counter |
|---|---|
| Is the HTTPS byte budget shedding load? | `remoted.server.budget.rejected.total` — [Metrics](metrics.md#public-transport-backpressure--remotedserverbudget) |
| Is a downstream service slow or down? | `remoted.forwarder.error.*`, `remoted.forwarder.deferred.rejected.total` — [Metrics](metrics.md#downstream-failures--remotedforwarder) |
| Why are agents getting `401`? | `remoted.auth.reject.*` — [Metrics](metrics.md#authentication-rejections--remotedauthreject) |
| Is enrollment being paced by its rate limit? | `remoted.enroll.rate_limited`, `remoted.enroll.rate_limit.available` — [Metrics](metrics.md#rate-limits--remotedendpointrate_limit) |
| Is the legacy channel dropping messages? | `metrics.messages.received_breakdown.discarded` and `events_failed` in the daemons-stats answer — [Queue Byte Limits](configuration.md#queue-byte-limits) |

## Settings that most often need changing

| Situation | Setting |
|---|---|
| HTTPS answers `503` under load | [`remoted.max_inflight_bytes`](configuration.md#remotedmax_inflight_bytes), [`remoted.max_deferred_requests`](configuration.md#remotedmax_deferred_requests), [`remoted.max_parallel_connections`](configuration.md#remotedmax_parallel_connections), [`remoted.max_requests_per_agent`](configuration.md#remotedmax_requests_per_agent) / [`remoted.max_inflight_bytes_per_agent`](configuration.md#remotedmax_inflight_bytes_per_agent) when one agent is the source — read the metrics first |
| Enrolling a large fleet at once | [`remote.https.enroll_rate_limit`](configuration.md#httpsenroll_rate_limit) (100 per second by default, for `POST /enroll`; at the default, 10 000 agents need at least ~100 s) |
| Slow agent links | [`remoted.http_read_timeout`](configuration.md#remotedhttp_read_timeout) together with the agent's own budget — [Connection timing tuning](timing-tuning.md) |
| Agents with unsynchronized clocks get `401 stale_token` | fix NTP; [`remoted.jwt_clock_skew`](configuration.md#remotedjwt_clock_skew) only as a stopgap |
| No 4.x agent left | [`remote.legacy.enabled`](configuration.md#legacyenabled) `no` |

## Protocol Example

The batch both channels post to the engine ([Event Protocol](event-protocol.md)):

```text
H {"wazuh":{"agent":{"id":"001","name":"web-01","groups":["web"]}}}
E {"log":"Connection from 192.168.1.100"}
E {"log":"Authentication successful"}
```

## References

- [Architecture](architecture.md)
- [HTTPS Agent API](https-events-api.md)
- [Configuration](configuration.md)
- [Metrics](metrics.md)
- [Connection timing tuning](timing-tuning.md)
- [Stateless Metadata](stateless-metadata.md)
- [Event Protocol](event-protocol.md)
