# Quick Reference: Stateless Metadata

## TL;DR

Wazuh 5.0+ automatically enriches all events with agent metadata (OS, version, groups, etc.) before
forwarding them to the engine. No configuration required.

The metadata **cache** described on this page belongs to the legacy `<remote><legacy>` channel, which
extracts it from 4.x keep-alives. A 5.x agent instead reports its host metadata on `POST /control`
(`notify`), and the manager writes it straight to wazuh-db — see
[HTTPS Agent API](https-events-api.md#control-endpoint-post-control).

## Key Concepts

- **Stateless**: Every event carries agent context
- **Keep-Alive**: Metadata sent every ~60 seconds *(legacy channel)*
- **Cache**: Manager stores metadata in memory *(legacy channel)*
- **x-wev1**: Protocol format (header + events)

## Metadata Fields

| Field         | Example           | Source                                                         |
| ------------- | ----------------- | -------------------------------------------------------------- |
| Agent ID      | `"001"`           | Agent registration                                             |
| Agent Name    | `"web-server-01"` | Keep-alive message                                             |
| Agent Version | `"v5.0.0"`        | Keep-alive message                                             |
| Groups        | `["web", "prod"]` | Keep-alive message                                             |
| OS Name       | `"Ubuntu"`        | Keep-alive message                                             |
| OS Version    | `"22.04"`         | Keep-alive message                                             |
| OS Platform   | `"ubuntu"`        | Keep-alive message                                             |
| OS Type       | `"linux"`         | Keep-alive or inferred                                         |
| Architecture  | `"x86_64"`        | Keep-alive (all platforms, requires extended keepalive format) |
| Hostname      | `"web-server-01"` | Keep-alive (all platforms, requires extended keepalive format) |

## Common Tasks

### Check Metadata Collection

```bash
tail -f `/var/wazuh-manager/logs/wazuh-manager.log` | grep -i "keepalive\|metadata"
```

## Configuration Quick Start

### Default Settings (Good for <10K agents)

No changes needed. Defaults work well.

### High Throughput (>50K events/sec)

```conf
# /var/wazuh-manager/etc/wazuh-manager-internal-options.conf
remoted.control_msg_queue_size=32768
remoted.batch_events_capacity=262144
remoted.worker_pool=8
remoted.sender_pool=16
```

### Large Agent Count (>10K agents)

```conf
# /var/wazuh-manager/etc/wazuh-manager-internal-options.conf
remoted.control_msg_queue_size=32768
```

For the HTTPS channel, size the capacity limits instead —
`remoted.max_inflight_bytes`, `remoted.max_parallel_connections` and
`remoted.max_deferred_requests`. [Configuration](configuration.md) has sizing examples for
deployments above 10K agents, and [Metrics](metrics.md) links each limit to the metric that tells you
whether it is the one binding.

## Performance Tips

1. **Increase batch size**: More events per request
2. **Monitor queue depth**: Should be near zero under normal load
3. **Watch the byte budget**: `remoted.server.budget.rejected.total` climbing means the in-flight
   limit is what is shedding load, not the downstream
4. **Prefer TCP over UDP** *(legacy channel only)*: better throughput

## Protocol Example

```
H	{"wazuh":{"agent":{"id":"001","name":"web-01","groups":["web"]}}}
E	{"log":"Connection from 192.168.1.100"}
E	{"log":"Authentication successful"}
```

## Monitoring

### Statistics file *(legacy channel)*

These counters describe the `<remote><legacy>` pipeline only. They stay at zero on a manager serving
5.x agents over HTTPS.

```bash
cat /var/wazuh-manager/var/run/wazuh-manager-remoted.state
```

- `queue_size`: Should be <50% capacity
- `tcp_sessions`: Number of connected agents
- `events_count`: Total events processed
- `control_msg_count`: Keep-alive messages processed
- `discarded_count`: Messages dropped (should be 0)

### HTTPS agent server metrics

The C++ module's own metrics (per-endpoint outcomes and latency, auth rejections, downstream
failures, backpressure) are a separate dump on its local admin socket:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
```

Full catalog, with each metric linked to the setting it helps size: [Metrics](metrics.md).

## References

- [Stateless Metadata](stateless-metadata.md)
- [Architecture](architecture.md)
- [Protocol](event-protocol.md)
- [Configuration](configuration.md)
- [Metrics](metrics.md)
