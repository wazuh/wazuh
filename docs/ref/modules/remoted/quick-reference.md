# Quick Reference: Stateless Metadata

## TL;DR

Wazuh 5.0+ automatically enriches all events with agent metadata (OS, version, groups, etc.) before sending to analysisd. No configuration required.

## Key Concepts

- **Stateless**: Every event carries agent context
- **Keep-Alive**: Metadata sent every ~60 seconds
- **Cache**: Manager stores metadata in memory
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
# /var/wazuh-manager/etc/internal_options.conf
remoted.control_msg_queue_size=32768
remoted.batch_events_capacity=262144
remoted.worker_pool=8
remoted.sender_pool=16
```

### Large Agent Count (>10K agents)

```conf
# /var/wazuh-manager/etc/internal_options.conf
remoted.control_msg_queue_size=32768
```

**And** recompile with larger hash table:
```c
// src/remoted/agent_metadata_db.c
OSHash_setSize(agent_meta_map, 4096);
```

## Performance Tips

1. **Use TCP**: Better throughput than UDP
2. **Increase batch size**: More events per HTTP POST
3. **Monitor queue depth**: Should be near zero under normal load
4. **Size hash table**: Buckets should be ~agents/5

## Protocol Example

```
H	{"wazuh":{"agent":{"id":"001","name":"web-01","groups":["web"]}}}
E	{"log":"Connection from 192.168.1.100"}
E	{"log":"Authentication successful"}
```

## Monitoring

### Statistics File

```bash
cat /var/wazuh-manager/var/run/wazuh-manager-remoted.state
```

### Key Metrics

- `queue_size`: Should be <50% capacity
- `tcp_sessions`: Number of connected agents
- `events_count`: Total events processed
- `control_msg_count`: Keep-alive messages processed
- `discarded_count`: Messages dropped (should be 0)

## References

- [Stateless Metadata](stateless-metadata.md)
- [Architecture](architecture.md)
- [Protocol](event-protocol.md)
- [Configuration](configuration.md)
