# Remoted Configuration

Configuration options for remoted module.

For the full per-option reference (all options, defaults and allowed values verified against the parser) see [Remote Configuration](../../configuration/remote.md).

## XML Configuration

File: `/var/wazuh-manager/etc/wazuh-manager.conf`

### Key Options

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
    <agents>
      <allow_higher_versions>no</allow_higher_versions>
    </agents>
  </remote>
</wazuh_config>
```

| Option | Default | Description |
|--------|---------|-------------|
| `port` | `1514` | Listening port |
| `protocol` | `tcp` | Protocol: `tcp`, `udp`, or `tcp,udp` |
| `queue_size` | `131072` | Message queue size (warn if > 262144) |
| `agents/allow_higher_versions` | `no` | Accept agents with a higher Wazuh version than the manager |

## Internal Options

File: `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

### Key Settings

```conf
# Network
remoted.receive_chunk=4096
remoted.send_timeout_to_retry=5

# Threading
remoted.worker_pool=4
remoted.sender_pool=8

# Queues (important for stateless metadata)
remoted.control_msg_queue_size=16384
remoted.batch_events_capacity=131072

# Queue byte limits (0 = unlimited)
remoted.queue_max_bytes=67108864
remoted.batch_events_max_bytes=24117248
```

## Stateless Metadata Configuration

### Cache Expiration

```conf
# Agent metadata cache expiration time in seconds [60..86400]
# Entries older than this threshold will be cleaned up periodically
# Default: 300 (5 minutes)
remoted.enrich_cache_expire_time=300
```

**Guidelines**:
- Ephemeral/short-lived agents: 300 (5 minutes) - default
- Stable agents with occasional restarts: 600 (10 minutes)
- Long-running stable agents: 1800 (30 minutes)

The cleanup runs every 60 seconds and removes entries that haven't received a keepalive in the configured time period.

### Queue Sizing

```conf
# Keep-alive processing
remoted.control_msg_queue_size=16384  # Default: 16384

# Event batching
remoted.batch_events_capacity=131072  # Default: 131072
```

**Sizing Guidelines**:
- Small (<1K agents): control=4096, batch=32768
- Medium (1K-10K agents): control=16384, batch=131072 (defaults)
- Large (>10K agents): control=32768, batch=262144

### Queue Byte Limits

Caps total memory used by each queue regardless of event count. Useful when agents send large events that would otherwise cause unbounded memory growth even at normal event rates.

```conf
# Maximum bytes held in the input queue (messages received from agents)
# Default: 67108864 (64 MiB). Set to 0 to disable.
remoted.queue_max_bytes=67108864

# Maximum bytes held in the events queue (events forwarded to the engine)
# Default: 33554432 (32 MiB). Set to 0 to disable.
remoted.batch_events_max_bytes=33554432
```

| Option | Default | Min | Description |
|--------|---------|-----|-------------|
| `remoted.queue_max_bytes` | `67108864` | `1024` | Byte cap for the input message queue |
| `remoted.batch_events_max_bytes` | `33554432` | `1024` | Byte cap for the outbound events queue toward the engine |

**Behavior when the limit is reached**:
- Events that individually exceed the limit are dropped immediately.
- Events that would push the total over the limit are dropped until space is freed.
- Dropped events increment the same discard counter as a full queue (`discarded_count` in the state file).
- A warning is logged at most once every 5 seconds to avoid log flooding.

**Guidelines**:
- The byte limit and the event-count limit (`batch_events_capacity`) are independent. An event is dropped if either limit is reached.
- Values between 1 and 1023 bytes are rejected at startup as they are almost certainly a configuration error.
- Set to `0` to revert to count-only limiting.

### Hash Table Tuning

Metadata cache bucket count (requires recompile of `src/remoted/agent_metadata_db.c`):
- <10K agents: 2048 (default)
- 10K-50K agents: 4096
- >50K agents: 8192

## Performance Tuning

**High Throughput (>50K events/sec)**

```conf
remoted.control_msg_queue_size=32768
remoted.batch_events_capacity=262144
remoted.worker_pool=8
remoted.sender_pool=16
```

### Large Agent Count (>10K agents)

```conf
remoted.control_msg_queue_size=32768
remoted.keyupdate_interval=30
remoted.rlimit_nofile=131072
```

Also increase hash table buckets (requires recompile).

### Low Memory

```conf
remoted.control_msg_queue_size=4096
remoted.batch_events_capacity=32768
remoted.worker_pool=2
remoted.sender_pool=4
```

## Monitoring

Enable statistics in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

```conf
remoted.state_interval=5
```

View statistics: `cat /var/wazuh-manager/var/run/wazuh-manager-remoted.state`

Enable `debug2` logging:

```conf
remoted.debug=2
```

## References

- [Remote Configuration reference](../../configuration/remote.md)
- [Stateless Metadata](stateless-metadata.md)
- [Remoted Architecture](architecture.md)
- [Event Protocol](event-protocol.md)
