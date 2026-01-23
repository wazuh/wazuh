# Remoted Configuration

Configuration options for remoted module.

## XML Configuration

File: `/var/ossec/etc/ossec.conf`

### Key Options

```xml
<ossec_config>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
    <allow_higher_versions>yes</allow_higher_versions>
  </remote>
</ossec_config>
```

| Option | Default | Description |
|--------|---------|-------------|
| `connection` | `secure` | Connection type: secure (encrypted) or syslog |
| `port` | `1514` | Listening port |
| `protocol` | `tcp` | Protocol: tcp, udp, or tcp,udp |
| `queue_size` | `131072` | Message queue size |
| `allow_higher_versions` | `yes` | Allow agents with higher version |

## Internal Options

File: `/var/ossec/etc/internal_options.conf` or `/var/ossec/etc/local_internal_options.conf`

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

Enable statistics in `/var/ossec/etc/internal_options.conf`:

```conf
remoted.state_interval=5
```

View statistics: `cat /var/ossec/var/run/wazuh-remoted.state`

Enable debug logging:

```conf
remoted.debug=2
```

## References

- [Stateless Metadata](stateless-metadata.md)
- [Remoted Architecture](architecture.md)
- [Event Protocol](event-protocol.md)
- [Wazuh Configuration Guide](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html)
