# Remoted Configuration Reference

Complete configuration reference for the Remoted module.

The remoted module is responsible for managing secure communication between Wazuh agents and the manager. It handles agent connections, authentication, message routing, and event enrichment. This is a manager-only module.

For module overview and architecture, see [Remoted Module](index.html).

---

## Main Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<remote>`

**Module:** Manager-only

**Internal Options:** `remoted.*`

The remoted module configuration controls how the manager listens for and processes agent communications.

### port

Listening port for agent connections.

- **Default value:** `1514`
- **Allowed values:** Integer from `1` to `65535`
- **Note:** Standard port for Wazuh agent-manager communication

### protocol

Communication protocol(s) to accept from agents.

- **Default value:** `tcp`
- **Allowed values:** `tcp`, `udp`, or `tcp,udp`
- **Note:** TCP is recommended for reliable delivery; UDP may be used for low-latency environments

### queue_size

Message queue size for incoming agent messages.

- **Default value:** `131072`
- **Allowed values:** Positive integer
- **Note:** Values greater than `262144` will generate a warning; adjust based on agent count and event rate

### allow_higher_versions

Accept connections from agents running a Wazuh version higher than the manager.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Enable when upgrading agents before the manager

### ipv6

Enable IPv6 support for agent connections.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Allows agents to connect using IPv6 addresses

### local_ip

Bind remoted to a specific local IP address.

- **Default value:** All interfaces (`0.0.0.0` for IPv4, `::` for IPv6)
- **Allowed values:** Valid IPv4 or IPv6 address
- **Note:** Restricts remoted to listen only on specified interface

### rids_closing_time

Time to keep agent session IDs (RIDs) cached after agent disconnects.

- **Default value:** `300` (5 minutes)
- **Allowed values:** Time value with optional suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days). Bare number defaults to seconds.
- **Example:** `300`, `5m`, `300s` are all equivalent
- **Note:** Prevents rapid reconnection issues; agent must wait this period before reusing same ID

### connection_overtake_time

Time in seconds before allowing a new connection to overtake an existing agent connection with the same ID.

- **Default value:** `60`
- **Allowed values:** Integer from `0` to `3600` (seconds)
- **Note:** Set to `0` to disable overtake protection (allows immediate reconnection); higher values provide more protection against connection hijacking while requiring longer wait for legitimate agent restarts

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

**Internal Options prefix:** `remoted.*`

Internal options provide advanced tuning for performance, threading, memory management, and monitoring.

### remoted.debug

Debug logging level for remoted module.

- **Default value:** `0`
- **Allowed values:** `0` (disabled), `1` (basic), `2` (verbose)
- **Note:** Use `debug2` for troubleshooting; generates significant log volume

### remoted.receive_chunk

Network receive buffer size in bytes.

- **Default value:** `4096`
- **Allowed values:** Positive integer
- **Note:** Larger values may improve throughput on high-bandwidth networks

### remoted.send_timeout_to_retry

Timeout in seconds before retrying a failed send operation.

- **Default value:** `1`
- **Allowed values:** Positive integer
- **Note:** Lower values increase retry frequency; higher values reduce network overhead

### remoted.worker_pool

Number of worker threads for processing agent messages.

- **Default value:** `4`
- **Allowed values:** Positive integer
- **Note:** Increase for high-throughput environments (e.g., `8` for >50K events/sec)

### remoted.sender_pool

Number of sender threads for forwarding events to the engine.

- **Default value:** `8`
- **Allowed values:** Positive integer
- **Note:** Increase for high-throughput environments (e.g., `16` for >50K events/sec)

### remoted.control_msg_queue_size

Queue size for agent keep-alive and control messages.

- **Default value:** `16384`
- **Allowed values:** Positive integer
- **Note:** Increase for large agent counts (e.g., `32768` for >10K agents)

### remoted.batch_events_capacity

Queue capacity for batching events before forwarding to the engine.

- **Default value:** `131072`
- **Allowed values:** Positive integer
- **Note:** Increase for high event rates (e.g., `262144` for >50K events/sec)

### remoted.queue_max_bytes

Maximum bytes held in the input message queue (messages received from agents).

- **Default value:** `67108864` (64 MiB)
- **Allowed values:** `0` (unlimited) or integer from `1024` upward
- **Note:** Caps memory usage; events exceeding the limit are dropped; set to `0` to disable byte limiting

### remoted.batch_events_max_bytes

Maximum bytes held in the events queue (events forwarded to the engine).

- **Default value:** `33554432` (32 MiB)
- **Allowed values:** `0` (unlimited) or integer from `1024` upward
- **Note:** Caps memory usage; events exceeding the limit are dropped; set to `0` to disable byte limiting

### remoted.enrich_cache_expire_time

Agent metadata cache expiration time in seconds.

- **Default value:** `300` (5 minutes)
- **Allowed values:** Integer from `60` to `86400`
- **Note:** Entries older than this threshold are cleaned up periodically; adjust based on agent stability (ephemeral: `300`, stable: `600-1800`)

### remoted.keyupdate_interval

Interval in seconds for reloading agent key files.

- **Default value:** `10`
- **Allowed values:** Positive integer
- **Note:** Lower values detect new agents faster but increase I/O overhead

### remoted.rlimit_nofile

Maximum number of open file descriptors for the remoted process.

- **Default value:** `458752`
- **Allowed values:** Positive integer
- **Note:** Increase for large agent counts (e.g., `131072` for >10K agents); default supports ~200K concurrent connections

### remoted.state_interval

Interval in seconds for writing statistics to the state file.

- **Default value:** `5`
- **Allowed values:** `0` (disabled) or positive integer
- **Note:** Set to `0` to disable statistics; lower values provide more frequent updates

### remoted.send_chunk

Maximum bytes to send in a single write operation to an agent.

- **Default value:** `4096` (4 KB)
- **Allowed values:** Positive integer (bytes)
- **Note:** Larger values may improve throughput but increase network buffer requirements

### remoted.buffer_relax

Send buffer flushing mode selector.

- **Default value:** `1`
- **Allowed values:** `0` (strict: flush immediately), `1` (relaxed: allow buffering with timeout), `2` (lazy: maximum batching)
- **Note:** Controls buffering behavior; `1` balances latency and throughput

### remoted.send_buffer_size

Size of send buffer per agent connection in bytes.

- **Default value:** `131072` (128 KB)
- **Allowed values:** Positive integer (bytes)
- **Note:** Larger buffers handle burst traffic better

### remoted.recv_timeout

Timeout in seconds for receiving data from agents.

- **Default value:** `1`
- **Allowed values:** Positive integer (seconds)
- **Note:** Agent marked as unresponsive if no data received within timeout

### remoted.tcp_keepidle

Time in seconds before sending TCP keepalive probes on idle connections.

- **Default value:** `30`
- **Allowed values:** Positive integer (seconds)
- **Note:** Helps detect dead connections; platform-specific support required

### remoted.tcp_keepintvl

Interval in seconds between TCP keepalive probes.

- **Default value:** `10`
- **Allowed values:** Positive integer (seconds)
- **Note:** Works with `tcp_keepidle` and `tcp_keepcnt`

### remoted.tcp_keepcnt

Number of unacknowledged TCP keepalive probes before considering connection dead.

- **Default value:** `3`
- **Allowed values:** Positive integer
- **Note:** Total dead detection time = `tcp_keepidle + (tcp_keepintvl × tcp_keepcnt)`

### remoted.merge_shared

Enable merging shared configuration files for agents.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Combines group-specific configurations; disable for troubleshooting

### remoted.pass_empty_keyfile

Allow remoted to start even if client.keys file is empty.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Useful for fresh installations; disable in production for security

### remoted.router_forwarding_disabled

Disable forwarding messages to the router component.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Set to `yes` to disable router integration (standalone manager mode)

### remoted.request_pool

Size of the request pool for handling agent communications.

- **Default value:** `1024`
- **Allowed values:** Positive integer
- **Note:** Increase for high-concurrency scenarios

### remoted.request_timeout

Timeout in seconds for agent request operations.

- **Default value:** `10`
- **Allowed values:** Positive integer (seconds)
- **Note:** Maximum time to wait for agent response

### remoted.response_timeout

Timeout in seconds for manager response operations to agents.

- **Default value:** `60`
- **Allowed values:** Positive integer (seconds)
- **Note:** Maximum time for manager to respond to agent requests

### remoted.request_rto_sec

Retransmission timeout (seconds part) for agent requests.

- **Default value:** `1`
- **Allowed values:** Positive integer (seconds)
- **Note:** Combined with `request_rto_msec` for total RTO

### remoted.request_rto_msec

Retransmission timeout (milliseconds part) for agent requests.

- **Default value:** `0`
- **Allowed values:** `0-999` (milliseconds)
- **Note:** Fine-tune retransmission timing for lossy networks

### remoted.max_attempts

Maximum retry attempts for failed agent communications.

- **Default value:** `4`
- **Allowed values:** Positive integer
- **Note:** After this many failures, operation is abandoned

### remoted.shared_reload

Interval in seconds for reloading shared configuration files.

- **Default value:** `10`
- **Allowed values:** Positive integer (seconds)
- **Note:** How often remoted checks for changes in `shared/` directory

### remoted.disk_storage

Enable disk-based storage for agent event queue persistence.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Persists queued events across remoted restarts; impacts I/O performance

### remoted.verify_msg_id

Verify message ID sequence from agents to detect tampering or replay attacks.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Enable for additional security; may cause issues with clock skew or agent restarts

### remoted.batch_events_per_agent_capacity

Maximum events to batch per agent before forwarding to engine.

- **Default value:** `131072`
- **Allowed values:** Positive integer
- **Note:** Higher values improve throughput but increase latency

### remoted.recv_counter_flush

Message count threshold for flushing receive counters to statistics.

- **Default value:** `128`
- **Allowed values:** Positive integer (message count)
- **Note:** Counters are flushed after this many messages received; internal monitoring metric

### remoted.comp_average_printout

Event count threshold for logging compression statistics.

- **Default value:** `19999`
- **Allowed values:** Integer from `10` to `999999` (event count)
- **Note:** Compression stats logged after this many events processed

### HTTPS Agent Server (`remoted_module`)

Advanced tuning for the experimental HTTPS agent server (see
[HTTPS Events API](https-events-api.md)). These are RESTinio transport settings, not part
of the regular `<remote>` configuration -- bind address, port and max body size are
regular `<remote>` settings instead (see [HTTPS Events API](https-events-api.md#configuration)).
An option present in `wazuh-manager-internal-options.conf` but out of its allowed range (or
non-numeric) prevents `remoted` from starting, same as every other internal option.

#### remoted.http_io_threads

Number of I/O threads (accept + read/write) for the HTTPS agent server.

- **Default value:** `2`
- **Allowed values:** Integer from `1` to `64`

#### remoted.http_worker_threads

Number of worker threads that run endpoint handlers (auth + business logic), off the I/O threads.

- **Default value:** `4`
- **Allowed values:** Integer from `1` to `256`

#### remoted.http_read_timeout

Seconds to wait for a full request to arrive on a connection.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `300`
- **Note:** The clock starts as soon as the connection is established, so this also bounds a
  stalled TLS handshake -- there is no separate handshake timeout

#### remoted.http_write_timeout

Seconds to wait for a response write to complete.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `300`

#### remoted.http_request_timeout

Seconds a request may take to be handled end-to-end.

- **Default value:** `30`
- **Allowed values:** Integer from `1` to `600`

#### remoted.http_max_url_size

Maximum accepted URL size, in bytes.

- **Default value:** `2048`
- **Allowed values:** Integer from `1` to `65536`

#### remoted.http_max_header_name_size

Maximum accepted HTTP header name size, in bytes.

- **Default value:** `256`
- **Allowed values:** Integer from `1` to `8192`

#### remoted.http_max_header_value_size

Maximum accepted HTTP header value size, in bytes.

- **Default value:** `8192`
- **Allowed values:** Integer from `1` to `65536`

#### remoted.http_max_header_count

Maximum number of HTTP headers accepted per request.

- **Default value:** `64`
- **Allowed values:** Integer from `1` to `1024`

#### remoted.http_max_pipelined_requests

Maximum in-flight unanswered requests per connection (HTTP pipelining depth).

- **Default value:** `4`
- **Allowed values:** Integer from `1` to `64`

#### remoted.http_concurrent_accepts

Maximum concurrent in-progress TCP accepts for the HTTPS agent server.

- **Default value:** `2`
- **Allowed values:** Integer from `1` to `64`

#### remoted.http_buffer_size

Socket read buffer size for the HTTPS agent server, in bytes.

- **Default value:** `8192`
- **Allowed values:** Integer from `1` to `1048576` (1 MiB)

---

## Configuration Examples

### Default Configuration

Standard settings for most deployments:

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

### UDP and TCP Support

Accept agent connections via both TCP and UDP protocols:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp,udp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

### Large Agent Deployments (>10K agents)

Optimized for high agent counts:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>262144</queue_size>
  </remote>
</wazuh_config>
```

Internal options (`/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`):

```conf
remoted.control_msg_queue_size=32768
remoted.keyupdate_interval=30
remoted.rlimit_nofile=131072
```

### High Throughput (>50K events/sec)

Optimized for high event rates:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>262144</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
remoted.control_msg_queue_size=32768
remoted.batch_events_capacity=262144
remoted.worker_pool=8
remoted.sender_pool=16
```

### Low Memory Environments

Reduced memory footprint for resource-constrained systems:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>65536</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
remoted.control_msg_queue_size=4096
remoted.batch_events_capacity=32768
remoted.worker_pool=2
remoted.sender_pool=4
```

### Ephemeral Agents (Short-Lived)

Optimized for ephemeral or containerized agents with frequent restarts:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
# Short cache expiration for ephemeral agents
remoted.enrich_cache_expire_time=300

# Standard queue sizes
remoted.control_msg_queue_size=16384
remoted.batch_events_capacity=131072
```

### Stable Long-Running Agents

Optimized for stable, long-running agents with infrequent restarts:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
# Longer cache expiration for stable agents
remoted.enrich_cache_expire_time=1800

# Standard queue sizes
remoted.control_msg_queue_size=16384
remoted.batch_events_capacity=131072
```

### Allow Higher Agent Versions

Allow agents with newer Wazuh versions to connect during rolling upgrades:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
    <agents>
      <allow_higher_versions>yes</allow_higher_versions>
    </agents>
  </remote>
</wazuh_config>
```

### Memory-Capped Queues

Limit memory consumption with byte caps regardless of event count:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
# Cap input queue at 128 MiB
remoted.queue_max_bytes=134217728

# Cap events queue at 64 MiB
remoted.batch_events_max_bytes=67108864
```

---

## Queue Byte Limits

The byte limit options (`remoted.queue_max_bytes` and `remoted.batch_events_max_bytes`) cap the total memory used by queues regardless of event count. This is useful when agents send large events that would otherwise cause unbounded memory growth even at normal event rates.

### Behavior When Limits Are Reached

- Events that individually exceed the limit are dropped immediately
- Events that would push the total over the limit are dropped until space is freed
- Dropped events increment the same discard counter as a full queue (`discarded_count` in the state file)
- A warning is logged at most once every 5 seconds to avoid log flooding

### Guidelines

- The byte limit and event-count limit (`batch_events_capacity`) are independent. An event is dropped if either limit is reached.
- Values between `1` and `1023` bytes are rejected at startup as they are almost certainly a configuration error.
- Set to `0` to revert to count-only limiting.

### Sizing Examples

**Small deployments (<1K agents):**
```conf
remoted.control_msg_queue_size=4096
remoted.batch_events_capacity=32768
```

**Medium deployments (1K-10K agents):**
```conf
remoted.control_msg_queue_size=16384
remoted.batch_events_capacity=131072
```

**Large deployments (>10K agents):**
```conf
remoted.control_msg_queue_size=32768
remoted.batch_events_capacity=262144
```

---

## Stateless Metadata Cache

The stateless metadata cache stores agent metadata extracted from keep-alive messages to enrich stateless events.

### Cache Expiration Guidelines

**Ephemeral/short-lived agents:**
```conf
remoted.enrich_cache_expire_time=300  # 5 minutes (default)
```

**Stable agents with occasional restarts:**
```conf
remoted.enrich_cache_expire_time=600  # 10 minutes
```

**Long-running stable agents:**
```conf
remoted.enrich_cache_expire_time=1800  # 30 minutes
```

The cleanup process runs every 60 seconds and removes entries that haven't received a keep-alive in the configured time period.

### Hash Table Tuning

Metadata cache bucket count (requires recompile of `src/remoted/agent_metadata_db.c`):

**<10K agents:**
- Default: 2048 buckets

**10K-50K agents:**
- Recommended: 4096 buckets

**>50K agents:**
- Recommended: 8192 buckets

---

## Monitoring

### Enable Statistics

Enable statistics in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

```conf
remoted.state_interval=5
```

View statistics:
```bash
cat /var/wazuh-manager/var/run/wazuh-manager-remoted.state
```

### Enable Debug Logging

Enable verbose logging in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

```conf
remoted.debug=2
```

View logs:
```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep remoted
```

### Check Queue Status

Monitor queue depths and dropped events:
```bash
# View state file
cat /var/wazuh-manager/var/run/wazuh-manager-remoted.state

# Watch for discarded events
grep "discarded_count" /var/wazuh-manager/var/run/wazuh-manager-remoted.state
```

---

## See Also

- [Remoted Module](index.html) - Module overview and architecture
- [Stateless Metadata](stateless-metadata.md) - Agent metadata caching system
- [Event Protocol](event-protocol.md) - Agent-manager communication protocol
- [Architecture](architecture.md) - Module design and implementation
- [Quick Reference](quick-reference.md) - Command reference and troubleshooting
