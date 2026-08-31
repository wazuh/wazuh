# Remoted Configuration Reference

Complete configuration reference for the Remoted module.

The remoted module is responsible for managing secure communication between Wazuh agents and the manager. It handles agent connections, authentication, message routing, and event enrichment. This is a manager-only module.

For module overview and architecture, see [Remoted Module](README.md).

---

## Main Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<remote>`

**Module:** Manager-only

**Internal Options:** `remoted.*`

The remoted module configuration controls how the manager listens for and processes agent communications.


### legacy.enabled

Enable the classic TCP/UDP listener and every subsystem that only serves 4.x agents
(the legacy `remote_upgrade` task-delivery poller, the `merged.mg` push, the
control/event dispatch threads, the per-agent metadata cache cleanup thread, the
message-handler worker pool, and the fd closer thread).

- **Default value:** `yes` when `<legacy>` is present; absence of the whole `<legacy>`
  block is equivalent to `no`
- **Allowed values:** `yes`, `no`
- **Note:** With `no`, remoted binds no legacy socket and starts no legacy thread; only
  5.x agents (served over `<https>`) can connect. `merged.mg`/group generation stays on
  regardless, since the HTTPS `/download` endpoint also serves it to 5.x agents.
  Disabling this also causes `remote_upgrade` task creation for agents below v5.0.0 to be
  rejected at creation time, since there is no delivery path for them anymore.

### legacy.port

Listening port for agent connections.

- **Default value:** `1514`
- **Allowed values:** Integer from `1` to `65535`
- **Note:** Standard port for Wazuh agent-manager communication

### legacy.protocol

Communication protocol(s) to accept from agents.

- **Default value:** `tcp`
- **Allowed values:** `tcp`, `udp`, or `tcp,udp`
- **Note:** TCP is recommended for reliable delivery; UDP may be used for low-latency environments

### legacy.queue_size

Message queue size for incoming agent messages.

- **Default value:** `131072`
- **Allowed values:** Positive integer
- **Note:** Values greater than `262144` will generate a warning; adjust based on agent count and event rate

### agents.allow_higher_versions

Accept connections from agents running a Wazuh version higher than the manager.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Enable when upgrading agents before the manager

### legacy.ipv6

Enable IPv6 support for agent connections.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Allows agents to connect using IPv6 addresses

### legacy.local_ip

Bind remoted to a specific local IP address.

- **Default value:** `127.0.0.1` (loopback-only) when `ipv6` is `no`; all IPv6 interfaces (`::`)
  when `ipv6` is `yes` (the `127.0.0.1` default only applies in IPv4 mode)
- **Allowed values:** Valid IPv4 or IPv6 address
- **Note:** Restricts remoted to listen only on the specified interface. Set to `0.0.0.0` to
  accept agent connections from any IPv4 interface. The shipped `wazuh-manager.conf` and
  install-time template ship the loopback-only default as-is; an operator who wants
  remote agents must add `<local_ip>0.0.0.0</local_ip>` after install.

### legacy.rids_closing_time

Time to keep agent session IDs (RIDs) cached after agent disconnects.

- **Default value:** `300` (5 minutes)
- **Allowed values:** Time value with optional suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days). Bare number defaults to seconds.
- **Example:** `300`, `5m`, `300s` are all equivalent
- **Note:** Prevents rapid reconnection issues; agent must wait this period before reusing same ID

### legacy.connection_overtake_time

Time in seconds before allowing a new connection to overtake an existing agent connection with the same ID.

- **Default value:** `60`
- **Allowed values:** Integer from `0` to `3600` (seconds)
- **Note:** Set to `0` to disable overtake protection (allows immediate reconnection); higher values provide more protection against connection hijacking while requiring longer wait for legitimate agent restarts

---

## HTTPS Configuration

**XML Section:** `<remote><https>`

Configuration for the RESTinio-based HTTPS listener. All options are optional; an absent `<https>` block (or an absent individual option) falls back to the module's built-in defaults, so the listener is usable without configuring anything here. There is no `enabled` toggle: the listener always attempts to start, and self-gates on the presence of a valid certificate/key.

### https.port

HTTPS listening port.

- **Default value:** `1517`
- **Allowed values:** Integer from `1` to `65535`

### https.bind_addr

Address the HTTPS listener binds to.

- **Default value:** `127.0.0.1`
- **Allowed values:** Valid IPv4 or IPv6 address
- **Note:** `0.0.0.0` is IPv4-only. `::` listens on IPv6 only by default -- it does **not** also
  accept IPv4 connections unless `dual_stack` is explicitly set to `yes` -- see
  [HTTPS Agent API: Bind address](https-events-api.md#bind-address-ipv4-ipv6-and-dual-stack)
  for the full explanation.

### https.global_prefix

URL path prefix every HTTPS endpoint is served under: with `/wazuh-manager/` configured,
`POST /stateless` is exposed as `POST /wazuh-manager/stateless` and the health probe as
`GET /wazuh-manager/`. With a prefix in effect, the unprefixed paths answer `404`.

This is a **URL path**, unrelated to the installation directory `/var/wazuh-manager` despite the
similar spelling: nothing on disk is looked up under it.

- **Default value:** `/` (no prefix) when the tag is absent — an upgraded configuration keeps
  serving today's unprefixed endpoints. Freshly generated configurations ship
  `/wazuh-manager/`.
- **Allowed values:** `/` (explicit "no prefix"), or `/segment[/segment...]` with an optional
  trailing slash. Characters `A-Z a-z 0-9 . _ ~ -` and `/`; no empty (`//`) or `.`/`..`
  segments, no percent-encoding; at most 255 characters. Any other value is rejected as a
  configuration error (`wazuh-manager-remoted -t` reports it).
- **Note:** the prefix is a routing matter only. The manager routes on the request target exactly
  as sent — prefix included — so agents must send the full prefixed path, and any proxy in between
  must forward the path untouched. The bearer token does not bind the target, so a prefix mismatch
  between agent and manager (or a proxy-side rewrite) surfaces as `404`, never as `401`. The prefix
  counts toward `remoted.http_max_url_size`. Only the public HTTPS listener is prefixed; the
  local admin socket is not. See
  [HTTPS Events API](https-events-api.md#authentication-jwt-bearer).

### https.dual_stack

Whether an IPv6 `bind_addr` (e.g. `::`) also accepts IPv4 clients on the same socket
(the `IPV6_V6ONLY` socket option).

- **Default value:** `no` (force IPv6-only)
- **Allowed values:** `yes` (force dual-stack on), `no` (force IPv6-only); any other value is
  rejected as a configuration error
- **Note:** Only meaningful when `bind_addr` is IPv6; ignored (with a warning) for an IPv4
  `bind_addr`. See [HTTPS Agent API: Bind address](https-events-api.md#bind-address-ipv4-ipv6-and-dual-stack).

### https.certificate

Path to the TLS certificate chain (PEM) presented by the server.

- **Default value:** `etc/certs/remoted.pem` (relative to the manager's chroot)
- **Note:** at startup the manager warns if this certificate has expired or expires within 30 days,
  so a silent outage for verifying agents can be prevented before it happens.

### https.key

Path to the TLS private key (PEM) matching `certificate`.

- **Default value:** `etc/certs/remoted-key.pem` (relative to the manager's chroot)

### https.ca

Path to a CA bundle (PEM) used to verify client (agent) certificates.

- **Default value:** `etc/certs/root-ca.pem` (relative to the manager's chroot)
- **Note:** Only actually read when `verification_mode` is `certificate`; harmless
  if left at its default and `verification_mode` stays `none`. See the special case below.

### https.verification_mode

Client-certificate verification strictness.

- **Default value:** `none`
- **Allowed values:**
  - `none` — the client certificate is not verified.
  - `certificate` — the client certificate chain is validated against `ca`.
  - `full` — same as `certificate`, plus the address the peer connects from must appear as an
    IP entry in that certificate's Subject Alternative Name. A connection whose certificate is
    valid but lists a different address is answered `403` on every route, including the
    unauthenticated health probe, and a throttled warning naming the address is logged.
- **What these modes authenticate:** whoever **opens the connection**. On a direct
  agent-to-manager connection that is the agent. Behind a TLS-terminating reverse proxy or
  load balancer it is the **proxy**, because the agent's TLS session ends there and a new one
  is opened towards the manager — the agent's certificate cannot cross that boundary. In that
  topology `certificate` is still valuable (only your proxy can reach the listener), but it
  does **not** authenticate agents: an agent presenting no certificate at all is still
  accepted. Requiring certificates from agents behind a proxy is configured on the proxy.
- **Before choosing `full`:** for the same reason, the address it checks is the **proxy's**
  whenever one terminates TLS, so behind a proxy the mode constrains where your proxy may
  connect from, not where agents may. It fits a direct deployment, or one where the balancer
  preserves the client address at network level. It also requires every agent certificate to
  carry the agent's address in its SAN, which has to be reissued whenever that address changes.
- **Note:** any other value is rejected as a configuration error (the config test fails), so a
  typo cannot silently leave client-certificate verification disabled.
- **Special case:** if `<ca>` is explicitly configured in XML but `<verification_mode>` is not, the manager defaults `verification_mode` to `certificate` instead of `none`, and logs a warning explaining the override. An explicit `<verification_mode>` (including `none`) always wins over this inference.

### https.ciphers

TLS 1.3 ciphersuite override for the HTTPS listener (`SSL_CTX_set_ciphersuites()` naming
scheme, e.g. `TLS_AES_256_GCM_SHA384`). The listener requires TLS 1.3 as its minimum
protocol version.

- **Default value:** `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`
- **Allowed values:** colon-separated TLS 1.3 ciphersuite name string. The value is validated at
  configuration-parse time: a name that is not a TLS 1.3 suite (for example a TLS 1.2 string such
  as `HIGH:!ADH`) is rejected so the config test catches it, instead of the listener failing to
  start at runtime.

### https.max_body_size

Maximum accepted HTTP request body size.

- **Default value:** `20MB`
- **Allowed values:** Size with optional unit suffix (`B`, `KB`, `MB`, `GB`); bare number defaults to bytes.

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
- **Note:** Level `2` is also what reveals the HTTPS agent server's per-request rejection reasons
  (malformed or unauthenticated requests). Those are kept at debug because an unauthenticated client
  controls how many it can trigger; conditions an operator can act on are logged at info or warning
  level regardless of this setting — including a rejection caused by the agent's registered address no
  longer matching. See
  [Diagnosing rejections and capacity problems](https-events-api.md#diagnosing-rejections-and-capacity-problems).

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

### remoted.legacy_task_polling_interval

Interval in seconds between polls of the Task Manager's pending tasks on behalf of connected
agents older than v5.0.0. Every cycle, `remoted` checks each connected agent's self-reported
version and, for agents confirmed below v5.0.0, asks the Task Manager for pending tasks and
delivers any `remote_upgrade` (WPK) one over the agent's existing session — see
[Remote agent upgrade](../../../guide/migration/remote-agent-upgrade.md) for the full delivery flow.

- **Default value:** `900` (15 minutes)
- **Allowed values:** Integer from `300` to `86400`
- **Note:** Must be configured comfortably smaller than the Task Manager's own `task-manager.task_ttl`
  (default `3600`s, see [Task Manager configuration](../task_manager/configuration.md)) — a task created just
  after a poll cycle must still be `pending` when the next cycle runs, or it can flip to `expired` before
  ever being delivered.

### remoted.keyupdate_interval

Interval in seconds for reloading agent key files. Also governs the HTTPS agent server's
`remoted_module` C++ `Keystore` (see [HTTPS Agent API](https-events-api.md)): it hot-reloads
`client.keys` on its own (an `inotify` subscription reacts immediately; this interval is only the
periodic fallback poll, in case a notification is ever missed), reusing this same option instead of
introducing a second one for the same concept.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `3600`
- **Note:** Lower values detect new agents faster but increase I/O overhead. Whether the C++
  keystore's reloads are actually happening (and succeeding) is visible as
  `remoted.auth.keystore.*` in
  [`GET /metrics`](metrics.md#keystore-health--remotedauthkeystore)

### remoted.rlimit_nofile

Maximum number of open file descriptors for the remoted process.

- **Default value:** `458752`
- **Allowed values:** Positive integer
- **Note:** The default already supports ~200K concurrent connections. Only increase above the default (up to the allowed maximum of `1048576`) if you observe file-descriptor exhaustion under very large agent counts — do not set below the default of `458752`.

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

Advanced tuning for the HTTPS agent server (see
[HTTPS Agent API](https-events-api.md)): RESTinio transport settings (`remoted.http_*`) plus the
downstream UDS client and auth middleware tunables (`remoted.downstream_*`, `remoted.auth_*`,
further down this section). None of these are part of the regular `<remote>` configuration --
bind address, port and max body size are regular `<remote>` settings instead (see
[HTTPS Agent API](https-events-api.md#configuration)). An option present in
`wazuh-manager-internal-options.conf` but out of its allowed range (or non-numeric) prevents
`remoted` from starting, same as every other internal option.

#### remoted.http_io_threads

Number of I/O threads (accept + read/write) for the HTTPS agent server.

- **Default value:** `0` (auto: resolves to `cpp_get_nproc()`, the number of CPUs available to the
  process -- cgroup-aware on Linux)
- **Allowed values:** Integer from `0` to `64`

#### remoted.http_worker_threads

Number of worker threads that run endpoint handlers (auth + business logic), off the I/O threads.

- **Default value:** `0` (auto: resolves to `2 * cpp_get_nproc()` -- oversubscribed because this
  work can block on token verification and `client.keys` file I/O)
- **Allowed values:** Integer from `0` to `256`
- **Note:** Size it from the end-to-end latency histograms (`remoted.http.stateless.latency`,
  `remoted.http.stateful.latency`) in
  [`GET /metrics`](metrics.md#request-latency--remotedhttpendpointlatency)

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
- **Note:** The end-to-end latency histograms in
  [`GET /metrics`](metrics.md#request-latency--remotedhttpendpointlatency) are measured against
  this cap: a p99 creeping toward it predicts request cutoffs before they happen

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

#### remoted.max_inflight_bytes

Maximum in-flight (unprocessed) request payload bytes before the HTTPS server sheds load with HTTP 503.

- **Default value:** `268435456` (256 MiB)
- **Allowed values:** Integer from `1048576` (1 MiB) to `1073741824` (1 GiB)
- **Note:** The C++ side clamps this up to at least one max-size request at startup, so a too-small
  value cannot reject everything. This is NOT `legacy.queue_size` (that is an event COUNT, not bytes).
  Live occupancy and the cumulative shed count are visible as `remoted.server.budget.*` in
  [`GET /metrics`](metrics.md#public-transport-backpressure--remotedserverbudget).

#### remoted.max_parallel_connections

Maximum simultaneous HTTPS connections.

- **Default value:** `512`
- **Allowed values:** Integer from `1` to `65536`
- **Note:** Bounds the read-phase memory peak (~`max_parallel_connections` × `max_body_size`). Also
  the only bound on concurrent streamed responses (`POST /download`): chunked output rearms
  `remoted.http_write_timeout` per chunk, so a slow-but-steady reader can hold a transfer open
  indefinitely and there is no per-stream limiter. A mass upgrade (the whole fleet fetching a WPK
  at once, many over slow links) is therefore bounded only by this value. Started transfers and
  offered bytes are visible as `remoted.download.*` in
  [`GET /metrics`](metrics.md#downloads--remoteddownload).

#### remoted.max_deferred_requests

Maximum requests parked awaiting a downstream service before replying with HTTP 503.

- **Default value:** `256`
- **Allowed values:** Integer from `1` to `65536`
- **Note:** No `Retry-After` header is sent; the agent runs its own retry/backoff on a 503. If you
  see warnings about this limit being reached, consider increasing it or investigating why the
  downstream service is slow. Live occupancy and the cumulative shed count are visible as
  `remoted.forwarder.deferred.*` in
  [`GET /metrics`](metrics.md#deferred-forwarding--remotedforwarderdeferred).

#### remoted.http_stream_chunk_size

Bytes per chunk when streaming a response body (`POST /download`).

- **Default value:** `65536` (64 KiB)
- **Allowed values:** Integer from `4096` to `1048576` (1 MiB)
- **Note:** Charged per *in-flight transfer*, so the worst case is roughly this value times the
  number of simultaneous downloads. A larger chunk buys fewer read/write round trips (less CPU per
  byte) at the cost of more memory while transfers are running. It does not change the bytes
  delivered -- only how they are framed on the wire.

> **The three timeouts below are sequential phases of one request, and the sum matters.**
> `remoted.http_request_timeout` bounds the *whole* request and its clock starts before the
> downstream call, so if `connect + write + response` exceeds it, the HTTP server tears the request
> down before the downstream deadline is ever reached. `remoted` logs a warning at startup when that
> is the case. Each phase has its own log message naming its own setting, so the log tells you which
> one elapsed — and its own counter (`remoted.forwarder.error.*`) in
> [`GET /metrics`](metrics.md#downstream-failures--remotedforwarder), so the totals tell you which
> one dominates.

#### remoted.http_content_encoding_enabled

Whether the HTTPS listener accepts request bodies compressed with `Content-Encoding: zstd`. When
disabled, a request carrying that header is rejected with `415 Unsupported Content-Encoding`, the
same as any unrecognized encoding. Bodies sent without a `Content-Encoding` header are unaffected
either way.

Unlike the numeric options above, this is a boolean: it has no "unset" sentinel, so a value absent
from the configuration file resolves to the default (enabled) on the C side before it reaches the
module.

- **Default value:** `1` (enabled)
- **Allowed values:** `0` (disabled) or `1` (enabled)

#### remoted.downstream_connect_timeout

Seconds to wait for the downstream UDS connect (to the engine's event ingress) to complete.

- **Default value:** `2`
- **Allowed values:** Integer from `1` to `60`
- **Note:** Exceeding it logs *"Timed out connecting to the downstream service"*. A connection
  *refused* immediately (rather than timing out) means nothing is listening on the socket and is
  reported differently.

#### remoted.downstream_write_timeout

Seconds to wait for the request body write to the downstream service to complete.

- **Default value:** `5`
- **Allowed values:** Integer from `1` to `300`
- **Note:** Only reached when the downstream service accepts the connection but does not drain its
  socket. Without this bound such a peer would pin the request's deferred-work slot indefinitely.

#### remoted.downstream_response_timeout

Seconds to wait for the downstream service's response after the write completes.

- **Default value:** `5`
- **Allowed values:** Integer from `1` to `300`
- **Note:** This is the global default. An endpoint whose handler legitimately takes much longer can
  declare its own deadline instead of forcing this value up for every endpoint (which would delay
  detection of a genuinely hung downstream on the fast ones).

#### remoted.downstream_stateful_response_timeout

Seconds to wait for the inventory sync server's answer to a relayed `POST /stateful` request.

- **Default value:** `20`
- **Allowed values:** Integer from `1` to `3600`
- **Note:** Dedicated to the `/stateful` route: a synchronization session is validated, indexed and
  flushed to the indexer WITHIN the request, so it cannot ride the global 5-second default. The
  default keeps the total downstream budget (connect + write + response = 2+5+20 s) inside
  `remoted.http_request_timeout`'s default (30 s); raising it past that requires raising the
  request cap too, or the HTTP server cuts the request off first (remoted warns at startup when
  the deadlines cannot be honored).

#### remoted.downstream_io_threads

Number of threads running the downstream UDS client's `io_context`.

- **Default value:** `0` (auto: resolves to `cpp_get_nproc()`)
- **Allowed values:** Integer from `0` to `256`

#### remoted.downstream_post_process_threads

Number of threads running the per-endpoint post-processors (build/deliver the reply once the
downstream service answers).

- **Default value:** `0` (auto: resolves to `cpp_get_nproc()`)
- **Allowed values:** Integer from `0` to `256`

#### remoted.downstream_max_response_body_size

Cap on a downstream response body, in bytes.

- **Default value:** `10485760` (10 MiB)
- **Allowed values:** Integer from `1048576` (1 MiB) to `67108864` (64 MiB)

#### remoted.jwt_max_age

Maximum **age** (seconds) of an agent's bearer token (`wazuh-agent+jwt`) the auth middleware accepts:
a token is usable while `now - iat <= jwt_max_age + jwt_clock_skew`. The token's declared lifetime
(`exp - iat`) is a fixed 60 s of the profile and is not configurable; this option (together with
`jwt_clock_skew` below) governs how much manager/agent clock drift is tolerated before an otherwise
valid token is rejected as stale.

- **Default value:** `60`
- **Allowed values:** Integer from `1` to `43200` (12h, the profile maximum -- a larger value keeps
  remoted from starting)
- **Note:** Rejections against the time window (too old, expired, or issued in the future) are
  visible as `remoted.auth.reject.clock_skew` in
  [`GET /metrics`](metrics.md#authentication-rejections--remotedauthreject). A moving counter
  usually means unsynchronized agent clocks — fix NTP before widening the window. Widening it also
  widens the replay window of a captured token (this profile has no replay store); rely on it only
  as far as the deployment's clock drift actually requires.

#### remoted.jwt_clock_skew

Tolerated clock difference (seconds) between an agent and the manager, applied in both directions:
a token may be issued up to `jwt_clock_skew` seconds in the future, and is still accepted up to
`jwt_clock_skew` seconds after its `exp`. This is the option that matters most for tolerating a real
manager/agent clock difference -- `jwt_max_age` above bounds total token age, but a clock skew
between the two hosts is compensated for here.

- **Default value:** `30`
- **Allowed values:** Integer from `0` to `43200` (12h, the profile maximum; `0` means no tolerance
  at all)
- **Note:** Shares the `remoted.auth.reject.clock_skew` counter with `remoted.jwt_max_age` (see
  above). Also bounds the freshness window of `POST /enroll`. Widening it also widens the replay
  window of a captured token (this profile has no replay store).

#### remoted.auth_max_body_size

Hard cap on the authenticated request body size, in bytes (checked by the auth middleware,
independent of the transport's own body cap -- `http_max_body_size`, a regular `<remote>` setting,
not an internal option).

Applies to the body **as received on the wire**. It does not bound a `Content-Encoding: zstd` body
once decompressed -- that is bounded by the in-flight memory budget instead (`max_inflight_bytes`);
see [HTTPS Agent API](https-events-api.md#content-encoding-zstd). Rejections against either cap
are visible as `remoted.auth.reject.body_too_large` in
[`GET /metrics`](metrics.md#authentication-rejections--remotedauthreject).

- **Default value:** `10485760` (10 MiB)
- **Allowed values:** Integer from `1048576` (1 MiB) to `67108864` (64 MiB)

#### remoted.control_keepalive_throttle

Minimum seconds between two wazuh-db keepalive writes for the same agent. `notify` requests
arriving faster than this are answered normally but absorbed in memory without touching the
database.

- **Default value:** `60`
- **Allowed values:** Integer from `1` to `3600`
- **Note:** `last_keepalive` is refreshed by the first notify that is **not** throttled, that is,
  the first one arriving at or after the end of a window. A throttled notify never reaches the
  database, so the effective staleness of `last_keepalive` is up to one whole window. Two writes
  ignore the window: the first host-carrying notify, and the first notify after a `startup`
  (which must lift the agent out of the `pending` state a startup leaves in wazuh-db).
- **Note:** Keep it below half of `<global><agents_disconnection_time>` (default `15m`); remoted
  warns at startup from half upward. The staleness monitord compares against the threshold is the
  throttle plus the agent's notify interval, so any value at or above half can disconnect agents
  that are answering normally. Half rather than just below the threshold also bounds detection:
  monitord's sweep period is the disconnection time itself, so detection lands anywhere between
  one and two times it.
- **Note:** A value at or below the fleet's notify cadence suppresses nothing: the throttle can
  only drop a notify that arrives inside an open window. This is not checked at startup, because
  remoted does not know the agent's `notify_time`.
- **Note:** 5.x agents only. A 4.x keepalive is written by the legacy path, ungated, so a sizing
  table built from this option has to count 5.x agents alone.
- **Note:** The throttle state lives in remoted's in-memory registry, which is per node. An agent
  alternating between cluster nodes is throttled independently on each, so its worst-case
  database write rate is one write per window **per node**.

#### remoted.control_groups_refresh_interval

Seconds between refreshes of the cached shared-group listing used to answer `/control`.

- **Default value:** `60`
- **Allowed values:** Integer from `1` to `3600`
- **Note:** This is the propagation latency an agent sees for a change of group **membership**
  only. Group **content** travels on a different path: the merged-groups watcher picks up a
  changed `merged.mg` on inotify plus a poll, so content propagates in seconds while membership
  waits out this interval. At the defaults that is roughly 60 s against 10 s, and at the maximum
  of `3600` the two differ by about two orders of magnitude.
- **Note:** Editing `var/multigroups/<hash>/merged.mg` by hand is not a way to reproduce this:
  `remoted.shared_reload` (default `10`) regenerates the file and reverts the edit.

#### remoted.control_wdb_request_connections

Size of the wazuh-db connection pool the control plane uses.

- **Default value:** `4`
- **Allowed values:** Integer from `1` to `64`
- **Note:** Size it from the successful round-trip time: `remoted.control.wdb.latency` in
  [`GET /metrics`](metrics.md#control-plane--remotedcontrol) times the keepalive arrival rate
  tells you how many round trips must be in flight at once.

#### remoted.control_wdb_roundtrip_deadline

Milliseconds a single wazuh-db round-trip may take before the control handler gives up.

- **Default value:** `2000`
- **Allowed values:** Integer from `100` to `30000`
- **Note:** Exceeding it surfaces to the agent as a `503` on `/control`, and counts as
  `remoted.control.wdb_error` in
  [`GET /metrics`](metrics.md#control-plane--remotedcontrol). The healthy-round-trip
  distribution that sizes this deadline is `remoted.control.wdb.latency` (timeouts are
  deliberately excluded from the histogram).

#### remoted.control_wdb_max_queue_size

High-water mark for queued wazuh-db requests; over it the handler reports QueueFull.

- **Default value:** `10000`
- **Allowed values:** Integer from `100` to `1000000`
- **Note:** Queue-full failures also count as `remoted.control.wdb_error` in
  [`GET /metrics`](metrics.md#control-plane--remotedcontrol).

#### remoted.control_tm_concurrency

Concurrent task-manager requests the control plane may have in flight.

- **Default value:** `4`
- **Allowed values:** Integer from `1` to `64`

#### remoted.control_tm_deadline

Milliseconds a single task-manager round-trip may take.

- **Default value:** `2000`
- **Allowed values:** Integer from `100` to `30000`
- **Note:** Failures are visible as `remoted.control.task_fetch_error` in
  [`GET /metrics`](metrics.md#control-plane--remotedcontrol).

#### remoted.control_tm_max_queue_size

High-water mark for queued task-manager requests.

- **Default value:** `10000`
- **Allowed values:** Integer from `100` to `1000000`

#### remoted.enroll_password_refresh_interval

Seconds between polls of `etc/authd.pass` for Password-mode `POST /enroll`.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `3600`
- **Note:** Until a change is picked up, Password-mode enrollment keeps failing with the old
  key; those rejections count as `remoted.auth.reject.enrollment_key_unavailable` in
  [`GET /metrics`](metrics.md#authentication-rejections--remotedauthreject).

#### remoted.authd_connect_timeout

Seconds `remoted` waits to connect to `authd`'s local enrollment socket.

- **Default value:** `2`
- **Allowed values:** Integer from `1` to `60`
- **Note:** Exhausting it answers the agent `503` and counts as
  `remoted.enroll.authd_unavailable`; size it against
  [`remoted.http.enroll.latency`](metrics.md#request-latency--remotedhttpendpointlatency), the
  only measurement that spans the hop to `authd`.

#### remoted.authd_response_timeout

Seconds `remoted` waits for `authd`'s answer once connected.

- **Default value:** `0` (worker-aware default: short on the master, long enough on a worker to
  outlast `authd`'s own worker-to-master cluster retry budget)
- **Allowed values:** Integer from `0` to `120`
- **Note:** Same evidence as `authd_connect_timeout`; together they must stay under
  [`remoted.http_request_timeout`](configuration.md#remotedhttp_request_timeout), which the
  module warns about at startup.

#### remoted.authd_max_queue_size

Enrollment requests that may wait for an `authd` worker before further ones are refused.

- **Default value:** `256`
- **Allowed values:** Integer from `1` to `65536`
- **Note:** Visible as
  [`remoted.enroll.authd.queue.{depth,capacity}`](metrics.md#agent-enrollment--remotedenroll);
  refusals count in `remoted.enroll.authd.queue.rejected.total`, which is the saturation share
  of `remoted.enroll.authd_unavailable`.

#### remoted.authd_worker_threads

Concurrent connections `remoted` keeps to `authd` for enrollment.

- **Default value:** `8`
- **Allowed values:** Integer from `1` to `32`
- **Note:** Capped well under `authd`'s own local-socket listen backlog (128), so a larger pool
  gains nothing. Raise it when
  [`remoted.enroll.authd.queue.depth`](metrics.md#agent-enrollment--remotedenroll) sits near
  its capacity at peak.

---

## Configuration Examples

### Default Configuration

Standard settings for most deployments:

```xml
<wazuh_config>
  <remote>
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </legacy>
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
    <legacy>
      <port>1514</port>
      <protocol>tcp,udp</protocol>
      <queue_size>131072</queue_size>
    </legacy>
  </remote>
</wazuh_config>
```

### Large Agent Deployments (>10K agents)

Optimized for high agent counts:

```xml
<wazuh_config>
  <remote>
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>262144</queue_size>
    </legacy>
  </remote>
</wazuh_config>
```

Internal options (`/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`):

```conf
remoted.control_msg_queue_size=32768
remoted.keyupdate_interval=30
remoted.rlimit_nofile=524288
```

Only raise `rlimit_nofile` above its default (`458752`) if you observe file-descriptor exhaustion
under very large fleets; do not set it lower than the default for a scale-up scenario.

### High Throughput (>50K events/sec)

Optimized for high event rates:

```xml
<wazuh_config>
  <remote>
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>262144</queue_size>
    </legacy>
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
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>65536</queue_size>
    </legacy>
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
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </legacy>
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
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </legacy>
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
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </legacy>
    <agents>
      <allow_higher_versions>yes</allow_higher_versions>
    </agents>
  </remote>
</wazuh_config>
```

### HTTPS with Mutual TLS

Require and validate agent client certificates, including a full IP-to-certificate match:

```xml
<wazuh_config>
  <remote>
    <https>
      <port>1517</port>
      <bind_addr>0.0.0.0</bind_addr>
      <global_prefix>/wazuh-manager/</global_prefix>
      <certificate>etc/certs/remoted.pem</certificate>
      <key>etc/certs/remoted-key.pem</key>
      <ca>etc/certs/root-ca.pem</ca>
      <verification_mode>certificate</verification_mode>
      <ciphers>TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256</ciphers>
      <max_body_size>20MB</max_body_size>
    </https>
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </legacy>
  </remote>
</wazuh_config>
```

### Memory-Capped Queues

Limit memory consumption with byte caps regardless of event count:

```xml
<wazuh_config>
  <remote>
    <legacy>
      <port>1514</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </legacy>
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

### HTTPS agent server metrics (`GET /metrics`)

The C++ module keeps its own metric registry — request outcomes and latency per endpoint,
authentication-rejection and downstream-failure taxonomies, backpressure occupancy, keystore
health — served as a JSON dump on the module's local admin socket:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
```

The full catalog, with each metric linked back to the setting it helps size, is in
[Metrics](metrics.md). These are separate from (and additive to) the legacy statistics below.

### View Statistics

Query remoted's statistics on demand via the API:

```bash
GET /cluster/{node_id}/daemons/stats?daemons_list=wazuh-manager-remoted
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

- [Remoted Module](README.md) - Module overview and architecture
- [Metrics](metrics.md) - The HTTPS agent server's metric catalog, linked back to these settings
- [HTTPS Agent API](https-events-api.md) - The HTTPS transport, protocol and endpoints
- [Stateless Metadata](stateless-metadata.md) - Agent metadata caching system
- [Event Protocol](event-protocol.md) - Agent-manager communication protocol
- [Architecture](architecture.md) - Module design and implementation
- [Quick Reference](quick-reference.md) - Command reference and troubleshooting
