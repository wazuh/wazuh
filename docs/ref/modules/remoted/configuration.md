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
  block is equivalent to `no`. The installer writes the block with `<enabled>yes</enabled>` (set
  `WAZUH_REMOTE_LEGACY_ENABLED=no` at install time to write `no`), so an installed manager serves
  the legacy channel until this is changed
- **Allowed values:** `yes`, `no`
- **Note:** With `no`, remoted binds no legacy socket and starts no legacy thread; only
  5.x agents (served over `<https>`) can connect. `merged.mg`/group generation stays on
  regardless, since the HTTPS `/download` endpoint also serves it to 5.x agents.
  Disabling this also causes `remote_upgrade` task creation for agents below v5.0.0 to be
  rejected at creation time, since there is no delivery path for them anymore.
- **Read by modulesd at start-up.** The Task Manager's upgrade routes consult this value to decide
  whether an upgrade can be delivered at all, and read it **once**, when modulesd starts. Changing it
  therefore needs `wazuh-manager-modulesd` restarted as well as `wazuh-manager-remoted`, or upgrade
  requests will keep applying the previous value.

### legacy.ca_delivery

Send the manager's CA certificate to a pre-v5.0.0 agent during a remote upgrade, so the upgraded
agent has a trust anchor for the HTTPS listener it is about to start using.

A 5.0 manager is always a fresh install, so a 4.x fleet reaches 5.0 by remote upgrade. Once
upgraded, those agents speak HTTPS on 1517 but hold no anchor on disk, and they cannot enrol again
to obtain one — they already carry a `client.keys` identity, so they never see an enrollment token.
With this enabled, remoted pushes `remote.https.ca_certificate` to the agent's `var/incoming/` as
`root-ca.pem` over the same encrypted, integrity-protected channel it uses for the WPK, immediately
before issuing the `upgrade` command. The agent's installer picks it up from there.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Disable when a corporate PKI or a configuration-management tool distributes the anchor
  by its own means. With `no`, the upgrade push is byte-for-byte what it was before this option
  existed — no file is read and no additional command is sent.
- **Note:** With `yes` and a `remote.https.ca_certificate` bundle carrying more than one CA (a
  rotation in progress), the bytes pushed are **not** the file as it sits on disk. `legacy_task_ca_read()`
  asks the C++ module for the certificate the HTTPS listener's leaf is currently served under, and
  the module hands back the first one that the leaf **actually chains to** and that is **an anchor
  the agent-side installer would keep**: it must be a CA (`basicConstraints CA:TRUE`) and currently
  within its validity window. A valid signature is deliberately not enough — a rotation's overlap is
  exactly where the bundle can carry an **expired** re-issue of the same key next to the current one,
  and a certificate holding that key under another subject signs the leaf without being its issuer at
  all; neither is something `src/init/pkg_installer.sh` will install and work with. If
  nothing in the bundle qualifies, **nothing is delivered** and the upgrade proceeds without a CA
  (see the "never fails an upgrade" note below) — better that than a `root-ca.pem` drop-in the
  installer rejects on arrival. The result is re-serialized on its own, with no publication block
  (`remoted_module_tls_leaf_signer_pem()`, `src/remoted/src/legacy_task_delivery.c:651-681`) — the
  agent-side installer refuses a `root-ca.pem` drop-in with more than one certificate, so sending the
  bundle verbatim during a rotation would leave the agent with no anchor at all. With a single,
  currently-valid CA in the bundle, the result is substantively equivalent to the file.
- **Note:** The CA is only sent when the upgrade targets v5.0.0 or later. An agent being stepped up
  to an intermediate 4.14.x release does not receive it: nothing on that version would read it.
- **Read by remoted only.** Unlike `legacy.enabled` and `https.verification_mode` below, this value
  is not cached by modulesd, so a change takes effect after restarting `wazuh-manager-remoted`
  alone.
- **Never fails an upgrade.** If the CA cannot be sent, the upgrade proceeds and the manager logs a
  warning naming the CA step specifically. An agent off the air is worse than an agent without an
  anchor.

The manager refuses to send a CA that the certificate its own HTTPS listener serves does not chain
to, and logs an error instead — an agent that pinned such an anchor would fail every connection
afterwards, which is worse than sending nothing. This is the same check `GET /cacerts` applies
before handing the CA to a 5.x agent, so the two paths can never disagree.

**Certificate requirements.** The manager cannot verify that its certificate covers the address a
given agent dials: behind NAT, a load balancer, or in a cluster, it does not know that address. Two
requirements are therefore the operator's to meet:

- Every node's agent-facing certificate must be issued by the CA being distributed. Certificates
  are not synchronized across cluster nodes, and the poller sends the CA configured on whichever
  node holds the agent's session — so a worker distributes its own `remote.https.ca_certificate`.
- That certificate must carry every address agents actually dial among its subjectAltName entries:
  the cluster VIP, each node's own address, and any NAT address. remoted logs a warning at start-up
  if the certificate carries no usable SAN at all — meaning no DNS or IP entry beyond loopback and
  the host's own name — but it cannot detect a SAN list that is merely missing the right address.
  A token minted for one worker's own address also needs that address on the master's
  certificate; see [Enrollment tokens](../authd/README.md#enrollment-tokens).

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

Capacity, in messages, of the input queue between the legacy listener and the message-handler
workers ([`remoted.worker_pool`](#remotedworker_pool)).

- **Default value:** `131072`
- **Allowed values:** Positive integer
- **Note:** Values greater than `262144` are accepted with the warning `Queue size is very high. The
  application may run out of memory.` A message arriving at a full queue is discarded (see
  [Queue Byte Limits](#queue-byte-limits) for how discards are reported)

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

- **Default value:** `0.0.0.0` (all IPv4 interfaces) when `ipv6` is `no`; all IPv6 interfaces (`::`)
  when `ipv6` is `yes` (the `0.0.0.0` default only applies in IPv4 mode)
- **Allowed values:** Valid IPv4 or IPv6 address
- **Note:** Restricts remoted to listen only on the specified interface. The shipped
  `wazuh-manager.conf` and the install-time template write the `0.0.0.0` default explicitly; set a
  specific address (or `127.0.0.1`) to accept agents only through that interface.

### legacy.rids_closing_time

Time to keep agent session IDs (RIDs) cached after agent disconnects.

- **Default value:** `5m` (300 seconds)
- **Allowed values:** Time value with optional suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days). Bare number defaults to seconds. A non-positive value is replaced by the default with a warning.
- **Example:** `300`, `5m`, `300s` are all equivalent
- **Note:** Idle time after which remoted closes an agent's open RIDS (message-counter) file in
  `queue/rids/`

### legacy.connection_overtake_time

Seconds an agent's current TCP session must have been idle (no message received on it) before a new
connection from the same agent may take it over.

- **Default value:** `60`
- **Allowed values:** Integer from `0` to `3600` (seconds)
- **Note:** While the current session has been active more recently than this, a message arriving on
  a second connection with the same agent key is dropped and that connection closed; once the conflict
  outlasts the window remoted logs `Agent key already in use: agent ID '<id>' (source IP: <ip>)`
  (two hosts sharing one key). `0` disables overtaking altogether: the second connection is always
  refused and the warning is logged at once.

---

## HTTPS Configuration

**XML Section:** `<remote><https>`

Configuration for the RESTinio-based HTTPS listener. All options are optional; an absent `<https>` block (or an absent individual option) falls back to the module's built-in defaults, so the listener is usable without configuring anything here. There is no `enabled` toggle: the listener always starts, and the manager fails closed without a readable certificate/key — it issues them at installation and never reissues them; a deployment on its own PKI overwrites them (see [Certificate provisioning and fail-closed start](https-events-api.md#certificate-provisioning-and-fail-closed-start)).

### https.port

HTTPS listening port.

- **Default value:** `1517`
- **Allowed values:** Integer from `1` to `65535`

### https.bind_addr

Address the HTTPS listener binds to.

- **Default value:** `0.0.0.0` (all IPv4 interfaces)
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

- **Default value:** `/wazuh-manager/`. The schema materialises it into the effective
  configuration, so an absent tag means the prefix is applied, not that it is skipped. Serving
  unprefixed endpoints requires writing `/` explicitly.
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

- **Default value:** `etc/certs/remoted.pem` (relative to the manager's home)
- **Note:** the manager issues this file at installation and never reissues it. To use your own PKI, overwrite it — a leaf of the CA in
  `ca_certificate`, issued by the installation assistant's `wazuh-certs-tool` — as
  `wazuh-manager:wazuh-manager 640` before the first start. Missing: `wazuh-manager-control start`
  refuses with `(1244): Invalid configuration at '/remote/https/certificate': file not found: …`.
  Present but unreadable by the service user: `wazuh-manager-remoted` exits with
  `Cannot start the HTTPS agent listener: …`.
- **Note:** at startup the manager warns if this certificate has expired or expires within 30 days,
  so a silent outage for verifying agents can be prevented before it happens.

### https.key

Path to the TLS private key (PEM) matching `certificate`.

- **Default value:** `etc/certs/remoted-key.pem` (relative to the manager's home)
- **Note:** provisioned together with `certificate`, same ownership and the same fail-closed
  behaviour when missing (`(1244) … '/remote/https/key': file not found`) or unreadable by the
  service user.
- **Note:** `certificate` and `key` must be set together or not at all: setting only one is
  rejected (`certificate and key must be set together`), so a custom certificate cannot silently
  pair with the default key.

### https.ca

Path to a CA bundle (PEM) used to verify client (agent) certificates.

- **Default value:** empty (not set). Empty means "no client-verification CA configured": no
  `verification_mode` is inferred from it, and verification stays off.
- **Note:** Only read when `verification_mode` is `certificate` or `full`. If one of those modes is
  set explicitly with no `ca`, the module falls back to `etc/certs/root-ca.pem` (relative to the
  manager's home). Setting `ca` without `verification_mode` turns verification on — see the special
  case below.
- **Note:** a configured `ca` that does not exist stops `wazuh-manager-control start`
  (`(1244) … '/remote/https/ca': file not found`).

### https.ca_certificate

Path to the CA certificate (PEM) that **issued** the listener certificate (`certificate`) — the
self-signed root that certificate chains to, or a bundle carrying it. It is the certificate the
manager serves on `GET /cacerts` and the one enrollment tokens pin, so agents can verify the listener
without an out-of-band CA copy. A certificate that only shares the issuer's key, one that has expired
and one without `CA:TRUE` are all refused: see
[the coherence check](https-events-api.md#ca-certificate-endpoint-get-cacerts).

Only its **certificates** are ever published: the manager parses the file and re-serialises the
X.509 blocks it found, so a PEM that also carries the CA's private key (a misprovisioned bundle)
hands out the certificate and nothing else, on `GET /cacerts` as well as in a `--embed-ca` token.
A file it cannot parse to the end is refused whole rather than served up to its first bad block.

- **Default value:** `etc/certs/root-ca.pem` (relative to the manager's home; the installer
  writes the option explicitly). Like the listener certificate, the file is issued by the credential
  resolver at installation (`root:wazuh-manager 640`), or provisioned by the operator together with
  the listener certificate it signs.
- **Note:** this is **not** the client-verification CA (`ca`): `ca` verifies agent certificates,
  `ca_certificate` is what agents use to verify the manager. An empty value is rejected at startup
  (`(1244): Invalid configuration at '/remote/https/ca_certificate': does not satisfy 'minLength'`).
  A missing file stops `wazuh-manager-control start` like a missing certificate
  (`(1244) … '/remote/https/ca_certificate': file not found`); if it disappears while remoted is
  running, `GET /cacerts` answers 404. Replacing it needs no restart — the manager notices a change in the file's content
  (not its timestamp or size) and revalidates it in the very request that reads it.

### https.verification_mode

Client-certificate verification strictness.

- **Default value:** `none` when `ca` is not set; `certificate` when `ca` is set and this option is absent
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
- **Special case:** if `ca` is set to a non-empty path but `verification_mode` is not, the manager defaults `verification_mode` to `certificate` instead of `none`, and logs `The 'remote.https.ca' option is configured but 'verification_mode' is not; defaulting 'verification_mode' to 'certificate'.` An explicit `<verification_mode>` (including `none`) always wins over this inference.
- **Effect on agent upgrades:** anything other than `none` (or unset) blocks upgrading an agent
  *to* v5.0.0 or newer, because the freshly upgraded agent comes back speaking HTTPS and may not be
  able to re-establish a connection; remoted logs a warning saying so at startup. `PUT /agents/upgrade` can override that with `force`, accepting
  the risk and logging it; `PUT /agents/upgrade_custom` has no `force` parameter and so cannot.
  Like `legacy.enabled`, this is read **once at modulesd start-up**, so changing it needs modulesd
  restarted before upgrades see the new value.

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

Maximum accepted HTTP request body size, enforced by the transport.

- **Default value:** `10M` (10 MiB)
- **Allowed values:** Positive byte count with an optional single-letter suffix (`B`, `K`, `M`, `G`, case-insensitive). `K`/`M`/`G` are binary multiples; a bare number is bytes. Suffixes such as `MB` are rejected.
- **Effect:** Raising the limit admits larger wire bodies and increases potential memory use per connection;
  lowering it rejects larger requests at the transport. The authentication and shared-memory limits still apply.
- **Note:** Keep it **above** [`remoted.auth_max_body_size`](#remotedauth_max_body_size) (5 MiB by
  default). Breaching *this* cap is not a `413`: the parser fails on `Content-Length` and the
  connection is closed with no response at all, which an agent cannot tell apart from a network
  failure — so it never splits its batch and retries the same bytes indefinitely. The auth limit is
  what produces the `413` the agent acts on. Setting the two equal makes the closed connection the
  only outcome, because the `Content-Length` check always fires first.

### Rate limits of the unauthenticated routes

Two of the HTTPS routes cannot be put behind the bearer-token gateway, because their callers do not
yet have the credential it verifies: `POST /enroll` (an enrolling agent has no `client.keys` entry
yet) and `GET /cacerts` (a caller fetching the trust anchor does not have one yet by definition).
For those two, these two options cap how fast the manager serves the route at all.
`POST /enroll/secret` is authenticated, but it costs the manager the same `authd` round trip as
`/enroll`, so it shares `/enroll`'s bucket and is charged **before** its bearer is verified.

**Neither is written into the shipped `wazuh-manager.conf`** — the defaults below apply without any
`<https>` block, and an operator only adds a line to change one.

What is being bounded is the **work behind the route**, not the transport. A `/enroll` request costs
the manager a round trip to authd over its local socket and, on a cluster worker, a further round
trip to the master; a caller pays one HTTP request for it. The
[in-flight byte budget](#remotedmax_inflight_bytes) and
[`remoted.max_parallel_connections`](#remotedmax_parallel_connections) bound the *memory* a request
holds and shed with a `503`; these bound *how often* the route is served and refuse with a `429` and
a `Retry-After`.

> **The limit is a ceiling for the endpoint, not an allowance per agent.** One bucket per route,
> shared by every caller: a single client asking fast enough can consume the whole route's budget,
> and a fleet-wide burst is paced by the same number. Size these for the fleet — at
> `enroll_rate_limit` `100`, a bootstrap of 10 000 agents needs at least ~100 seconds of `/enroll`
> traffic. The agent retries with its own backoff ramp, so a paced rollout completes; it is slower,
> not broken.
>
> **In a cluster the ceiling is per node.** Every manager runs its own limiter, so N nodes behind a
> load balancer admit up to N times the configured rate between them, and an agent refused by one
> node may be admitted by the next one it is balanced to. Size the value for what a single node
> should serve, not for the cluster total.

Each limit is a token bucket, and the configured rate is the only number: **the bucket depth is
derived from it, at twice the rate, and is not configurable.** Real traffic does not arrive evenly
spaced — a hundred agents coming back after an outage arrive in the same instant, not one every
10 ms — so a bucket holding exactly one second's worth would refuse a perfectly acceptable load on
its arrival pattern alone. Two seconds' worth absorbs that without raising the sustained ceiling.

`remoted.<endpoint>.rate_limit.available` in
[`GET /metrics`](metrics.md#rate-limits--remotedendpointrate_limit) is the live headroom (its maximum
is that derived depth), `.burst` reports the depth in force, and `remoted.<endpoint>.rate_limited`
counts what was refused.

### https.enroll_rate_limit

Sustained requests per second the manager serves across `POST /enroll` and `POST /enroll/secret`
together, counted for the two routes as a whole and not per agent.

- **Default value:** `100`
- **Allowed values:** Integer from `0` to `100000`. `0` disables the limit.
- **Note:** Short bursts of up to twice this value are absorbed before the rate paces them.
- **Effect:** Requests over the limit are answered `429` with `Retry-After` **without reaching
  authd** (on `/enroll/secret`, without even being authenticated), so a peer with no usable credential can no longer turn `/enroll` into an amplifier onto
  the cluster's internal socket.
- **Note:** Higher than `/cacerts`'s default even though it is the more expensive route: every agent
  must pass through it at least once (a bootstrap, or a mass re-enrollment after a credential
  rotation).

### https.cacerts_rate_limit

Sustained `GET /cacerts` requests per second the manager serves, counted for the endpoint as a
whole.

- **Default value:** `50`
- **Allowed values:** Integer from `0` to `100000`. `0` disables the limit.
- **Note:** Short bursts of up to twice this value are absorbed before the rate paces them.
- **Note:** The route is cheap — a file read plus a hash, with the parsed result cached while the
  file's content is unchanged, and no downstream service behind it — but an agent that cannot fetch
  the anchor cannot complete a handshake at all, so do not set this below the rate at which new
  agents appear.

**Example — raising the enrollment ceiling for a wide rollout:**

```xml
<remote>
  <https>
    <enroll_rate_limit>500</enroll_rate_limit>
  </https>
</remote>
```

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

**Internal Options prefix:** `remoted.*`

Internal options provide advanced tuning for performance, threading, memory management, and monitoring.

Three things to know before editing that file:

- **It ships empty.** The installed template carries only comments, so every option below is
  serving its compiled-in default. Tuning one means adding the `name=value` line yourself.
- **An out-of-range or non-numeric value is fatal**, not clamped: the daemon refuses to start and
  logs which option it rejected. Keep the documented range in view when editing.
  Put comments on separate lines beginning with `#`; an inline comment becomes part of the value.
- **The file is per node and is never synchronized.** Nothing in a cluster propagates it, so a
  value set on one manager makes an agent's behavior depend on which node it lands on.

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

Bytes read per `recv()` call from a legacy TCP connection (the per-connection receive buffer grows
in steps of this size).

- **Default value:** `4096`
- **Allowed values:** Integer from `1024` to `16384`
### remoted.send_timeout_to_retry

Seconds remoted waits before retrying once to queue a message for a legacy agent whose per-connection
send buffer ([`remoted.send_buffer_size`](#remotedsend_buffer_size)) is full.

- **Default value:** `1`
- **Allowed values:** Integer from `1` to `60`
### remoted.worker_pool

Number of message-handler threads that decrypt and dispatch messages read off the legacy listener.

- **Default value:** `4`
- **Allowed values:** Integer from `1` to `16`
- **Note:** Must be `1` when [`remoted.verify_msg_id`](#remotedverify_msg_id) is enabled

### remoted.sender_pool

Number of threads that push a group's `merged.mg` to legacy (4.x) agents. 5.x agents fetch it
themselves over `POST /download`.

- **Default value:** `8`
- **Allowed values:** Integer from `1` to `64`
### remoted.control_msg_queue_size

Queue size for agent keep-alive and control messages.

- **Default value:** `16384`
- **Allowed values:** Integer from `4096` to `1048576`
### remoted.batch_events_capacity

Item capacity of the legacy events queue that the dispatcher batches, enriches and posts to the
engine.

- **Default value:** `131072`
- **Allowed values:** Integer from `0` to `1048576`; `0` removes the item-count cap
### remoted.queue_max_bytes

Maximum bytes held in the input message queue (messages received from agents).

- **Default value:** `67108864` (64 MiB)
- **Allowed values:** `0` (unlimited) or integer from `1024` to `2147483647`; `1`–`1023` stops remoted
  at startup
- **Note:** See [Queue Byte Limits](#queue-byte-limits)

### remoted.batch_events_max_bytes

Maximum bytes held in the events queue (events forwarded to the engine).

- **Default value:** `33554432` (32 MiB)
- **Allowed values:** `0` (unlimited) or integer from `1024` to `2147483647`; `1`–`1023` stops remoted
  at startup
- **Note:** See [Queue Byte Limits](#queue-byte-limits)

### remoted.enrich_cache_expire_time

Agent metadata cache expiration time in seconds.

- **Default value:** `300` (5 minutes)
- **Allowed values:** Integer from `60` to `86400`
- **Note:** Entries older than this are removed by the cleanup pass, which runs every five seconds;
  see [Stateless Metadata Cache](#stateless-metadata-cache)

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

Soft file descriptor limit remoted raises itself to at start.

- **Default value:** `65536`
- **Allowed values:** Integer from `1024` to `1048576`
- **Note:** The daemon never raises its hard limit, which belongs to whatever starts the manager
  (`LimitNOFILE=65536` in the service unit, the init script, or the container's `ulimits.nofile`),
  and never lowers a soft limit that is already higher. A hard limit below this value is kept and
  logged once as a warning; raise that limit first to go higher. HTTPS connections are bounded by
  `remoted.max_parallel_connections` (default `256`), far below this value; only a large 4.x fleet
  on the legacy TCP listener needs more.
  `GET /cluster/{node_id}/configuration/request/internal` reports the effective value.
  See [File descriptor limits](../../configuration/manager/README.md#file-descriptor-limits).

### remoted.send_chunk

Maximum bytes taken from a legacy agent's send buffer per socket write.

- **Default value:** `4096` (4 KB)
- **Allowed values:** Integer from `512` to `16384` (bytes)

### remoted.buffer_relax

What a legacy TCP connection's receive buffer does with its memory after the complete messages in it
have been dispatched.

- **Default value:** `1`
- **Allowed values:** `0` (keep the allocation), `1` (shrink it to the pending data or
  `remoted.receive_chunk`, whichever is larger), `2` (shrink it to the pending data, freeing it
  entirely when nothing is pending)

### remoted.send_buffer_size

Capacity, in bytes, of the per-connection send buffer holding messages queued for a legacy TCP agent.

- **Default value:** `131072` (128 KB)
- **Allowed values:** Integer from `65536` to `1048576` (bytes)
- **Note:** When it is full, remoted waits [`remoted.send_timeout_to_retry`](#remotedsend_timeout_to_retry)
  and tries once more (`Not enough buffer space. Retrying...` at debug level)

### remoted.recv_timeout

Receive timeout (`SO_RCVTIMEO`), in seconds, set on the legacy TCP listening socket.

- **Default value:** `1`
- **Allowed values:** Integer from `1` to `60` (seconds)

### remoted.tcp_keepidle

Idle seconds before TCP keepalive probes are sent on the legacy TCP listener's sockets.

- **Default value:** `30`
- **Allowed values:** Integer from `1` to `7200` (seconds)
- **Note:** With `tcp_keepintvl` and `tcp_keepcnt`, bounds how long a dead legacy TCP peer goes unnoticed

### remoted.tcp_keepintvl

Interval in seconds between TCP keepalive probes.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `100` (seconds)
- **Note:** Works with `tcp_keepidle` and `tcp_keepcnt`

### remoted.tcp_keepcnt

Number of unacknowledged TCP keepalive probes before considering connection dead.

- **Default value:** `3`
- **Allowed values:** Integer from `1` to `50`
- **Note:** Total dead detection time = `tcp_keepidle + (tcp_keepintvl × tcp_keepcnt)`

### remoted.merge_shared

Build each group's `merged.mg` from the files in its `shared/` directory.

- **Default value:** `1`
- **Allowed values:** `0` (disabled), `1` (enabled)
- **Note:** With `0`, remoted does not rebuild `merged.mg`. It is also forced to `0` on a cluster
  worker node and when remoted is started with `-m`.

### remoted.pass_empty_keyfile

Allow remoted to start when `client.keys` is missing, unreadable or empty.

- **Default value:** `1`
- **Allowed values:** `0` (disabled), `1` (enabled)
- **Note:** With `0`, remoted exits whenever it loads a `client.keys` with no agents, including the
  first start of a manager that has none registered yet.

The next six options govern **requests to 4.x agents**: messages the manager sends to a legacy
agent and whose answer it waits for (the plain-text requests accepted on `queue/sockets/remote.sock`,
see [the local request socket](README.md#local-request-socket), and the WPK transfer of a remote
upgrade). They have no effect while the legacy channel is disabled.

### remoted.request_pool

Maximum requests to legacy agents in progress at once.

- **Default value:** `1024`
- **Allowed values:** Integer from `1` to `4096`

### remoted.request_timeout

Seconds a request waits for a free slot in `remoted.request_pool` before it is refused with
`Request pool is full. Rejecting request.`

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `600` (seconds)

### remoted.response_timeout

Seconds remoted waits for a legacy agent's answer to a request once it has been delivered (`Response
timeout for request counter ...` when it elapses). Also the per-command wait of the legacy WPK
upgrade delivery.

- **Default value:** `60`
- **Allowed values:** Integer from `1` to `3600` (seconds)

### remoted.request_rto_sec

Retransmission timeout (seconds part) for a request to a **UDP** legacy agent: how long remoted waits
for its ACK before resending. TCP agents are sent the request once.

- **Default value:** `1`
- **Allowed values:** Integer from `0` to `60` (seconds)

### remoted.request_rto_msec

Retransmission timeout (milliseconds part), added to `remoted.request_rto_sec`.

- **Default value:** `0`
- **Allowed values:** `0-999` (milliseconds)

### remoted.max_attempts

Maximum sends of a request to a UDP legacy agent (and maximum waits for its answer) before the request
fails with `err Maximum attempts exceeded`.

- **Default value:** `4`
- **Allowed values:** Integer from `1` to `16`

### remoted.shared_reload

Interval in seconds for reloading shared configuration files.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `18000` (seconds)
- **Note:** How often remoted re-reads `etc/shared/` and regenerates `merged.mg` files

### remoted.disk_storage

Where remoted builds a group's `merged.mg` before comparing it with the current one.

- **Default value:** `0`
- **Allowed values:** `0` (in memory), `1` (in a temporary `merged.mg.tmp` file next to it)
- **Note:** It does not persist events or any queue. `1` trades memory for disk I/O while building
  large shared configurations.

### remoted.verify_msg_id

Reject agent messages whose counter is not higher than the last one received from that agent,
to detect replayed messages.

- **Default value:** `0`
- **Allowed values:** `0` (disabled), `1` (enabled)
- **Note:** `1` requires `remoted.worker_pool` set to `1`; with more workers remoted refuses to
  start, because message order cannot be guaranteed. It checks only messages on the legacy (4.x)
  listener; HTTPS agents are authenticated per request with their bearer token.

### remoted.batch_events_per_agent_capacity

Maximum events one agent may hold in the legacy events queue; further events from that agent are
discarded until its share drains.

- **Default value:** `131072`
- **Allowed values:** Integer from `0` to `1048576`; `0` removes the per-agent cap

### remoted.recv_counter_flush

Messages received from a legacy agent between two writes of its message counter to its RIDS file
(`queue/rids/<id>`).

- **Default value:** `128`
- **Allowed values:** Integer from `10` to `999999` (message count)

### remoted.comp_average_printout

Messages remoted compresses and encrypts for legacy agents between two debug lines (`Event count after '<n>': <original>-><compressed> (<rate>%)`) reporting the average compression rate.

- **Default value:** `19999`
- **Allowed values:** Integer from `10` to `999999` (event count)

### Agent module limits (`fim.*`, `syscollector.*`, `sca.*`)

Seventeen more options in the same file are read by remoted, although they live under their
modules' namespaces rather than `remoted.*`. They are the per-module inventory caps the manager
hands every 5.x agent in the `limits` object of its `POST /control` `startup` answer (see
[Control endpoint](https-events-api.md#control-endpoint-post-control)); the agent applies them.

| Option | Limit sent as |
|---|---|
| `fim.file_limit` | `limits.fim.file` |
| `fim.registry_key_limit` | `limits.fim.registry_key` |
| `fim.registry_value_limit` | `limits.fim.registry_value` |
| `syscollector.hotfixes_limit` | `limits.syscollector.hotfixes` |
| `syscollector.packages_limit` | `limits.syscollector.packages` |
| `syscollector.processes_limit` | `limits.syscollector.processes` |
| `syscollector.ports_limit` | `limits.syscollector.ports` |
| `syscollector.network_iface_limit` | `limits.syscollector.network_iface` |
| `syscollector.network_protocol_limit` | `limits.syscollector.network_protocol` |
| `syscollector.network_address_limit` | `limits.syscollector.network_address` |
| `syscollector.hardware_limit` | `limits.syscollector.hardware` |
| `syscollector.os_info_limit` | `limits.syscollector.os_info` |
| `syscollector.users_limit` | `limits.syscollector.users` |
| `syscollector.groups_limit` | `limits.syscollector.groups` |
| `syscollector.services_limit` | `limits.syscollector.services` |
| `syscollector.browser_extensions_limit` | `limits.syscollector.browser_extensions` |
| `sca.checks_limit` | `limits.sca.checks` |

- **Default value:** `30000` each
- **Allowed values:** Integer from `0` to `2147483647`; like every other option here, a value out
  of range stops remoted at startup
- **Note:** Read once when remoted starts. They also feed the `settings_hash` a `notify` answer
  carries, so after a restart with a changed limit every agent sees a new hash and sends a fresh
  `startup` to pick the new limits up. The file is per node: set the same values on every cluster
  node, or an agent's limits depend on the node it lands on.

### HTTPS Agent Server (`remoted_module`)

Advanced tuning for the HTTPS agent server (see
[HTTPS Agent API](https-events-api.md)): RESTinio transport settings (`remoted.http_*`) plus the
downstream UDS client and auth middleware tunables (`remoted.downstream_*`, `remoted.auth_*`,
further down this section). None of these are part of the regular `<remote>` configuration --
bind address, port and max body size are regular `<remote>` settings instead (see
[HTTPS Agent API](https-events-api.md#configuration)). An option present in
`wazuh-manager-internal-options.conf` but out of its allowed range (or non-numeric) prevents
`remoted` from starting, same as every other internal option.

The timeout and retry settings below each pair with a deadline on the agent's side of the same
hop; [Connection timing tuning](timing-tuning.md) covers which pairs must move together and what
breaks when only one does.

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
- **Note:** It is a **total** deadline on receiving the request, not an idle timer: it is armed
  once and never rearmed as bytes arrive, so a body that takes longer than this to upload is cut
  even though it never stalled, and the connection is closed without an HTTP status. This is the
  setting that bounds a large `POST /stateful` or `POST /stateless` over a slow link -- raising
  the agent's own per-request budget without raising this one changes nothing (see
  [Connection timing tuning](timing-tuning.md#3-invariants)). The startup downstream-budget warning
  names `remoted.http_request_timeout` instead, so that is the option usually reached for first,
  and raising it does not widen the window an agent has to send its body

#### remoted.http_write_timeout

Seconds to wait for a response write to complete.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `300`
- **Note:** On a streamed `POST /download` the deadline is rearmed per chunk, but it still bounds
  each chunk's flush, so it is the setting that aborts a WPK transfer over a slow link: measured
  5/10 aborts at the shipped 10 s below ~1 Mbit/s against 0/5 at 120 s on the same shaper. Size it
  against the slowest link that must be able to complete an upgrade
  ([Connection timing tuning](timing-tuning.md#5-per-goal-recipes)). The per-chunk deadline puts a
  floor on the usable link speed, `remoted.http_stream_chunk_size` divided by this value, about
  6.5 KB/s at the defaults of 64 KiB and 10 s. An abort leaves no line in the manager log at any
  level: RESTinio reports the expiry from `handle_xxx_timeout()` at trace level, and the module's
  logger adapter strips trace at compile time

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

- **Default value:** `0` (auto: resolves to `cpp_get_nproc()`, floored at `2` so a single-core host or
  cgroup does not regress below the previous fixed default)
- **Allowed values:** Integer from `0` to `64`

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

- **Default value:** `256`
- **Allowed values:** Integer from `1` to `65536`
- **Note:** Reaching this limit **rejects nothing**: the transport postpones the accept and the
  connection waits in the kernel's listen backlog, so saturation shows up as added latency rather
  than as an error the agent can see. There is consequently no rejection counter for it — watch
  [`remoted.server.connections.open`](metrics.md#public-transport-backpressure--remotedserverbudget)
  against `.max` instead, which is the only visibility into how close the listener is running to it.
- **Note:** Bounds the read-phase memory peak (~`max_parallel_connections` × `max_body_size`). Also
  the only bound on concurrent streamed responses (`POST /download`): chunked output rearms
  `remoted.http_write_timeout` per chunk and there is no per-stream limiter, so a fast reader holds
  a slot for as long as the transfer needs. A slow one does not get the same freedom: below roughly
  1 Mbit/s the per-chunk write deadline is what aborts the transfer (see
  [Connection timing tuning](timing-tuning.md#5-per-goal-recipes)). A mass upgrade (the whole fleet
  fetching a WPK at once, many over slow links) is therefore bounded only by this value. Started transfers and
  offered bytes are visible as `remoted.download.*` in
  [`GET /metrics`](metrics.md#downloads--remoteddownload).

#### remoted.max_deferred_requests

Maximum requests parked awaiting a downstream service before replying with HTTP 503.

- **Default value:** `128`
- **Note:** Deliberately kept **below**
  [`remoted.max_parallel_connections`](#remotedmax_parallel_connections). A forwarded request holds
  a connection *and* a deferred slot, so whichever limit is lower is the one that binds. Keeping
  this one lower means saturation is shed as an explicit, counted `503` the agent retries on,
  instead of as invisible accept-queue latency. Raising it to or above the connection cap makes it
  effectively unreachable.
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

Seconds to wait for the connect to a downstream service's Unix socket (the engine's event ingress for
`/stateless`, the inventory sync server for `/stateful`, `/stats` and `/config`) to complete.

- **Default value:** `2`
- **Allowed values:** Integer from `1` to `60`
- **Note:** Exceeding it is logged (throttled) as `Downstream call to the <service> failed
  (connect_timeout) ... Consider increasing the value of 'downstream_connect_timeout'.` A connection
  *refused* immediately (rather than timing out) means nothing is listening on the socket and is
  reported as `connect_failed` instead.

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
  detection of a genuinely hung downstream on the fast ones). `/stateless` is bound by this default:
  it must stay above the engine's real p99 ingestion latency, or a batch the engine takes longer to
  ingest is redelivered by the agent's retry, with nothing able to recognize it as the same batch.

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
- **Note:** The same window bounds every `wazuh-enroll+jwt` bearer of `POST /enroll` — the shared
  enrollment password, an enrollment token, and the re-enrollment credential. The last one is
  verified by `authd` on the master node, which reads this option and `remoted.jwt_clock_skew`
  itself, so the two daemons never accept different windows.

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
  above). Also bounds the freshness window of every `POST /enroll` bearer, the re-enrollment
  credential `authd` verifies on the master included (`authd` reads the same option). Widening it
  also widens the replay window of a captured token (this profile has no replay store).

#### remoted.auth_max_body_size

Hard cap on the authenticated request body size, in bytes (checked by the auth middleware,
independent of the transport's own body cap -- [`https.max_body_size`](#httpsmax_body_size), a
regular `<remote>` setting, not an internal option).

Applies to the body **as received on the wire**. It does not bound a `Content-Encoding: zstd` body
once decompressed -- that is bounded by the in-flight memory budget instead (`max_inflight_bytes`);
see [HTTPS Agent API](https-events-api.md#content-encoding-zstd). Rejections against either cap
are visible as `remoted.auth.reject.body_too_large` in
[`GET /metrics`](metrics.md#authentication-rejections--remotedauthreject).

- **Default value:** `5242880` (5 MiB)
- **Allowed values:** Integer from `1048576` (1 MiB) to `67108864` (64 MiB)
- **Note:** This is the cap that answers a `413`, and the agent acts on it: it splits an oversized
  `/stateless` batch and resends it smaller without dropping events, then ramps back up. Keep it
  **below** [`https.max_body_size`](#httpsmax_body_size) so an oversized body reaches this check
  instead of being cut at the transport with no response at all. The agent's own ceiling is
  `<client><batch><size>` (1 MiB by default), which also bounds `/stateful` sessions, so the
  default leaves 5x headroom — raise this one if that setting is raised.

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
  warns at startup from half upward. The staleness the disconnection sweep compares against the
  threshold is the throttle plus the agent's notify interval, so any value at or above half can
  disconnect agents that are answering normally. Half rather than just below the threshold also
  leaves room for the sweep's own granularity: the sweep polls the threshold on a quarter of it,
  bounded to `[60 s, 300 s]`, so detection lands within the threshold plus one interval — 15 m to
  18 m 45 s at the defaults. The sweep runs as a
  [recurring manager task](../task_manager/schedules.md), on the cluster master only.
- **Note:** A value at or below the fleet's notify cadence suppresses nothing: the throttle can
  only drop a notify that arrives inside an open window. This is not checked at startup, because
  remoted does not know the agent's `notify_time`.
- **Note:** 5.x agents only. A 4.x keepalive is written by the legacy path, ungated, so a sizing
  table built from this option has to count 5.x agents alone.
- **Note:** The throttle state lives in remoted's in-memory registry, which is per node. An agent
  alternating between cluster nodes is throttled independently on each, so its worst-case
  database write rate is one write per window **per node**.

#### remoted.control_groups_refresh_interval

Seconds between refreshes of the cached shared-group listing used to answer `/control`, and the
freshness bound of `/download`'s authorization.

- **Default value:** `60`
- **Allowed values:** Integer from `1` to `3600`
- **Note:** For a change of group **membership** this is the backstop, not the usual latency.
  When a membership change is written to the node's `wazuh-manager-db`, remoted is told which
  agents changed (`POST /_internal/agents/groups` on its [admin socket](README.md#local-admin-socket)):
  on a cluster worker by the cluster daemon, after it applies the master's changes; on a master or
  a standalone node by the server API, after it assigns or removes a group, and after it deletes a
  group. remoted then stops trusting those agents' cached memberships, and their next `/control`
  or configuration download reads the database. That notification is best effort. When it is lost
  (remoted down or restarting, its admin socket unreachable, a worker's publication queue full),
  and for changes nothing announces (a group assigned at enrollment, or a group directory removed
  by hand, which `wazuh-manager-modulesd` applies to the database on its own), the cached
  membership is trusted until it is this old. That includes `startup`: it answers from a fresh
  cached membership without querying the database, so inside this window an agent restarted after
  losing a group can still be handed that group's selector, and download it.
- **Note:** Group **content** travels on a different path: the merged-groups watcher picks up a
  changed `merged.mg` on inotify plus a poll, so content propagates in seconds. When a membership
  change is not announced, the two differ by this interval: roughly 60 s against 10 s at the
  defaults, about two orders of magnitude at the maximum of `3600`.
- **Note:** Editing `var/multigroups/<hash>/merged.mg` by hand is not a way to reproduce this:
  `remoted.shared_reload` (default `10`) regenerates the file and reverts the edit.
- **Note:** It is also how long an agent's `/control` keeps answering while wazuh-db is down: a
  fresh membership answers `startup` and `notify` without a query. Once it expires, a refresh that
  fails is answered `503` (the agent retries) and does not mark the cached membership fresh, so
  **every** notify retries the query: one wazuh-db round trip per notify, for the whole fleet. That
  retry is deliberate. Serving the expired membership instead, or marking it fresh on failure, would
  hand out membership that can be arbitrarily stale with no sign of it, which is the worse trade for
  a security product. The retry rate is visible as `remoted.control.wdb.*` in
  [`GET /metrics`](metrics.md#control-plane--remotedcontrol).

- **Note:** `/download` trusts the cached membership of an agent for this long. After that, and for
  an agent the node has no cached membership for (it never sent `/control` here, or remoted
  restarted), a `config` download first reads the agent's groups from the local wazuh-db — one
  query per agent, shared by concurrent downloads — and answers `503` if that read fails or finds
  no row for the agent. A lower
  value tightens how long a revoked group can still be downloaded on this node when the change
  was not announced to remoted (see above), at the cost of more of those reads.

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

#### remoted.control_wdb_request_deadline

Milliseconds a control-plane wazuh-db request may take end to end, counted from the moment it is
queued: the wait for a free connection, any reconnection, and the round trip.

- **Default value:** `5000`
- **Allowed values:** Integer from `100` to `30000`
- **Note:** A request still queued when it runs out is failed without ever being sent, so work
  queued while wazuh-db is down is not replayed against it once it comes back. An expired group
  lookup answers `/control` startup and notify (and a `config` `/download`) with `503`
  `dependency_unavailable`; an expired membership is never served in its place. Each expiry counts
  as `remoted.control.wdb_error` in [`GET /metrics`](metrics.md#control-plane--remotedcontrol) and
  is reported, throttled, as a `WazuhDB request expired before wazuh-db answered` warning.
- **Note:** `remoted.control_wdb_roundtrip_deadline` still bounds the round trip itself, inside this
  budget. remoted warns at startup when this deadline plus `remoted.control_tm_deadline` does not fit
  below the HTTPS listener's request timeout, because the connection would be closed before
  `/control` could answer.

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

Seconds between fallback polls of the two `authd`-written secret files `POST /enroll` authenticates
against: `etc/authd.pass` (the shared enrollment password, Password mode) and
`etc/enrollment_tokens.json` (the enrollment token store, every mode). Both are also watched with
`inotify`, which normally reacts first; this interval only bounds how long a missed notification can
go unnoticed.

- **Default value:** `10`
- **Allowed values:** Integer from `1` to `3600`
- **Note:** Until a change is picked up, Password-mode enrollment keeps failing with the old
  key; those rejections count as `remoted.auth.reject.enrollment_key_unavailable` in
  [`GET /metrics`](metrics.md#authentication-rejections--remotedauthreject). For the token store,
  an unknown token id additionally forces one immediate re-read (at most one per second), so a
  token minted on the master moments earlier is accepted on a worker without waiting for this poll
  — provided the cluster sync has already delivered the file. Successful and failed loads of the
  store are [`remoted.enroll.token_store.reloads.total` /
  `reload_failures.total`](metrics.md#agent-enrollment--remotedenroll).

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

#### remoted.vd_scan_read_timeout

Seconds to wait for VD's answer to the inline `POST /scan/vd` admission relay.

- **Default value:** `5`
- **Allowed values:** Integer from `1` to `300`
- **Note:** VD answers at admission into its bounded dispatch queue, not after running the scan,
  so this is a local-socket round trip measured in milliseconds. A larger value does not make VD
  queue the scan any sooner.

#### remoted.vd_scan_write_timeout

Seconds to wait for the write side of the same inline `POST /scan/vd` relay to VD.

- **Default value:** `5`
- **Allowed values:** Integer from `1` to `300`
- **Note:** Same admission-only round trip as `remoted.vd_scan_read_timeout`. Both, plus the
  fixed deadlines of the `/offset` query the scan gates on, make up the `/scan/vd` downstream
  budget checked at startup against `http_request_timeout`.

---

## Configuration Examples

### Installed Configuration

The `<remote>` block the installer writes into `etc/wazuh-manager.conf` (every value can be changed
at install time through the matching `WAZUH_REMOTE_*` variable):

```xml
<wazuh_config>
  <remote>
    <https>
      <port>1517</port>
      <bind_addr>0.0.0.0</bind_addr>
      <global_prefix>/wazuh-manager/</global_prefix>
      <certificate>etc/certs/remoted.pem</certificate>
      <key>etc/certs/remoted-key.pem</key>
      <ca_certificate>etc/certs/root-ca.pem</ca_certificate>
    </https>

    <legacy>
      <enabled>yes</enabled>
      <port>1514</port>
      <protocol>tcp</protocol>
      <local_ip>0.0.0.0</local_ip>
      <queue_size>131072</queue_size>
    </legacy>

    <agents>
      <allow_higher_versions>no</allow_higher_versions>
    </agents>
  </remote>
</wazuh_config>
```

The other sections the installer writes are omitted here.

### HTTPS Only (no 4.x agents)

Turn the legacy channel off once no 4.x agent is left; nothing is bound on `1514` afterwards, and
remote upgrades of agents below v5.0.0 are refused:

```xml,fragment
<remote>
  <legacy>
    <enabled>no</enabled>
  </legacy>
</remote>
```

### UDP and TCP Support

Accept 4.x agents over both TCP and UDP:

```xml,fragment
<remote>
  <legacy>
    <enabled>yes</enabled>
    <port>1514</port>
    <protocol>tcp,udp</protocol>
  </legacy>
</remote>
```

### Allow Higher Agent Versions

Accept agents whose version is higher than the manager's on `POST /control` and on the legacy
channel:

```xml,fragment
<remote>
  <agents>
    <allow_higher_versions>yes</allow_higher_versions>
  </agents>
</remote>
```

### HTTPS with Client Certificates

Require and validate agent client certificates (`full` would additionally require the peer address
among the certificate's SAN entries):

```xml,fragment
<remote>
  <https>
    <port>1517</port>
    <bind_addr>0.0.0.0</bind_addr>
    <global_prefix>/wazuh-manager/</global_prefix>
    <certificate>etc/certs/remoted.pem</certificate>
    <key>etc/certs/remoted-key.pem</key>
    <ca_certificate>etc/certs/root-ca.pem</ca_certificate>
    <ca>etc/certs/root-ca.pem</ca>
    <verification_mode>certificate</verification_mode>
    <ciphers>TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256</ciphers>
    <max_body_size>20M</max_body_size>
  </https>
</remote>
```

### Memory-Capped Legacy Queues

Internal options (`/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`):

```conf
# Cap the legacy input queue at 128 MiB
remoted.queue_max_bytes=134217728

# Cap the legacy events queue at 64 MiB
remoted.batch_events_max_bytes=67108864
```

---

## Queue Byte Limits

The byte limit options (`remoted.queue_max_bytes` and `remoted.batch_events_max_bytes`) cap the total
memory held by the two legacy-channel queues regardless of event count. They do not apply to the
HTTPS channel, whose equivalent is [`remoted.max_inflight_bytes`](#remotedmax_inflight_bytes).

### Behavior When Limits Are Reached

- A message larger than the whole input-queue limit is dropped immediately; one that would push the
  total over the limit is dropped until space is freed. The count limit
  ([`legacy.queue_size`](#legacyqueue_size)) drops the same way.
- Input-queue drops count in `metrics.messages.received_breakdown.discarded` and are logged as
  `Input queue discarded <n> event(s) in the last 90 seconds.`, at most once every 90 seconds.
- Events-queue drops (its byte limit, [`remoted.batch_events_capacity`](#remotedbatch_events_capacity)
  or [`remoted.batch_events_per_agent_capacity`](#remotedbatch_events_per_agent_capacity)) count in
  `metrics.messages.received_breakdown.events_failed` and are logged as
  `Events queue discarded <n> event(s) in the last 90 seconds.`, at most once every 90 seconds.

### Guidelines

- The byte limit and the item-count limits are independent: an event is dropped when either is
  reached.
- Values between `1` and `1023` bytes stop remoted at startup
  (`remoted.queue_max_bytes (<n>) is below the minimum of 1024 bytes.`).
- Set to `0` to revert to count-only limiting.

---

## Stateless Metadata Cache

The legacy channel caches the agent metadata extracted from 4.x keep-alives to build the header of
the event batches it forwards to the engine ([Stateless Metadata](stateless-metadata.md)).

- Entry lifetime: [`remoted.enrich_cache_expire_time`](#remotedenrich_cache_expire_time) (default
  `300` seconds).
- The cleanup thread sleeps five seconds between passes. It removes expired entries once their
  pending events have drained; entries of agents that sent a shutdown are also removed once their
  queues drain.
- The hash table has 2048 buckets. This is **not** an option: the value is a compile-time constant
  (`OSHash_setSize(agent_meta_map, 2048)` in `src/remoted/src/agent_metadata_db.c`).

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
[Metrics](metrics.md). The admin socket is the complete, authoritative surface; the API below
reports most of the same figures for remote consumption.

### View Statistics

Query remoted's statistics on demand via the API:

```bash
GET /cluster/{node_id}/daemons/stats?daemons_list=wazuh-manager-remoted
```

The response carries **both** channels:

- The keys directly under `metrics` — `bytes`, `tcp_sessions`, `messages`, `queues`,
  `control_messages_queue_*` — count the **legacy** TCP/UDP channel (remoted answers them on
  `queue/sockets/remote.sock`, see [the local request socket](README.md#local-request-socket)).
  With [`legacy.enabled`](#legacyenabled) set to `no` every one of them reports `0`. In particular
  `metrics.bytes` and `metrics.tcp_sessions` are **not** byte and session counts for HTTPS
  traffic — the HTTPS transport keeps neither.
- `metrics.http_server` reports the HTTPS agent server, projected from the same registry the
  admin socket serves. See [Metrics — API projection](metrics.md#api-projection) for the
  mapping and its conventions.

### Effective Configuration

The values remoted is actually running with, schema defaults applied:

```bash
GET /cluster/{node_id}/configuration/request/remote     # the <remote> section
GET /cluster/{node_id}/configuration/request/internal   # the legacy remoted.* internal options
```

The `internal` answer covers the legacy channel's options only; the `remoted.http_*`,
`remoted.downstream_*`, `remoted.control_*`, `remoted.authd_*` and `remoted.jwt_*` options are not
reported there. Run `/var/wazuh-manager/bin/wazuh-manager-remoted -t` to check that those are within
range: it validates them and exits non-zero on the first bad one.

### Enable Debug Logging

Enable verbose logging in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

```conf
remoted.debug=2
```

View logs:
```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep wazuh-manager-remoted
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
