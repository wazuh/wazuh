# Agent-manager protocol migration from 4.x to 5.0

## What changed

The agent-manager protocol inherited from OSSEC — a proprietary format encrypted with Blowfish or
AES, carried over UDP or a persistent TCP connection on port `1514` — has been replaced by an
**HTTPS API on port 1517**. A 5.x agent enrolls, reports and receives work over that API
exclusively; it has no legacy code path at all.

The manager keeps serving 4.x agents on the old channel, but only when it is explicitly enabled.

This guide covers the **channel**: which listeners exist, what moved where on the wire, and what an
operator has to change around the manager. For the `wazuh-manager.conf` edits themselves, see
[Manager configuration migration](manager-configuration-migration.md#remote-section). For the agent's
side of the configuration, see [Agent configuration](../../ref/modules/client/configuration.md).

### Why

The old design was hard to scale. A persistent connection pinned each agent to one node, so load
balancing meant balancing connections rather than requests, and every manager-to-agent feature had to
know which node "owned" an agent. Request-per-operation HTTPS removes that coupling: any node can
answer any request, and standard HTTP infrastructure — load balancers, TLS termination, proxies —
works without a custom protocol in the middle.

The consequence to plan for is that **the manager no longer tracks which node an agent is connected
to**. Anything that relied on that mapping is gone or reworked.

## Listeners and ports

| Port | Listener | 5.0 status |
| --- | --- | --- |
| `1517` | Remoted HTTPS agent API | **Default.** Always enabled. Serves 5.x agents, enrollment included. |
| `1514` | Remoted legacy AES TCP/UDP | Opt-in. Only bound when `<remote><legacy>` is present and enabled. Serves 4.x agents. |
| `1515` | `authd` TLS enrollment | Opt-in. Gated by `<auth><legacy_enrollment>`. Only needed by 4.x agents. |

Open `1517/tcp` on the manager before migrating any agent. If your fleet is fully on 5.x, `1514` and
`1515` can both be closed — see [Retiring the legacy channel](#retiring-the-legacy-channel).

> The default `<remote><https><bind_addr>` is `127.0.0.1`. On a manager that must accept agents from
> other hosts, set it to `0.0.0.0` (or a specific address). This mirrors the `<legacy><local_ip>`
> default change described in
> [Manager configuration migration](manager-configuration-migration.md#remote-section).

## Message mapping

Everything the legacy channel carried now maps onto a route. Full contracts in
[HTTPS Agent API](../../ref/modules/remoted/https-events-api.md).

| 4.x mechanism | 5.0 equivalent |
| --- | --- |
| `OSSEC A:'<name>'` enrollment on port 1515 | `POST /enroll` on 1517, which bridges to `authd` over its local socket |
| `#!-agent startup` control message | `POST /control` with `{"type":"startup"}` |
| `#!-agent ack` keep-alive | `POST /control` with `{"type":"notify"}` |
| `#!-agent shutdown` | `POST /control` with `{"type":"shutdown"}` |
| `#!-req` manager-to-agent requests | The `tasks` array in a `notify` response — the agent pulls work instead of the manager pushing it |
| Event messages (logs, SCA, rootcheck, ...) | `POST /stateless`, as an H/E batch |
| `5:` dbsync deltas | **Removed.** Not supported in 5.0. |
| `s:` incremental inventory sync | `POST /stateful` — whole sessions only; the manager no longer accepts incremental syncs |
| `merged.mg` pushed down the connection | `POST /download` with `{"resource_type":"config"}`, triggered by a `config_hash` change in a `notify` response |
| WPK package pushed for remote upgrade | `POST /download` with `{"resource_type":"wpk"}` |
| `u:upgrade_module:` upgrade acknowledgment | Still honored on the legacy channel, so remote upgrade of a 4.x agent keeps working |
| Feed-update rescan driven by the manager | `POST /scan/vd`, requested by the agent when a `notify` response reports a newer `vd_feed_offset` |
| `GET /agents/{id}/stats/{component}` on the server API | `POST /stats`, reported by the agent and read from the `wazuh-agent-stats` index |

### Authentication

The pre-shared key in `client.keys` is still the credential, and **`client.keys` migrates as-is** —
the 64-hex secret `authd` has always generated is exactly the 32-byte key the new scheme needs, so no
re-enrollment is required for the key itself. What changed is how the key is used: instead of deriving a session cipher, each request carries a bearer token the agent signs
with it — a JWT of the closed profile `wazuh-agent+jwt` (HS256, 60-second lifetime, fresh `jti` per
request; see [HTTPS Agent API](../../ref/modules/remoted/https-events-api.md#authentication-jwt-bearer)):

```text
Authorization: Bearer <header>.<claims>.<signature>
protocol-version: 1
```

The key is never transmitted. A token is accepted while `now - iat <= 60 s + 30 s` of tolerated
skew and is never accepted more than 30 s before it was issued, so **the manager and its agents need
roughly synchronized clocks** — a skewed agent clock is a new failure mode with no 4.x equivalent. It
surfaces as `401 Invalid client authentication` (the agent corrects itself from the manager's `Date`
header once and retries). The token does not sign the method, path or body: TLS protects them, so a
proxy that rewrites the path yields a `404`, not a `401`.

The `ip` column of `client.keys` is enforced exactly as the legacy listener enforced it: `any`, a
single address, a CIDR or dotted mask, an IPv6 prefix. A leading `!` is read positively, not as a
negation, matching the legacy keystore — which is what lets a migrated `client.keys` authorize the
same agents it did in 4.x. The peer address is deliberately **not** part of the token, so NAT
between agent and manager does not invalidate it.

### Error semantics

Two differences worth knowing before reading logs:

- Every credential failure — unknown agent, key mismatch, address not allowed, bad signature, stale
  or malformed token — collapses to a single generic **`401`** (with `WWW-Authenticate: Bearer`). The specific cause is deliberately not
  exposed to the client; it is in the manager log and in the `remoted.auth.reject.*` metrics.
- Capacity is shed with **`503`**, never `429`. The manager processes what it has capacity for
  instead of buffering into a fixed queue, which is why `<queue_size>` no longer applies to this
  channel. If an agent ever logs a `429`, something between it and the manager produced it.

## What the legacy channel still carries

With `<remote><legacy>` enabled, a 4.x agent keeps working for events, keep-alives, centralized
configuration and remote upgrade. It does **not** get:

- **Active response.** There is no delivery path for agents below 5.0.0; a task targeting one is
  dropped.
- **Inventory synchronization.** `s:` messages are discarded — a 4.x agent's inventory is not synced
  to a 5.0 manager.
- **dbsync deltas.** `5:` messages are discarded.

Treat the legacy channel as a migration bridge for event collection and upgrade, not as feature
parity. See [Remote agent upgrade](remote-agent-upgrade.md) for the upgrade path itself.

## Options that changed

Three distinct categories, which are easy to conflate:

**Moved** — same meaning, new location. Leaving them directly under `<remote>` is a startup error;
there is no automatic migration.

| 4.x | 5.0 |
| --- | --- |
| `<remote><port>` | `<remote><legacy><port>` |
| `<remote><protocol>` | `<remote><legacy><protocol>` |
| `<remote><ipv6>` | `<remote><legacy><ipv6>` |
| `<remote><local_ip>` | `<remote><legacy><local_ip>` — **default changed to `127.0.0.1`** |
| `<remote><queue_size>` | `<remote><legacy><queue_size>` — legacy channel only; the HTTPS channel uses back-pressure instead |
| `<remote><rids_closing_time>` | `<remote><legacy><rids_closing_time>` |
| `<remote><connection_overtake_time>` | `<remote><legacy><connection_overtake_time>` |

**Removed** — rejected outright; the manager will not start.

| 4.x | Notes |
| --- | --- |
| `<remote><connection>` | All agent-manager communication uses the secure protocol |
| `<remote><allowed-ips>` | Use the `ip` column in `client.keys` |
| `<remote><denied-ips>` | Same |

**New** — the HTTPS listener's own block, `<remote><https>`: `port`, `bind_addr`, `global_prefix`,
`certificate`, `key`, `ca`, `verification_mode`, `ciphers`, `max_body_size`, `dual_stack`.
`<remote><agents>` is unchanged. See
[Remoted configuration](../../ref/modules/remoted/configuration.md#https-configuration).

On the agent side, a 4.x `ossec.conf` is **accepted and ignored** rather than rejected, so an
in-place upgrade still starts: options that no longer apply (`<time-reconnect>`, `<max_retries>`,
`<retry_interval>`, `<protocol>`, `<crypto_method>`, and the `<enrollment>` address/port/certificate
options) log a notice and are skipped. No script rewrites the file for you.

## Certificates

The HTTPS listener requires a certificate and key. Manager packages generate a self-signed pair at
install time, so a default install already satisfies this — but note that starting is **fail-closed**:
if the certificate or key is missing or invalid, `remoted` does not start at all, rather than coming
up without the listener.

`authd` and `remoted` now share one pair, `etc/certs/remoted.pem` and `etc/certs/remoted-key.pem`
(with `etc/certs/root-ca.pem` as the CA). A 4.x configuration that pointed `<auth><ssl_manager_cert>`
and `<ssl_manager_key>` at `authd.pem`/`authd-key.pem` should be repointed, or the overrides dropped
so the defaults apply. See
[Manager configuration migration](manager-configuration-migration.md#auth-section).

Client-certificate validation is optional and configured with
`<remote><https><verification_mode>`: `none` (default), `certificate`, or `full` (which additionally
requires the peer's address to appear in the certificate's SAN).

## Behind a load balancer

HTTPS changes what a load balancer has to do. TLS 1.3 on the backend, aligned body-size and timeout
limits, no PROXY protocol, and **no URL path prefix** — remoted serves its routes at the root. The
worked configurations are in
[Remoted load balancers](../../ref/modules/remoted/load-balancers/README.md).

Because requests are independent, an agent's traffic may be spread across nodes, and that is the
intended behavior rather than something to pin down with session affinity. The one thing to keep
whole is a `POST /stateful` session: it is a single request by design, so a load balancer must not
split or retry it partially.

## Retiring the legacy channel

Once no 4.x agents remain:

1. Remove the `<remote><legacy>` block (or set `<enabled>no</enabled>`). The legacy listener, keystore,
   metadata cache, event queue and dispatcher threads are then never created.
2. Set `<auth><legacy_enrollment>no</legacy_enrollment>` to stop listening on `1515`.
3. Close `1514` and `1515` on the firewall.

Verify with the manager log at startup: it reports either
`Legacy listener disabled ('<remote><legacy>' absent or disabled).` or
`Listening on port <port>/<protocol> (secure).`

## Verification

```bash
# The HTTPS listener answers its unauthenticated liveness probe
curl -k https://<manager>:1517/
# -> {"status":"ok","module":"remoted"}
```

For a signed request against any authenticated route, the module ships the same signing tools the
protocol reference uses — `send_stateless.py`, `send_control.py`, `send_enroll.py`,
`send_download.py`, `send_agent_json.py`, `send_scan_vd.py` under
`src/remoted/remoted_module/tools/`. See
[Testing](../../ref/modules/remoted/https-events-api.md#testing).

Per-endpoint outcomes, authentication rejections and back-pressure are exposed on the module's local
admin socket:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
```

See [Metrics](../../ref/modules/remoted/metrics.md) for the catalog, and
[Diagnosing rejections and capacity problems](../../ref/modules/remoted/https-events-api.md#diagnosing-rejections-and-capacity-problems)
for reading them.

## References

- [HTTPS Agent API](../../ref/modules/remoted/https-events-api.md) — the protocol and all nine endpoints
- [Remoted architecture](../../ref/modules/remoted/architecture.md) — how the two channels sit side by side
- [Remoted configuration](../../ref/modules/remoted/configuration.md) — every `<remote>` option and internal option
- [Manager configuration migration](manager-configuration-migration.md) — the `wazuh-manager.conf` edits
- [Remote agent upgrade](remote-agent-upgrade.md) — upgrading 4.x agents to 5.x
- [Authd](../../ref/modules/authd/README.md) — enrollment logic and the `remote_enrollment` / `legacy_enrollment` matrix
