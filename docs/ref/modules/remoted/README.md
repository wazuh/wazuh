# Remoted Module

The `remoted` module is responsible for managing secure communication between Wazuh agents and the manager. It handles agent connections, authentication, message routing, and event enrichment.

It serves two channels at once, and they share almost nothing:

- The **HTTPS agent API** on port `1517` — the transport in 5.0. A 5.x agent enrolls, reports and receives work over it exclusively.
- The **legacy AES-encrypted TCP/UDP channel** on port `1514` — kept only to serve 4.x agents. The
  schema leaves it off when `<remote><legacy>` is absent, but the installer writes
  `<legacy><enabled>yes</enabled>` into `etc/wazuh-manager.conf`, so an installed manager listens on
  `1514` until an operator sets it to `no` (see [`legacy.enabled`](configuration.md#legacyenabled)).

Every HTTPS route is served under the [`https.global_prefix`](configuration.md#httpsglobal_prefix),
`/wazuh-manager/` by default: `POST /stateless` below is `POST /wazuh-manager/stateless` on the wire,
and the unauthenticated health probe is `GET /wazuh-manager/` (unprefixed paths answer `404`).

## Key Features

- **HTTPS agent API**: TLS 1.3 listener with per-agent JWT bearer authentication (`wazuh-agent+jwt`, HS256 with the agent's `client.keys` key), serving eleven agent-facing routes (CA distribution, enrollment, events, state sync, control, file download, reporting)
- **Back-pressure**: capacity bounded by an in-flight byte budget and a deferred-work limiter rather than a fixed queue, shedding excess load with `503`
- **Group Management**: dynamic agent group assignment and centralized configuration distribution
- **Legacy compatibility**: TCP and UDP transports, AES message decryption, keep-alive metadata extraction and event batching for 4.x agents

## Components

- [Architecture](architecture.md) - Overview of remoted's internal architecture
- [HTTPS Agent API](https-events-api.md) - The agent-facing protocol: TLS, JWT bearer authentication, and all eleven endpoints
- [OpenAPI contract](agent-api.yaml) - The same contract as OpenAPI 3 (`agent-api.yaml`; the book also publishes a ReDoc viewer of it, `agent-api-reference.html`, beside this page)
- [Load balancers](load-balancers/README.md) - Deploying the HTTPS agent API behind a load balancer or reverse proxy ([NGINX](load-balancers/nginx.md), [HAProxy](load-balancers/haproxy.md))
- [Configuration](configuration.md) - Configuration options and tuning parameters
- [Connection timing tuning](timing-tuning.md) - The agent↔manager timing contract: which timeout, retry and throttle settings pair with which, and what breaks when they are moved alone
- [Metrics](metrics.md) - The HTTPS agent server's metric catalog, each metric linked to the setting it helps size
- [CA Rotation Runbook](ca-rotation.md) - Operating a multi-CA bundle rotation with `wazuh-manager-certs`: the fixed step order and the four ways to get it wrong
- [Certificate Validity](certificate-validity.md) - The `GET /tls` resource: the served certificate and the CA bundle, field by field
- [Stateless Metadata](stateless-metadata.md) - Agent metadata enrichment for stateless events (legacy channel)
- [Event Protocol](event-protocol.md) - Event framing and message format specification
- [Quick Reference](quick-reference.md) - Commands, counters and starting-point settings for both channels

## Overview

For a 5.x agent, remoted:

1. **Registers the agent** via `POST /enroll`, bridging to `authd`
2. **Authenticates every request** with a bearer token the agent signs with its pre-shared key (`wazuh-agent+jwt`, HS256), and checks the peer address against the agent's `client.keys` entry
3. **Receives events** via `POST /stateless` and relays them to the engine's event ingress
4. **Receives state** via `POST /stateful` and relays whole sessions to the inventory sync server
5. **Answers lifecycle messages** on `POST /control`, dispatching pending work back to the agent
6. **Serves centralized configuration and upgrade packages** on `POST /download`

On the legacy channel it instead receives AES-encrypted messages over TCP/UDP, extracts metadata from
keep-alives, enriches and batches events, and forwards them to the engine.

## Local admin socket

The C++ module serves its own metrics and readiness status over a manager-local Unix socket,
`queue/sockets/remote-admin-http.sock` (fixed path, mode `0660`), separate by design from the
agent-facing HTTPS endpoint — neither is ever exposed on the public listener. On a cluster worker,
the local cluster daemon also uses it to tell remoted which group memberships it just wrote to the
node's database.

| Route | Response |
|---|---|
| `GET /` | `200` `{"status":"ok","module":"remoted_module"}` |
| `GET /metrics` | `200` — JSON dump of every metric family the module keeps (request outcomes and latency per endpoint, auth-rejection and downstream-failure taxonomies, backpressure, keystore health, ...) — see [Metrics](metrics.md) for the full catalog and the settings each metric relates to |
| `GET /tls` | `200` — validity of the TLS material served to agents: the listener certificate (dates, `x509-sha256` identity, `loaded_at`) and every certificate of the CA bundle `GET /cacerts` hands out, with whether it signs the served one. No thresholds. `503` while the HTTPS listener is not up. Field by field in [Certificate validity](certificate-validity.md); the Server API serves it per node as `GET /cluster/{node_id}/daemons/remoted/tls` |
| `POST /_internal/agents/groups` | Internal, for the cluster daemon: the agent-group memberships a worker just applied to its local `wazuh-manager-db`, so `/control` and `/download` use them at once instead of when the cached membership expires (`remoted.control_groups_refresh_interval`). Body `{"set":[{"id":1,"groups":["default","web"]}],"invalidate":[5]}` (either key may be absent, not both): `set` replaces the groups of an agent this node already tracks (an empty list is `default`), `invalidate` makes remoted read the agent's groups from the database again on its next request; an agent the node does not track is skipped, never added. `200 {"updated":1,"invalidated":0,"skipped":0}` (counts per agent); `400 {"error":"…","code":400}` for a malformed body — nothing is applied; `413` above 256 KiB; `503` while remoted is stopping. Authorization is the socket's permissions: whoever can write to it can already change memberships in the database directly. Counted in `remoted.control.registry.push.*` ([Metrics](metrics.md#control-plane--remotedcontrol)) |
| `GET /status` | `200` — readiness, not bare liveness: `ready` reflects whether an enrollment password key is currently available, when enrollment is administratively enabled and Password-mode enrollment is on; it is `true` whenever remoted answers at all if either flag is off. `{"ready":true,"enrollment_password":{"ready":true},"keystore":{"readable":true,"agents_loaded":12,"entries_skipped":0},"enrollment_tokens":{"loaded":3,"last_reload_ok":true}}` (`enrollment_password` is omitted entirely unless both flags are on; `enrollment_tokens` is omitted when enrollment is off). `keystore` reports whether `client.keys` last reloaded successfully — informational only, it never gates `ready`, since remoted cannot tell an empty-but-fine `client.keys` apart from a stale one still serving the old table. `enrollment_tokens` does the same for the replica of `etc/enrollment_tokens.json` that verifies enrollment-token bearers (`loaded` = credential-bearing tokens in the replica; an absent file is a valid empty replica): informational, never gates `ready`. `503` before the module's keystore is up. `GET /cluster/{node_id}/status` embeds `ready`, `keystore` and `enrollment_password` from it under `wazuh-manager-remoted` |

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/status
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/tls | jq
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock -X POST \
  -H 'Content-Type: application/json' -d '{"invalidate":[1]}' http://localhost/_internal/agents/groups
```

A failure to bring this socket up only logs a warning: the admin plane is optional and remoted
keeps serving agents without it. The cluster daemon's membership updates are then lost too, and a
node follows its database only as cached memberships expire. When the admin socket is unreachable
while remoted itself is running, `GET /cluster/{node_id}/status` falls back to plain liveness
(`ready: true`) with a `reason: "admin socket unreachable"` field, rather than reporting the node not
ready — the admin plane failing to come up is not the same as remoted being unready.

A caller that needs Password-mode enrollment to be usable — not just remoted to be alive — should
poll `/status` (or `/cluster/{node_id}/status`) until `ready: true` with a bounded timeout before
proceeding, rather than assuming readiness the moment the process starts. On a joining worker,
`ready` turns `true` once the cluster's `etc/` file group (`client.keys`, `authd.pass`,
`enrollment_tokens.json`) has been synchronized from the master.

That is a first-join effect of those files travelling in the same synchronization group, not a
synchronization check: `client.keys` changes on every later enrollment, so a later `ready: true`
does not mean `client.keys` is currently in sync with the master — only `enrollment_password.ready`
gates `ready`, and `keystore` stays purely informational for exactly that reason (see above).

## Local request socket

Independently of the admin socket, the C daemon binds `queue/sockets/remote.sock` (always, whether
or not the legacy channel is enabled). It takes length-prefixed JSON commands from the manager's own
components:

| Command | Answer |
|---|---|
| `{"command":"getstats"}` | The legacy channel's counters (`metrics.bytes`, `metrics.messages`, `metrics.queues`, `metrics.tcp_sessions`, ...); the Server API's `GET /cluster/{node_id}/daemons/stats` reads them from here |
| `{"command":"getconfig","parameters":{"section":"remote"\|"internal"\|"global"}}` | The effective `remote` or `global` section, or the resolved `remoted.*` internal options; served by `GET /cluster/{node_id}/configuration/request/{section}` |
| `{"command":"assigngroup",...}` | Assigns the `default` group to a 4.x agent that has none; a worker's remoted sends it to the master's through the cluster |

Any message that is not JSON is taken as a request to forward to a 4.x agent over the legacy
channel, and is refused with `err Legacy delivery disabled` when that channel is off.

## Related Modules

- **wazuh-manager-db**: Stores agent information and connection status
- **Engine**: Consumes the event batches relayed by `POST /stateless` (and by the legacy channel) at its event ingress, `POST /events/enriched`
- **authd**: Owns all enrollment business logic; `POST /enroll` bridges to it over its local socket
- **task-manager**: Source of the pending tasks `POST /control` dispatches to agents
- **vulnerability_scanner**: Target of the on-demand re-scan requests relayed by `POST /scan/vd`
- **inventory-sync-server**: Receives agent state synchronization sessions relayed by the `POST /stateful` route
