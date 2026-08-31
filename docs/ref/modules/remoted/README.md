# Remoted Module

The `remoted` module is responsible for managing secure communication between Wazuh agents and the manager. It handles agent connections, authentication, message routing, and event enrichment.

It serves two channels at once, and they share almost nothing:

- The **HTTPS agent API** on port `1517` — the transport in 5.0. A 5.x agent enrolls, reports and receives work over it exclusively.
- The **legacy AES-encrypted TCP/UDP channel** on port `1514` — kept only to serve 4.x agents, and started only when `<remote><legacy>` is explicitly enabled.

## Key Features

- **HTTPS agent API**: TLS 1.3 listener with per-agent JWT bearer authentication (`wazuh-agent+jwt`, HS256 with the agent's `client.keys` key), serving nine agent-facing routes (enrollment, events, state sync, control, file download, reporting)
- **Back-pressure**: capacity bounded by an in-flight byte budget and a deferred-work limiter rather than a fixed queue, shedding excess load with `503`
- **Group Management**: dynamic agent group assignment and centralized configuration distribution
- **Legacy compatibility** *(opt-in)*: TCP and UDP transports, AES message decryption, keep-alive metadata extraction and event batching for 4.x agents

## Components

- [Architecture](architecture.md) - Overview of remoted's internal architecture
- [HTTPS Agent API](https-events-api.md) - The agent-facing protocol: TLS, JWT bearer authentication, and all nine endpoints
- [Endpoint reference](agent-api-reference.html) - The same contract as OpenAPI (source: [`agent-api.yaml`](agent-api.yaml))
- [Load balancers](load-balancers/README.md) - Deploying the HTTPS agent API behind a load balancer or reverse proxy ([NGINX](load-balancers/nginx.md), [HAProxy](load-balancers/haproxy.md))
- [Configuration](configuration.md) - Configuration options and tuning parameters
- [Metrics](metrics.md) - The HTTPS agent server's metric catalog, each metric linked to the setting it helps size
- [Stateless Metadata](stateless-metadata.md) - Agent metadata enrichment for stateless events (legacy channel)
- [Event Protocol](event-protocol.md) - Event framing and message format specification

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

The C++ module serves its own metrics over a manager-local Unix socket,
`queue/sockets/remote-admin-http.sock` (fixed path, mode `0660`), separate by design from the
agent-facing HTTPS endpoint — statistics are never exposed on the public listener.

| Route | Response |
|---|---|
| `GET /` | `200` `{"status":"ok","module":"remoted_module"}` |
| `GET /metrics` | `200` — JSON dump of every metric family the module keeps (request outcomes and latency per endpoint, auth-rejection and downstream-failure taxonomies, backpressure, keystore health, ...) — see [Metrics](metrics.md) for the full catalog and the settings each metric relates to |

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
```

A failure to bring this socket up only logs a warning: the admin plane is optional and remoted
keeps serving agents without it. The legacy `getstate` control socket is unaffected.

## Related Modules

- **wazuh-manager-db**: Stores agent information and connection status
- **Engine**: Consumes the event batches relayed by `POST /stateless` (and by the legacy channel) at its event ingress, `POST /events/enriched`
- **authd**: Owns all enrollment business logic; `POST /enroll` bridges to it over its local socket
- **task-manager**: Source of the pending tasks `POST /control` dispatches to agents
- **vulnerability_scanner**: Target of the on-demand re-scan requests relayed by `POST /scan/vd`
- **inventory-sync-server**: Receives agent state synchronization sessions relayed by the `POST /stateful` route
