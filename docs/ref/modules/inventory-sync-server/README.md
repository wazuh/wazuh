# Inventory Sync Server Module

Manager-side ingress for agent inventory synchronization, exposed over an HTTP/1.1 Unix domain socket
by `wazuh-manager-modulesd`.

Transitional: it runs alongside [Inventory Sync](../inventory-sync/README.md), which still owns the
router-based ingress and the state store. This module owns the socket that
[Remoted](../remoted/README.md) forwards agent requests to.

## Key Features

- HTTP/1.1 over a Unix domain socket, so no TCP port is exposed.
- Non-blocking transport: each connection runs on its own strand, and a response may be produced long
  after its handler returned.
- Admission control before a body is read: a global in-flight byte budget and a connection cap, both
  answering an explicit status rather than queueing silently.
- Two-phase shutdown bounded to fit the daemon's shutdown budget.
- Startup gate: the socket does not open until the indexer session and both connectors are constructed
  successfully.

## Components

- [Architecture](architecture.md) - transport, startup gate and shutdown protocol
- [Configuration](configuration.md) - the internal options, their ranges and their defaults
- [API Reference](api-reference.md) - the routes, their statuses and their bodies

## Overview

1. An agent sends inventory data to `wazuh-manager-remoted` over HTTPS.
2. Remoted authenticates it and forwards the payload to this module's Unix socket, adding the
   authenticated agent id as a request header.
3. This module validates the request, enriches the document with the agent id, this manager's cluster
   identity and a server timestamp, and answers.
4. An unhealthy indexer is reported as `503` so the agent retries rather than losing the data silently.

## Related Modules

- [Inventory Sync](../inventory-sync/README.md) - the module this one will replace. Both run in the same
  daemon during the migration and deliberately share nothing: different sockets, different store paths
  and different log tags, so their output can be told apart.
- [Remoted](../remoted/README.md) - the only production peer.
- [Indexer Connector](../indexer_connector/README.md) - the library used to reach the indexer.
