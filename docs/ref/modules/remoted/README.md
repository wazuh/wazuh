# Remoted Module

The `remoted` module is responsible for managing secure communication between Wazuh agents and the manager. It handles agent connections, authentication, message routing, and event enrichment.

## Key Features

- **Multi-protocol Support**: TCP and UDP communication protocols
- **Stateless Metadata Enrichment**: Automatic enrichment of agent events with metadata
- **Agent Keep-Alive Processing**: Monitoring and tracking agent connection status
- **Event Batching**: High-performance event aggregation and forwarding
- **Group Management**: Dynamic agent group assignment and configuration distribution
- **HTTPS Events API** *(experimental)*: TLS listener with per-agent AES-CMAC authentication for event ingestion

## Components

- [Architecture](architecture.md) - Overview of remoted's internal architecture
- [Stateless Metadata](stateless-metadata.md) - Agent metadata enrichment for stateless events
- [Event Protocol](event-protocol.md) - Event framing and message format specification
- [HTTPS Events API](https-events-api.md) - TLS endpoint + AES-CMAC agent authentication (experimental)
- [Load balancers](load-balancers/README.md) - Deploying the HTTPS events API behind a load balancer or reverse proxy ([NGINX](load-balancers/nginx.md), [HAProxy](load-balancers/haproxy.md))
- [Configuration](configuration.md) - Configuration options and tuning parameters

## Overview

The remoted module serves as the primary entry point for all agent communications. It:

1. **Receives agent messages** via TCP or UDP connections
2. **Authenticates and validates** messages using agent keys
3. **Extracts metadata** from agent keep-alive messages
4. **Enriches events** with agent and host metadata
5. **Forwards events** to the analysis engine for processing
6. **Manages agent groups** and configuration synchronization

## Related Modules

- **wazuh-manager-db**: Stores agent information and connection status
- **wazuh-manager-analysisd**: Consumes enriched events for rule evaluation
- **inventory-sync-server**: Receives agent state synchronization sessions relayed by the `POST /stateful` route
