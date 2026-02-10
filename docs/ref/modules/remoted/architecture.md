# Remoted Architecture

## Overview

The remoted module is the communication gateway between Wazuh agents and the manager. It handles secure connections, message parsing, metadata enrichment, and event forwarding to the analysis engine.

## High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                               Wazuh Manager                                │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                              Remoted Module                          │  │
│  │                                                                      │  │
│  │  ┌──────────────┐    ┌─────────────────┐    ┌───────────────┐        │  │
│  │  │   Network    │    │   Message       │    │   Metadata    │        │  │
│  │  │   Listener   │───▶│   Handler       │───▶│   Database    │        │  │
│  │  │  (TCP/UDP)   │    │   (Threads)     │    │  (OSHash)     │        │  │
│  │  └──────────────┘    └─────────────────┘    └───────────────┘        │  │
│  │         │                     │                      │    │          │  │
│  │         │                     │                      │    │          │  │
│  │         │              ┌──────▼──────┐               │    │          │  │
│  │         │              │   Control   │               │    │          │  │
│  │         │              │   Message   │               │    │          │  │
│  │         │              │   Queue     │               │    │          │  │
│  │         │              │ (Indexed)   │               │    │          │  │
│  │         │              └──────┬──────┘               │    │          │  │
│  │         │                     │                      │    │          │  │
│  │         │              ┌──────▼──────────┐           │    │          │  │
│  │         │              │  Control Msg    │           │    │          │  │
│  │         │              │  Processor      │           │    │          │  │
│  │         │              │  (Threads)      │           │    │          │  │
│  │         │              └──────┬──────────┘           │    │          │  │
│  │         │                     │                      │    │          │  │
│  │         │            ┌────────▼────────────────┐     │    │          │  │
│  │         │            │    wazuh-manager-db     │◀────┘    |          │  │
│  │         │            │     (Agent Info)        │          |          │  │
│  │         │            └─────────────────────────┘          |          │  │
│  │         │                                                 |          │  │
│  │         └─────────────▶┌─────────────────┐                |          │  │
│  │                        │   Event Queue   │                |          │  │
│  │                        │  (Round-Robin)  │                |          │  │
│  │                        └────────┬────────┘                |          │  │
│  │                                 │                         |          │  │
│  │                        ┌────────▼────────┐                |          │  │
│  │                        │  Event Batch    │                |          │  │
│  │                        │  Dispatcher     │◀───────────────┘          │  │
│  │                        │  (Thread)       │   (Enrichment)            │  │
│  │                        └────────┬────────┘                           │  │
│  └─────────────────────────────────┼────────────────────────────────────┘  │
│                                    │                                       │
│                           ┌────────▼────────┐                              │
│                           │  HTTP Client    │                              │
│                           │  (Unix Socket)  │                              │
│                           └────────┬────────┘                              │
└────────────────────────────────────┼───────────────────────────────────────┘
                                     │
                            ┌────────▼─────────────────┐
                            │  wazuh-manager-analysisd │
                            │  /events/ (enriched)     │
                            └──────────────────────────┘
```

## Core Components

### 1. Network Listener

Handles incoming connections from agents over TCP (port 1514, default) or UDP.

### 2. Message Handler

Processes received messages:
- **Decryption**: Decrypts agent messages using AES encryption
- **Validation**: Verifies message integrity and agent authentication
- **Classification**: Determines message type (control vs event)

**Message Types**:
- **Control Messages** (`#!-`): Keep-alive, startup, shutdown
- **Event Messages**: Log data, file integrity, system info

### 3. Metadata Database

In-memory cache storing agent metadata extracted from keep-alive messages:
- Uses OSHash (hash table) indexed by agent ID
- Thread-safe with read/write locks
- Stores: agent name, version, OS details, groups, hostname

### 4. Event Queue & Dispatcher

- Round-robin queue buffers events from all agents
- Dispatcher thread batches events and enriches them with metadata
- Sends batched events via HTTP POST to wazuh-manager-analysisd

### 5. HTTP Client

Forwards enriched event batches to analysisd:
- **Transport**: HTTP over Unix domain socket
- **Socket Path**: `/var/wazuh-manager/queue/sockets/queue`
- **Protocol**: x-wev1 (custom event framing)

## Data Flow

Agent sends event → Network Listener → Decrypt & Validate → Message Classification:
- **Control Message** → Parse Keep-Alive → Update Metadata Cache → Update wazuh-manager-db
- **Event Message** → Event Queue → Batch & Enrich with Metadata → HTTP POST to wazuh-manager-analysisd

## Key Configuration Options

```conf
# Control message queue size (keep-alive processing)
remoted.control_msg_queue_size=16384

# Event batch queue capacity
remoted.batch_events_capacity=131072

# Message handler threads
remoted.worker_pool=4
```

For complete configuration options, see [Configuration](configuration.md).

## References

- [Stateless Metadata](stateless-metadata.md)
- [Event Protocol](event-protocol.md)
- [Configuration](configuration.md)
