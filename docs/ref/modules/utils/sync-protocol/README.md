# Agent Sync Protocol

## Introduction

The **Agent Sync Protocol** is a shared module that provides a standardized interface for internal Wazuh modules (FIM, SCA, Inventory) to synchronize data with the Wazuh Manager. It implements a reliable, session-based synchronization mechanism that ensures data consistency and handles errors gracefully.

The protocol supports both **full** and **delta synchronization modes**, enabling efficient data transfer while maintaining state consistency. It uses a persistent queue backed by SQLite for durability and implements retry mechanisms with timeout controls to handle failures.

## Key Features

- **Unified API**: Single interface for all modules to interact with the synchronization protocol
- **Persistent Storage**: SQLite-based queue ensures data durability across agent restarts
- **Session Management**: Unique session IDs track synchronization state between agent and manager
- **Retry Mechanism**: Configurable retry attempts with exponential backoff for network resilience
- **EPS Control**: Rate limiting to prevent overwhelming the manager with data
- **Multiple Sync Modes**: Support for full, delta, integrity check, metadata, and groups synchronization

## Architecture Overview

Each internal module maintains its own instance of the Agent Sync Protocol with dedicated persistent storage:

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│     FIM     │   │     SCA     │   │  Inventory  │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
│ Agent Sync  │   │ Agent Sync  │   │ Agent Sync  │
│ Protocol    │   │ Protocol    │   │ Protocol    │
│ (FIM)       │   │ (SCA)       │   │ (Inventory) │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
│   SQLite    │   │   SQLite    │   │   SQLite    │
│ fim_sync.db │   │ sca_sync.db │   │ inv_sync.db │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       └────────────┬────┴─────────────────┘
                    │
           ┌────────▼────────┐
           │  Message Queue  │
           │    (MQueue)     │
           └────────┬────────┘
                    │
                    ▼
             Wazuh Manager
```

Each module instance:
- Has its own Agent Sync Protocol instance
- Maintains separate SQLite database for persistent storage
- Manages its own synchronization sessions independently
- Shares the same Message Queue infrastructure

## Documentation Structure

- [API Reference](api-reference.md) - Complete API documentation with function signatures
- [Integration Guide](integration-guide.md) - Step-by-step module integration examples
- [Protocol Lifecycle](lifecycle.md) - Detailed explanation of the synchronization phases
- [Sequence Diagrams](sequence-diagrams.md) - Visual representation of protocol interactions

## Quick Start

To integrate the Agent Sync Protocol in your module:

1. Include the appropriate header based on your language:
   - C++: `agent_sync_protocol.hpp`
   - C: `agent_sync_protocol_c_interface.h`

2. Create a protocol instance with your module name and database path

3. Persist differences using:
   - `persistDifference()` / `asp_persist_diff()` for database storage
   - `persistDifferenceInMemory()` / `asp_persist_diff_in_memory()` for in-memory recovery

4. Process manager responses with `parseResponseBuffer()` or `asp_parse_response_buffer()`

5. Check data integrity (optional):
   - `requiresFullSync()` / `asp_requires_full_sync()` to verify checksums

6. Trigger synchronization with:
   - `synchronizeModule()` / `asp_sync_module()` for module data
   - `synchronizeMetadataOrGroups()` / `asp_sync_metadata_or_groups()` for metadata/groups

7. Clean up in-memory data (if used):
   - `clearInMemoryData()` / `asp_clear_in_memory_data()` after recovery

See the [Integration Guide](integration-guide.md) for detailed examples.
