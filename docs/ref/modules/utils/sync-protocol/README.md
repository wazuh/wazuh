# Agent Sync Protocol

> **Scope note:** This is agent-side infrastructure — despite being documented alongside other
> shared/manager modules, `sync_protocol` has no manager-side usage; it is linked only by agent
> build targets (FIM, SCA, Syscollector, agent_info, the HTTPS client).

## Introduction

The **Agent Sync Protocol** is a shared module that provides a standardized interface for internal Wazuh modules (FIM, SCA, Inventory) to synchronize data with the Wazuh Manager. It implements a reliable, session-based synchronization mechanism that ensures data consistency and handles errors gracefully.

The protocol sends changes as **delta** synchronizations; a full replace is a `DataClean` of the
index followed by a delta synchronization of the fresh snapshot. It uses a persistent queue backed by SQLite for durability.
Timeout and retry behaviour for the HTTP layer are owned exclusively by the HTTPS transport module;
the sync protocol waits for the transport callback (up to a 15-minute safety net) and relies on the
module's own periodic cycle to retry after failures.

## Key Features

- **Unified API**: Single interface for all modules to interact with the synchronization protocol
- **Persistent Storage**: SQLite-based queue survives a clean restart, and an agent crash except for the in-memory buffer not yet flushed; an OS crash or power loss can lose recent commits. FIM, SCA and syscollector resend lost items after their next integrity check (see [Persistence Performance](persistence-performance.md))
- **Session Management**: Unique session IDs track synchronization state and guard against stale responses
- **Transport-Owned Retry**: HTTP-level retries and per-request timeouts are managed by the HTTPS
  transport layer (internal options `agent.https_stateful_attempts`, `agent.https_stateful_timeout`);
  the protocol layer only adds a 15-minute safety-net ceiling for a result that never arrives
- **Byte-Capped Sessions**: Delta sessions are capped at `<agent><batch><size>` (1 MiB by default), except `Option::VDFIRST`/`Option::VDSYNC`; a single larger item is sent alone, and dropped after repeated failures
- **Multiple Sync Modes**: Delta, integrity check, metadata, and groups synchronization, plus `DataClean`

## Architecture Overview

Each internal module maintains its own instance of the Agent Sync Protocol with dedicated persistent storage:

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│     FIM     │   │     SCA     │   │ Syscollector│
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
│ Agent Sync  │   │ Agent Sync  │   │ Agent Sync  │
│ Protocol    │   │ Protocol    │   │ Protocol    │
│ (FIM)       │   │ (SCA)       │   │(Syscollector│
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
│   SQLite    │   │   SQLite    │   │   SQLite    │
│ fim_sync.db │   │ sca_sync.db │   │ sys_sync.db │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       └────────────┬────┴─────────────────┘
                    │  one FullSession message per session
                    ▼
        ┌───────────────────────┐
        │   queue-sync socket   │  (local AF_UNIX STREAM,
        │  (SyncSocketTransport)│   no size bound)
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │  agentd / https_client │
        └───────────┬───────────┘
                    │  HTTPS POST /stateful
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
- [Persistence Performance](persistence-performance.md) - WAL mode justification and performance analysis

## Quick Start

To integrate the Agent Sync Protocol in your module:

1. Include the appropriate header based on your language:
   - C++: `agent_sync_protocol.hpp`
   - C: `agent_sync_protocol_c_interface.h`

2. Create a protocol instance with your module name and database path

3. Persist differences using `persistDifference()` / `asp_persist_diff()`

4. Process manager responses with `parseResponseBuffer()` or `asp_parse_response_buffer()`

5. Check data integrity (optional):
   - `requiresFullSync()` / `asp_requires_full_sync()` to verify checksums

6. Trigger synchronization with:
   - `synchronizeModule()` / `asp_sync_module()` for module data
   - `synchronizeMetadataOrGroups()` / `asp_sync_metadata_or_groups()` for metadata/groups

7. For a full-replace resync (e.g. after a checksum mismatch), call `notifyDataClean()` /
   `asp_notify_data_clean()` on the affected indices first, then re-persist the fresh snapshot
   and synchronize with `Mode::DELTA` — there is no in-memory recovery API or `Mode::FULL`
   anymore (see [Protocol Lifecycle](lifecycle.md#full-replace-recovery-dataclean-then-delta)).

See the [Integration Guide](integration-guide.md) for detailed examples.
