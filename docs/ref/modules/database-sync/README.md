# Database Sync Module

Agent database synchronization functionality within Wazuh DB.

## Overview

The Database Sync module manages the synchronization of agent-related data between the manager and the global database. This includes agent status updates, group assignments, and connection state management.

**Daemon:** Part of `wazuh-db`

**Component:** Manager-only

## Functionality

The Database Sync module handles:

- **Agent Status Synchronization**: Tracks and updates agent connection status and sync states
- **Group Synchronization**: Manages agent group assignments and hash recalculation
- **Real-time Updates**: Provides real-time or interval-based synchronization modes
- **Event Queue Management**: Buffers agent status update events for batch processing

## Configuration

Database sync is configured exclusively through internal options. See [Configuration](configuration.md) for details.

## See Also

- [Configuration](configuration.md) - Internal options reference
- [Wazuh DB](../wazuh_db/index.html) - Database management module
