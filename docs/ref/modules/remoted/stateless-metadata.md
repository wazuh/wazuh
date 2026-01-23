# Stateless Metadata Enrichment

## Overview

Wazuh 5.0+ enriches every event with agent metadata (identity, OS, groups) before forwarding to analysisd. This eliminates the need for analysisd to maintain agent state, improving scalability and reliability.

## How It Works

1. Agent sends keep-alive with metadata (JSON)
2. Remoted caches metadata in thread-safe hash table
3. Agent sends events
4. Remoted enriches events with cached metadata header
5. Forward to analysisd via x-wev1 protocol

See [Event Protocol](event-protocol.md) for wire format details.

## Group Updates

Group changes propagate automatically:
1. API updates agent groups
2. Manager notifies agent in next keep-alive response
3. Agent sends updated keep-alive
4. Subsequent events include new groups

**Propagation time**: Up to 60 seconds

## Performance

- **Memory**: ~500-1000 bytes per agent
- **Hash Table**: 2048 buckets (increase for >20K agents)
- **Batching**: Header generated once per batch

## Configuration

No configuration required - enabled by default.

For tuning: `remoted.control_msg_queue_size` and `remoted.batch_events_capacity` in `/var/ossec/etc/internal_options.conf`.

See [Configuration Guide](configuration.md) for details.

## References

- [Remoted Architecture](architecture.md)
- [Event Protocol Specification](event-protocol.md)
- [Configuration Guide](configuration.md)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
