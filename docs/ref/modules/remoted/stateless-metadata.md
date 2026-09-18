# Stateless Metadata Enrichment

## Overview

Each batch carries an agent ID and can carry context such as name, version, groups and host data.
The engine reads that context from the header and caches parsed headers; it does not need a separate
agent lookup to obtain those fields. The manager builds the header only on the legacy channel.

| Channel | Who builds the `H` header | Metadata source |
| --- | --- | --- |
| HTTPS agent API (`POST /stateless`, 5.x agents) | the **agent** | its own configuration and host |
| Legacy TCP/UDP (`<remote><legacy>`, 4.x agents) | the **manager** | the metadata cache described below |

On the HTTPS path remoted does not enrich anything: it verifies that the header's
`wazuh.agent.id` matches the authenticated agent and relays the batch to the engine unchanged. A
5.x agent reports its host metadata separately, on `POST /control` (`notify`), and the manager
writes that straight to wazuh-db — see
[HTTPS Agent API](https-events-api.md#control-endpoint-post-control).

**The cache below belongs to the legacy channel.** It runs only when `<remote><legacy>` is
present and enabled; on a manager serving 5.x agents exclusively, none of it is active.

<a id="how-it-works"></a>

## How It Works (legacy channel)

1. A 4.x agent sends a keep-alive carrying its metadata
2. Remoted caches that metadata in a thread-safe hash table, keyed by agent ID
3. The agent sends events
4. Remoted builds the batch header from the cached metadata
5. The batch is forwarded to the engine in the `x-wev1` framing

See [Event Protocol](event-protocol.md) for the wire format, including the exact header shape and
the single-space `H `/`E ` line prefixes.

## Group Updates

**Current legacy limitation:** `agent_meta_from_agent_info()` copies name, version and host fields,
but never fills the cache's `groups` member. `append_header()` emits groups only when that member is
populated, so this path currently omits `wazuh.agent.groups`. A group change is not guaranteed to
appear in subsequent legacy event headers. The manager's group/configuration distribution is a
separate path; no fixed end-to-end propagation bound follows from this cache.

A 5.x agent learns about a group change differently: `POST /control` (`notify`) returns a
`config_hash` and a `config_token`, and a changed hash is what makes the agent fetch the new
configuration over `POST /download`.

## Performance

- **Memory**: varies with the copied strings and allocations; there is no fixed per-agent byte bound
- **Hash table**: 2048 buckets. This is a compile-time constant, not a setting — see
  [Configuration](configuration.md#hash-table-tuning)
- **Batching**: the header is generated once per batch, not once per event

## Configuration

The enrichment itself has no options: when the legacy channel is enabled, it is always on.

What is tunable is the cache's entry lifetime and the queues feeding it —
`remoted.enrich_cache_expire_time`, `remoted.control_msg_queue_size` and
`remoted.batch_events_capacity` in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`.

See the [Configuration guide](configuration.md#stateless-metadata-cache) for defaults and sizing.

## References

- [Remoted Architecture](architecture.md)
- [Event Protocol Specification](event-protocol.md)
- [HTTPS Agent API](https-events-api.md)
- [Configuration Guide](configuration.md)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
