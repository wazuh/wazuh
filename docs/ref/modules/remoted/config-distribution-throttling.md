# Centralized Configuration Distribution Throttling

This document describes the investigation and design behind the mechanism that paces the distribution of centralized (group) configuration updates in `wazuh-manager-remoted`, and the associated staggering of agent restarts. It addresses [issue #37527](https://github.com/wazuh/wazuh/issues/37527).

## Problem

When the centralized configuration of a group changes, every agent in that group must download the new configuration and reload/restart. In large deployments (thousands of agents per group), this happens within a very narrow time window, producing load spikes on the manager:

- Simultaneous downloads of the updated `merged.mg`.
- Simultaneous agent restarts.
- Simultaneous reconnections and bursts of synchronization and event traffic afterwards.

## Current workflow

The relevant code lives in `src/remoted/src/manager.c`:

1. `update_shared_files()` rebuilds each group's `merged.mg` every `shared_reload_interval` seconds (10 by default) and stores its MD5 checksum.
2. On every agent keep-alive, `save_controlmsg()` compares the group's checksum against the checksum the agent reports. On mismatch it pushes the agent ID onto `pending_queue` and marks the agent as *not synced*.
3. A pool of `sender_pool` (8 by default) `wait_for_msgs()` threads pop `pending_queue` and call `send_file_toagent()`, sending the file **as fast as they can**.
4. On the agent side (`src/client-agent/src/receiver.c`), once the new `merged.mg` is received and its checksum verified, the agent triggers a reload/restart.

Because the restart is driven by the *reception* of the configuration, throttling the distribution on the manager side is sufficient to stagger both the downloads and the restarts. No agent-side change is required, which keeps older agents fully compatible.

## Evaluated strategies

| Strategy | Pros | Cons |
|----------|------|------|
| **Rate limiting / batched distribution** (chosen) | Single manager-side change at the natural chokepoint (`wait_for_msgs`); staggers downloads *and* restarts at once; cluster-friendly (each node paces its own agents); fully backward compatible | Restart timing is indirect (a consequence of paced delivery) rather than explicitly scheduled |
| Randomized restart delay (jitter) on the agent | Directly spreads restarts | Requires an agent-side protocol change; breaks compatibility with existing agents; does not spread the configuration downloads |
| Dedicated distribution queue with workers | Flexible scheduling | `pending_queue` already exists; adding a second queue duplicates state for little gain |
| Cluster-aware global balancing | Global optimum across the cluster | High complexity; needs cross-node coordination; each node already only serves the agents connected to it |

## Chosen solution

A **token-bucket rate limiter** shared by the sender threads, applied right before `send_file_toagent()` in `wait_for_msgs()`.

- Capacity (burst) and refill amount: `shared_config_batch_size` agents.
- Refill window: `shared_config_interval` seconds.
- Effective steady-state rate: `shared_config_batch_size / shared_config_interval` agents per
  second, after an initial burst of one full batch.

The pacing math is isolated in the pure helper `shared_config_bucket_update()` (no clock, no sleep) so it can be unit-tested deterministically; `throttle_shared_config_distribution()` wraps it with the shared mutex, the monotonic-style clock and the sleep.

### Configuration

Two options in the `<remote>` block of `ossec.conf` (see [configuration.md](configuration.md) for details):

- `shared_config_batch_size` — default `0`, which **disables** throttling and preserves the legacy "send as fast as possible" behavior. Backward compatible by default.
- `shared_config_interval` — default `5` seconds; only used when `shared_config_batch_size > 0`.

### Cluster behavior

Each cluster node runs its own `remoted` and only serves the agents connected to it. The limiter is therefore applied per node with no cross-node coordination required, which keeps the design simple and compatible with clustered environments. The effective cluster-wide rate is the sum of the per-node rates.

## Testing

- **Unit tests** (`src/unit_tests/remoted/`): `test_remote-config.c` covers parsing and validation of both options; `test_manager.c` covers the token-bucket math (`shared_config_bucket_update`): granting, refilling, capping at the batch size, and reporting the wait time when empty.
- **Integration tests** (`tests/integration/test_remoted/`): validation of valid/invalid option values, and a staggered-distribution test that simulates several agents in a group and asserts the configuration pushes are spread over time.
