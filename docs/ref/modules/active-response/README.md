# Active Response

The **Active Response** module runs a response action on an agent — block an IP address, lock a user
account, or run a script of your own — when an event indexed in the Wazuh Indexer matches an Alerting
monitor. The decision is made in the Indexer, the manager relays the response to the agent as a Task
Manager task, and the agent's `wazuh-execd` daemon runs the executable and, for a stateful response,
reverts it when its timeout expires.

## Key Features

- **IP blocking**: `block-ip` tries the platform's mechanisms in order and stops at the first that
  succeeds — firewalld then iptables on Linux, ipfw/pf/npf on the BSDs, pf on macOS, each followed by
  `hosts.deny` and `route`; netsh then `route` on Windows
- **Account locking**: `disable-account` locks a local account (`passwd -l` on Linux, `pwpolicy` on macOS)
- **Stateful or stateless**: a stateful response is reverted by `wazuh-execd` after its
  `stateful_timeout`; a stateless one runs once
- **Deduplication**: a stateful response repeated for the same keys (IP address, user name) while its
  reversion is pending is not run again; its countdown restarts instead
- **Metadata-driven**: what to run and for how long travels in the message under
  `wazuh.active_response`; the agent needs no per-response configuration
- **Custom executables**: any program in the agent's `active-response/bin/` that follows the JSON
  protocol on stdin/stdout

## Overview

1. **Event detection**: an Alerting monitor in the Wazuh Indexer matches an indexed event.
2. **Response document**: the monitor's Active Response notification channel writes a response
   document to the `wazuh-active-responses` data stream.
3. **Task creation**: `wazuh-manager-clusterd`, on every cluster node, reads the document and creates
   one Task Manager task of type `active_response` per target agent (see
   [Manager-side ingestion](architecture.md#manager-side-ingestion)).
4. **Delivery**: the agent receives the task in the response to its next `POST /control` and forwards
   the payload to `wazuh-execd`.
5. **Execution**: `wazuh-execd` runs `active-response/bin/<executable>` with the message on stdin and
   `"command": "enable"`; for a stateful response it runs it again with `"command": "disable"` once
   the timeout expires.

```
┌──────────────────┐  task   ┌──────────────────┐ execq  ┌──────────────┐  stdin  ┌────────────┐
│ Manager          │ ──────> │ wazuh-agentd     │ ─────> │ wazuh-execd  │ ──────> │ executable │
│ (clusterd + Task │  POST   │ (HTTPS client)   │  JSON  │ (agent)      │  JSON   │ (block-ip) │
│  Manager)        │ /control└──────────────────┘        └──────┬───────┘ <────── └────────────┘
└──────────────────┘                                            │        check_keys
                                                                │ timeout list:
                                                                └ re-run with "disable"
```

The message format, the `check_keys` exchange and the timeout handling are specified in
[Architecture](architecture.md#json-protocol).

## Executables

| Executable | Platforms | Action |
|---|---|---|
| `block-ip` | Linux, FreeBSD, OpenBSD, NetBSD, macOS, Windows | Blocks `source.ip`; one binary per platform family with its own method chain |
| `disable-account` | Linux, macOS | Locks `user.name` |

Method chains, commands and per-platform behaviour: [Executables Reference](executables.md).

## Configuration

What runs and when is configured in the Wazuh dashboard: a notification channel of the Active
Response type says what to run, and an Alerting monitor says when. There is no `<active-response>`
section in the manager configuration. On the agent, the `<active-response>` block of the local
`ossec.conf` can disable execution, set `repeated_offenders` or add `allowlist` entries; see
[Configuration](configuration.md).

## Restart and reload are not Active Response

Agent restart and reload are `agent_restart` / `agent_reload` tasks handled by the
[Control Module](../control/README.md), not Active Response executables.

## Logging

| Where | What |
|---|---|
| Agent: `logs/active-responses.log` under the agent's installation directory (`/var/ossec`, `/Library/Ossec` on macOS); `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` on Windows | What each executable did, written by the executable |
| Agent: `logs/ossec.log` (`ossec.log` on Windows), tag `wazuh-execd` | What `wazuh-execd` received, ran and reverted, and why a message was refused |
| Manager: `/var/wazuh-manager/logs/cluster.log`, tag `[Active Response]` | What the poller read, dispatched, held or discarded |

The agent's default `ossec.conf` also monitors `logs/active-responses.log` with a `<localfile>`
block, so its lines reach the manager as events.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Manager-side ingestion, delivery, `wazuh-execd`, the JSON protocol and every log message |
| [Configuration](configuration.md) | The agent's `<active-response>` block, internal options and troubleshooting |
| [Executables Reference](executables.md) | `block-ip` and `disable-account` per platform, and how to write a custom executable |

## See Also

- [Control Module](../control/README.md) - Agent restart/reload operations
- [Task Manager](../task_manager/README.md) - Storage and delivery of agent tasks
- [Remoted](../remoted/README.md) - The agent-facing `POST /control` endpoint
