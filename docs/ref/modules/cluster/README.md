# Wazuh server cluster

For the full per-option reference (all options, defaults and allowed values verified against the parser) see [Cluster Configuration](configuration.md).

> **Note:** The `<cluster>` XML section is **mandatory**: every 5.x manager is a cluster node, even a
> single one. It is validated against the manager configuration schema like every other section of
> `wazuh-manager.conf`: `key` is required and pattern-checked, and `port` must be within
> `1025`–`65534`. See [Cluster Configuration](configuration.md) for details.

## Introduction

The Wazuh server cluster is composed of multiple Wazuh server nodes running in a distributed environment. This deployment strategy provides horizontal scalability and improved performance. In environments with a large number of monitored endpoints, this setup can be combined with a network load balancer to distribute Wazuh agent connections across multiple nodes (see [A Wazuh server cluster behind a load balancer](lb.md)).

The Wazuh server cluster consists of one **master node** and any number of **worker nodes**. A manager installed on its own is a master with no workers.

---

## Architecture

There are two types of nodes in a Wazuh server cluster: **master nodes** and **worker nodes**, selected by `<cluster><node_type>`. These roles define the responsibilities of each node and establish a hierarchy used during synchronization processes.

A Wazuh server cluster can have only one master node. During synchronization, data from the master node always takes precedence over data from worker nodes. This ensures consistency and uniformity across the cluster.

> **Note**
> Configuration changes applied to the file
> `/var/wazuh-manager/etc/wazuh-manager.conf`
> on the master node are **not synchronized** to worker nodes (the file is on the cluster's
> exclusion list). You must replicate these changes manually and restart the nodes for them to
> take effect.

---

## Master node

The master node centralizes coordination and ensures that critical data remains consistent across all nodes in the cluster. Its responsibilities include:

- Creating agent identities: enrollment requests received by a worker are forwarded to the master
- Minting enrollment tokens
- Serving the Server API: `wazuh-manager-control` starts `wazuh-manager-apid` only on the master, so agent deletion, group management and every other API operation go through it
- Accepting the worker connections on the cluster port (`1516` by default)

---

## Worker node

Worker nodes are responsible for:

- Forwarding enrollment requests to the master node
- Pulling the synchronized files from the master node
- Receiving and processing events from Wazuh agents
- Sending agent status information to the master node

If a synchronized file is modified on a worker node, the change is discarded during the next synchronization cycle and replaced with the master node's version.

---

## What is synchronized

The synchronized set is fixed in `framework/wazuh/core/cluster/cluster.json`. Every entry flows from
the master to the workers:

| Path | Files | Mode written on the worker |
|---|---|---|
| `etc/` | `client.keys`, `authd.pass`, `enrollment_tokens.json` | `0640` |
| `etc/shared/` | everything, recursively (group configuration) | `0660` |
| `var/multigroups/` | `merged.mg`, recursively | `0660` |

`wazuh-manager.conf` is excluded, and so are files ending in `~`, `.tmp`, `.lock` or `.swp`. Nothing
else is synchronized: not `etc/certs/`, not the RBAC database, not `var/upgrade/`, not
`queue/tasks/`. What that means for agents reaching the cluster through a load balancer is
described in [What the cluster replicates, and what it does not](lb.md#4-what-the-cluster-replicates-and-what-it-does-not).

---

## How it works

The Wazuh server cluster is managed by the `wazuh-manager-clusterd` daemon, which runs on **every**
node and implements a master–worker architecture. Every connection is opened by a worker to the
address in `<cluster><nodes>`; the master answers and pushes data over those connections. The
cluster traffic is encrypted with `<cluster><key>`.

When a worker connects, the master refuses it if its node name is not made of letters, digits, `_`
and `-` (error `3060`), is already connected (`3028`) or equals the master's own (`3029`), if its
`<cluster><name>` differs (`3030`), or if its Wazuh version differs (`3031`). A worker whose key does
not match cannot decrypt the master's messages (`3025`). A worker that loses the connection retries
every 10 seconds.

Periodic tasks, with their intervals (internal, not configurable):

| Task | Runs on | Interval | What it does |
|---|---|---|---|
| Keep alive | worker | 60 s | Sends a keep-alive to the master. After 2 failed attempts in a row the worker disconnects. |
| Keep alive | master | 60 s | Closes the connection of a worker that has sent no keep-alive for 120 s. |
| Integrity check / Integrity sync | worker | 9 s | Sends the metadata of its synchronized files to the master, which compares it with its own and sends back the files that are missing, different or extra. |
| Local integrity | master | 8 s | Recalculates the metadata (BLAKE2b hash, modification time) of its synchronized files, so the comparison is not repeated for each worker. |
| Agent-info sync | worker | 10 s | Sends the agent information held by its local `wazuh-manager-db` (status, keep-alive, agent metadata) to the master's `wazuh-manager-db`. |
| Local agent-groups | master | 10 s, after a 30 s start delay | Reads the agent-group assignments not yet synchronized from its `wazuh-manager-db` and broadcasts them to every connected worker. |
| Agent-groups recv / recv full | worker | on each broadcast | Applies the assignments and compares its agent-groups checksum with the master's; after 5 mismatches in a row the worker requests the whole table. |

When `<indexer><hosts>` is configured, `wazuh-manager-clusterd` also runs indexer-dependent tasks,
started only while the indexer is reachable: on every node, the
[active-response](../active-response/README.md) fetch task; on the master, the group and cluster-name
synchronization of disconnected agents' indexed documents, and a periodic metrics snapshot. Without
`<indexer><hosts>` it logs `Indexer configuration is unavailable; Indexer tasks will not be started.`

The indexer is checked every 300 s while it is reachable. The scheme of `<indexer><hosts>` decides
TLS: `https://` hosts use `<ssl>`, `http://` hosts ignore it, and a list mixing both is refused. Two
kinds of failure are told apart:

- **A configuration that cannot work** — an `<indexer>` section that does not parse, mixed schemes, a
  `<certificate>` without its `<key>`, a TLS file that cannot be loaded, or a missing indexer
  credential in the keystore — is logged once, as an error: `Indexer tasks cannot start, the indexer
  configuration is not usable: <reason>`. It is logged again only when the reason changes, and is
  checked again every 300 s.
- **An unreachable indexer** is logged as a warning on every check, and checked again with an
  exponential backoff from 300 s, capped at 3600 s.

Either wait ends within 10 s of a change to `wazuh-manager.conf`, so a corrected configuration is
picked up without a restart. A change to the keystore alone is picked up at the next check.

---

## Local socket

Local processes reach the cluster through `/var/wazuh-manager/queue/sockets/cluster-internal.sock`,
which `wazuh-manager-clusterd` binds on every node with mode `0660`. It is used by `cluster_control`
and the Server API (node lists, health, distributed API requests), and by `wazuh-manager-authd` and
`wazuh-manager-remoted` on a worker to forward requests that only the master can execute (agent
enrollment, group assignment). If the socket cannot be reached, the C daemons retry 10 times, one
second apart.

---

## The daemon

`wazuh-manager-control start` starts `wazuh-manager-clusterd` on every node, master or worker. Its
command-line options, for running it by hand:

| Option | Effect |
|---|---|
| `-f` | Run in the foreground |
| `-d` | Enable debug messages; repeat (`-dd`) for more verbosity |
| `-V` | Print the version and exit |
| `-r` | Run as root instead of dropping privileges to `wazuh-manager` |
| `-t` | Read and check the cluster configuration, then exit (`0` when valid, `1` otherwise) |
| `-c <file>` | Configuration file to read (default `/var/wazuh-manager/etc/wazuh-manager.conf`) |

The debug level can also be set with the `wazuh_clusterd.debug` internal option (see
[Internal Options](configuration.md#internal-options)); when it is non-zero it takes precedence over
`-d`.

All cluster logs are written to `/var/wazuh-manager/logs/cluster.log`.

---

## Inspecting the cluster: `cluster_control`

`/var/wazuh-manager/bin/cluster_control` queries the running cluster through the local socket, so
it works on any node (a worker forwards node and health queries to the master).

| Option | Effect |
|---|---|
| `-l`, `--list-nodes` | List the connected nodes: name, type, version and address |
| `-l -fn <node> [<node> …]` | List only the named nodes |
| `-a`, `--list-agents` | List the agents: ID, name, IP, status and version |
| `-a -fs <status> [<status> …]` | List only the agents with the given statuses (`-fs` is accepted only with `-a`) |
| `-i`, `--health` | Show the last completed synchronizations of each connected worker |
| `-i more` | Show the detailed health report: keep-alive, integrity check and sync, agent-info and agent-groups timings |
| `-i -fn <node> [<node> …]` | Health of the named nodes only |
| `-d`, `--debug` | Print debug messages |
| `-u`, `--usage` | Print usage examples |

`-a`, `-l`, `-i` and `-u` are mutually exclusive. For example:

```bash
/var/wazuh-manager/bin/cluster_control -l
/var/wazuh-manager/bin/cluster_control -i more
```
