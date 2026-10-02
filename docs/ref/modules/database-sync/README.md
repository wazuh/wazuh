# Database Sync

The `database` module of `wazuh-manager-modulesd` keeps the agent and group tables of `global.db`
(owned by [`wazuh-manager-db`](../wazuh_db/README.md)) in step with two files on disk: the agent
registry `etc/client.keys` and the group directories under `etc/shared/`. It is a client of
`wazuh-manager-db`, not part of it.

**Daemon:** `wazuh-manager-modulesd` (log tag `wazuh-manager-modulesd:database`)

**Component:** Manager-only — the module is compiled out of the agent build.

**Source:** `src/wazuh_modules/src/wm_database.c`

## What it does

**At start, on every node (master and worker):**

- **Agent reconciliation.** Every agent in `client.keys` (other than `000`) missing from `global.db` is
  inserted with its name, registration IP and key, and no re-enrollment secret, so such an agent cannot
  re-enroll with a secret until it enrolls again. Every agent in `global.db` with no line in
  `client.keys` is deleted, together with its message-counter file `queue/rids/<id>` and its line in
  `queue/agents-timestamp`.
- **Group reconciliation.** Every group in `global.db` whose directory under `etc/shared/` no longer
  exists is deleted, and every directory under `etc/shared/` not yet in `global.db` is inserted as a
  group.

**While running:**

- **Groups** are kept in step on every node: a directory created, moved or removed under `etc/shared/`
  inserts or deletes that group.
- **Agents** are re-reconciled after `client.keys` changes **only on worker nodes**, where the file
  arrives from the master through the cluster. On the master, `wazuh-manager-authd` writes agent
  additions and removals to `global.db` itself, and this module does not touch agents again after
  start.

How changes are noticed depends on `wazuh_database.real_time`: in real-time mode (the default) through
inotify watches on `etc/` (for `client.keys`) and `etc/shared/`, whose events go through an internal
queue of pending paths; in interval mode by checking `client.keys` for a new modification time or inode
and rescanning `etc/shared/` every `wazuh_database.interval` seconds.

The module does **not** write agent connection status, keepalives or the group assignments of
individual agents; other components write those.

## Configuration

The module is configured only through internal options (`wazuh_database.*`); there is no XML section.
See [Configuration](configuration.md).

## See Also

- [Configuration](configuration.md) - Internal options reference
- [Wazuh DB](../wazuh_db/README.md) - The database daemon this module writes to
