# Database Sync

The `database` module of `wazuh-manager-modulesd` keeps the agent and group tables of `global.db`
(owned by [`wazuh-manager-db`](../wazuh_db/README.md)) in step with two files on disk: the agent
registry `/etc/wazuh-manager/client.keys` and the group directories under `/etc/wazuh-manager/shared/`. It is a client of
`wazuh-manager-db`, not part of it.

**Daemon:** `wazuh-manager-modulesd` (log tag `wazuh-manager-modulesd:database`)

**Component:** Manager-only — an agent's `wazuh-modulesd` never registers it (`wm_config()` in
`src/wazuh_modules/src/wmodules.c` adds it in the manager build only).

**Source:** `src/wazuh_modules/src/wm_database.c`

## What it does

**At start, on every node (master and worker):**

- **Agent reconciliation.** Every agent in `client.keys` (other than `000`) missing from `global.db` is
  inserted with its name, registration IP (as `client.keys` spells it, `any` included) and key, and no
  re-enrollment secret, so such an agent cannot re-enroll with a secret until it enrolls again. Its
  registration date (`date_add`) is the one `queue/agents-timestamp` records for it; when that file has
  no line for the agent — as on a worker, which forwards enrollments to the master — it is the time the
  row is inserted. Every agent in `global.db` with no line in
  `client.keys` is deleted, together with its message-counter file `queue/rids/<id>` and its line in
  `queue/agents-timestamp`.
- **Group reconciliation.** Every group in `global.db` whose directory under `/etc/wazuh-manager/shared/` no longer
  exists is deleted, and every directory under `/etc/wazuh-manager/shared/` not yet in `global.db` is inserted as a
  group.

**While running:**

- **Groups** are kept in step on every node: a directory created, moved or removed under `/etc/wazuh-manager/shared/`
  inserts or deletes that group.
- **Agents** are re-reconciled after `client.keys` changes **only on worker nodes**, where the file
  arrives from the master through the cluster. On the master, `wazuh-manager-authd` writes agent
  additions and removals to `global.db` itself, and this module does not touch agents again after
  start.

How changes are noticed depends on `wazuh_database.real_time`: in real-time mode (the default) through
inotify watches on `/etc/wazuh-manager` (for `client.keys`) and `/etc/wazuh-manager/shared/`, whose events go through an internal
queue of pending paths; in interval mode by checking `client.keys` for a new modification time or inode
and rescanning `/etc/wazuh-manager/shared/` every `wazuh_database.interval` seconds.

The module does **not** write agent connection status, keepalives or the group assignments of
individual agents; other components write those.

## Configuration

The module is configured only through internal options (`wazuh_database.*`); there is no XML section.
See [Configuration](configuration.md).

## See Also

- [Configuration](configuration.md) - Internal options reference
- [Wazuh DB](../wazuh_db/README.md) - The database daemon this module writes to
