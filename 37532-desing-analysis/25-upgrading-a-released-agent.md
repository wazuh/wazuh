# 25 — Upgrading a released 5.0.0 agent to the container schema

Every container document so far assumes a database that already has `container_id`. None of them
asks where that column comes from on an agent that is **already installed**. This one does.

The short version: **a released 5.0.0 agent cannot reach the 5.1.0 schema by `ALTER TABLE`**, and
the branch as it stands today fails on that path outright and silently. The reason is not
incidental — `container_id` is part of every primary key, and SQLite cannot change a primary key
in place.

Everything below marked **verified** was reproduced against a database built from
`origin/5.0.0`'s own DDL, or against the live agent databases on the `wazuh_manager` VM, on
2026-10-16. Everything else is read out of the code and labelled as such.

---

## 25.1 What a released 5.0.0 agent actually holds

Taken from `origin/5.0.0`, not assumed:

```sql
CREATE TABLE dbsync_groups (
    group_id BIGINT,
    group_name TEXT,
    ...
    PRIMARY KEY (group_name)) WITHOUT ROWID;
```

No `container_id`. No `container_json`. A **single-column** primary key. The same holds for
`file_entry`, which is `PRIMARY KEY(path)`.

| | 5.0.0 | 5.1.0 (this branch) |
| --- | --- | --- |
| `dbsync_groups` | `PRIMARY KEY (group_name)` | `PRIMARY KEY (container_id, group_name)` |
| `dbsync_processes` | `PRIMARY KEY (pid)` | `PRIMARY KEY (container_id, pid)` |
| `file_entry` | `PRIMARY KEY (path)` | `PRIMARY KEY (container_id, path)` |
| `container_context` | — | new table |
| `user_version` | **1** | 15 (syscollector) / 3 (FIM) |

The `user_version` of 1 is not a guess: 5.0.0 constructs `DBSync` with the five-argument
constructor (`syscollectorImp.cpp:567` on that branch), so `currentDbsyncVersion` is
`upgradeStatements.size() + 1` = 1, and every database it creates is stamped 1.

> **The migration mechanism itself had never run.** Neither consumer passed `upgradeStatements`
> until this branch wired it up. `SQLiteDBEngine::initialize` only executes the create statement
> for a database being built from nothing, so until now an upgraded agent silently kept whatever
> schema it already had. That is the hole this document is standing in.

---

## 25.2 Two defects on the upgrade path

### Defect 1 — the `DROP COLUMN` statements throw (introduced by the normalisation work)

Removing the `container_json` column added thirteen `ALTER TABLE … DROP COLUMN` statements to the
syscollector upgrade vector, and one to FIM's. Replaying them against a real 5.0.0 database:

```
-- upgrade 0: CREATE TABLE IF NOT EXISTS container_context    OK
-- upgrade 1: ALTER TABLE dbsync_groups DROP COLUMN container_json
Error: in prepare, no such column: "container_json"
```

**Verified.** The column never existed in 5.0.0, so the statement cannot succeed. Those thirteen
statements only ever made sense for *intermediate development* databases, which are the one
population that does not matter.

The consequence is worse than a crash. `dbengine_error` propagates out of `Syscollector::init()`
and is caught and logged at
[syscollector.cpp:108-112](../src/wazuh_modules/syscollector/src/syscollector.cpp#L108-L112) with
an explicit *"DO NOT re-throw"*. The module is left in a failed state and every later call is a
no-op: **inventory stops permanently on every upgraded agent, announced by a single log line.**

### Defect 2 — `container_id` is a primary-key member (pre-existing)

This one predates the normalisation work and is the deferred item
[09 §item 17](09-implementation-status.md) flagged for a separate issue.

Even with the drops removed, an upgraded 5.0.0 table still has no `container_id`, while 5.1.0
treats it as the leading primary-key column. `buildInsertDataSqlQuery` generates inserts from
`PRAGMA table_info`, so an unmatched JSON key is **silently dropped** — the container scope never
reaches the row. What follows is a collision:

```
INSERT INTO dbsync_groups (group_name, checksum) VALUES ('root','container-sum');
Error: UNIQUE constraint failed: dbsync_groups.group_name
```

**Verified.** The host has a `root` group; so does nearly every container.

Through DBSync the failure mode is quieter and worse than that error. `getPrimaryKeysFromTable`
reads the PK flags from `PRAGMA table_info`, and `getRowDiff` locates the existing row by exactly
those columns, so on a table keyed `(group_name)`:

1. A container reports its `root` group → the diff matches the **host's** row → `MODIFIED`, and
   the host's values are overwritten.
2. The next host scan reports its own `root` → matches the same row, now holding the container's
   data → `MODIFIED` again, overwritten back.

The row flip-flops between owners on every scan, emitting a spurious `MODIFIED` each time. Two
containers make it a three-way contest over one row. *(Read from the code, not reproduced
end-to-end — the collision above is the reproduced half.)*

---

## 25.3 Why `container_id` is in the primary key

Because the same natural key exists in the host and in every container: a `root` group, a PID 1,
an `/etc/passwd`, a `bash` package. The primary key is the only thing making them distinct rows.

It is worth being precise about what does **not** require it, because the scoping machinery is
the part people assume is responsible:

`SQLiteDBEngine::validatedScopeColumn`
([sqlite_dbengine.cpp:2221-2246](../src/shared_modules/dbsync/src/sqlite/sqlite_dbengine.cpp#L2221-L2246))
only checks that the scope column **exists** in the table. It then emits `WHERE container_id=?`
into the status-field, delete-detection and `getDeletedRows` statements. Scoped transactions and
per-container sweeps would work perfectly well with `container_id` as an ordinary column.

So the primary key is carrying **row identity**, and nothing else. That is also why it is
cost-free at the integrity layer: `getRowChecksum()` erases `container_id` before digesting,
precisely so that adding the column to a pre-container agent does not change a single host row's
checksum.

---

## 25.4 Could `container_id` be an ordinary value instead?

Only if something else supplies uniqueness. These are `WITHOUT ROWID` tables, so a primary key is
mandatory, and today that key *is* the natural key. Adding a `UNIQUE(container_id, group_name)`
index alongside does not help — the existing single-column key still forbids the second `root`.

Two variants exist. Both are already recorded in
[17 §17.5 row 1a](17-issue-question-coverage.md), whose decision box is still **unticked**
(`☐ keep ☐ change`), so revisiting this is a review the document invites rather than a
re-litigation.

**A surrogate row id**, with `container_id` and the natural key both as attributes. Doc 17's
recorded objection: *"flexible, and it gives up the natural uniqueness the current key has for
free."* It also does not buy what it appears to buy — replacing `PRIMARY KEY (group_name)` with a
surrogate is still a primary-key change, so it still requires a table rebuild.

**A synthetic URI** (`container://<id>/<path>`) as a single key. Doc 17: *"no schema change at
all, and it forks every path query, every prefix match and every existing FIM tool."* This is the
only option that genuinely removes the migration, because the key stays `(path)`. It generalises
badly, though: FIM has one natural key to encode, while the thirteen inventory tables have
composite ones, giving keys like `container://c1/eth0/ipv4/1.1.1.1` and breaking every column
that is currently queryable on its own.

| | Key (current) | Surrogate PK | Synthetic URI |
| --- | --- | --- | --- |
| Host + container rows coexist | yes | yes, via index | yes |
| Natural uniqueness | free, from the schema | maintained by hand | encoded in a string |
| 5.0.0 migration | rebuild | **rebuild anyway** | **none** |
| Rows clustered per container | yes | no | no |
| Scoped delete detection | works | works | prefix matching |
| Existing path/column queries | unaffected | unaffected | **forked** |

The clustering row is load-bearing for [24](24-container-context-measured.md): the per-container
context memo hits ~100% *because* `container_id` leads the clustering key of a `WITHOUT ROWID`
table. Under a surrogate key a container's rows scatter and the memo degrades toward one lookup
per row.

---

## 25.5 Can `wazuh_db`'s upgrade mechanism be reused?

**No**, for three independent reasons:

1. **It is not built into the agent.** `src/wazuh_db` sits inside `if(NOT IS_AGENT)` at
   [CMakeLists.txt:276-287](../src/CMakeLists.txt#L276-L287). Reusing it would mean shipping the
   wazuh-db daemon to every agent.
2. **It targets a different database.** The only function left in `wdb_upgrade.c` is
   `wdb_upgrade_global()`, which migrates `global.db` through wazuh-db's `wdb_t` handle and
   `schemas/schema_global_upgrade_vN.sql` files. Its `UPDATES[]` array is currently just a
   sentinel.
3. **It would be a second writer.** `local.db` and `fim.db` are owned by DBSync, which keeps a
   write transaction permanently open on its own connection.

The agent already has the right mechanism: DBSync's `upgradeStatements`, now wired up.

**But `wdb_upgrade.c` is worth reading for three things DBSync lacks**, and this is the part of
the comparison that has value:

| `wdb_upgrade_global()` does | `SQLiteDBEngine::initialize` does |
| --- | --- |
| `wdb_global_create_backup(…, "-pre_upgrade")`, restores on failure | nothing — a failed upgrade leaves a half-migrated database |
| Rejects `version > latest_version` and disables the database | no upper bound; a downgraded agent silently uses a newer schema |
| `wdb->enabled = false` with a specific error naming the database | a generic throw, swallowed by the caller |

Given that a failed migration here means permanent silent inventory loss, the backup/restore
pattern is not a nicety.

---

## 25.6 The options

| Option | Statements | Host rows | Re-sync on upgrade | Risk |
| --- | --- | --- | --- | --- |
| **Rebuild in place** | 53 syscollector + 7 FIM | preserved | **none** | copy step touches every row |
| Drop and recreate empty | 27 syscollector + 5 FIM | **discarded** | full, every agent | low, but loud |
| Separate container tables | ~13 creates | untouched | none | reverses the shared-table design |
| Synthetic URI | 0 | untouched | none | forks every path query |

**Rebuild in place** means, per table: create the new shape under a temporary name, copy rows with
`container_id = ''`, drop the original, rename. One statement per vector element, because the
upgrade loop prepares and steps exactly once — a multi-statement string silently runs only its
first statement.

Verified end to end on a 5.0.0 database:

```
=== before: 2 rows, checksums adm-sum,host-sum
=== after:  2 rows, checksums adm-sum,host-sum
=== container row no longer collides ===
/adm/adm-sum
/root/host-sum
c1/root/ctr-sum
integrity_check: ok
```

Checksum preservation is the point, and it is not luck: `getRowChecksum()` already erases
`container_id`, so a host row digests identically before and after. **No upgraded agent re-syncs
its inventory**, which is the cost the whole container-context design exists to avoid paying.

The FIM rebuild additionally has to recreate `path_index` and `inode_index`, which are dropped
with the original table. (An `ALTER TABLE … DROP COLUMN` preserves indexes — a manual rebuild does
not.)

---

## 25.7 Recommendation

1. **Remove the fourteen `DROP COLUMN` statements.** They break the only upgrade path that
   matters and serve only development databases. Required regardless of everything below.
2. **Migrate by rebuild**, preserving rows. It is the only option that keeps existing host
   inventory *and* avoids a fleet-wide re-sync, and the primary-key change is unavoidable under
   any design that keeps natural uniqueness.
3. **Treat the migration vector as frozen history.** One statement per element, append-only,
   written out literally rather than generated from a table list — a list someone later extends
   would silently rewrite a migration that has already run on real agents.
4. **Consider porting the backup/restore pattern** from `wdb_upgrade.c` into the DBSync upgrade
   loop. This changes shared code used by every consumer, so it is a separate decision; the
   failure mode it guards against is permanent silent data loss.

### What is not being proposed

Reopening `container_id`'s place in the primary key. It is there for row identity, the
alternatives are recorded and rejected in doc 17, and the one that would actually remove the
migration (the synthetic URI) forks every path query and does not generalise to the inventory
tables. The migration cost is real, and it is buying something.

---

## 25.8 Open questions for the team

- **Is a full re-sync actually unacceptable?** "Drop and recreate empty" is half the frozen
  history and far less code. It is rejected above on the strength of the no-re-sync guarantee —
  if that guarantee is worth less than it looks at fleet scale, the simpler option wins.
- **What is the oldest supported upgrade source?** This document assumes 5.0.0. If 4.x agents can
  reach 5.1.0 directly, their schema needs the same treatment and the vector grows.
- **Should the upgrade failure be fatal rather than silent?** Today the module logs and becomes a
  no-op. An agent whose inventory has permanently stopped arguably ought to be noisier than one
  log line.
- **Does FIM need the same backup treatment as syscollector**, or is a re-baseline acceptable
  there given the files are re-readable from disk?
