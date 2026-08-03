# Package inventory persistence

This document describes how the Container Images module stores the package inventory it
discovers, and the technical decisions behind the storage model.

> **Status:** package **extraction** is still stubbed. A temporary in-memory reader feeds a
> fixed inventory so the storage layer can be built and validated end to end. Real OCI /
> local-image reading replaces the stub later without changing the storage layer.

Synchronizing this inventory with the manager is a separate concern and is not part of this
layer. The delta callback described below is the seam it attaches to.

---

## What this layer provides

1. A local **SQLite database** (via the shared **DBSync** library) holding the container
   image inventory in two tables.
2. Change detection: each scan diffs against the stored state and produces
   create / modify / delete deltas.
3. Schema versioning and a cleanup entry point.

The flow is `scan -> DBSync transaction -> delta callback`, the same spine SCA, Syscollector
and FIM use up to the point where they hand deltas to the sync protocol.

---

## Data model

Reference-based, two tables. Packages belong to the image **reference** they were found
under; the image content digest is metadata, not identity.

### `dbsync_container_image_references`

Primary key `(reference_type, reference_value)`. Columns: the key, `image_config_digest`,
`manifest_digest`, `image_name`, `tag`, `tags`, `platform_os`, `platform_architecture`,
`platform_variant`, `platform_os_version`, plus `checksum`, `version`, `sync`.

`tag` is the display name. `tags` holds every tag the image answers to, serialized as a JSON
array, for sources that report more than one.

### `dbsync_container_image_packages`

Primary key `(reference_type, reference_value, name, version_, architecture, type)`.
Columns: the key, `vendor`, `installed`, `path`, `category`, `description`, `size`,
`priority`, `multiarch`, `source`, `package_db_path`, plus `checksum`, `version`, `sync`.

The columns mirror the host package inventory (`dbsync_packages`) so the same indexer mapping
can be reused, with two differences:

- The owning reference replaces `path` in the primary key. Image inventories have no host
  install path, so `path` is an attribute here, populated only when the package database
  records one.
- `package_db_path` is added: the package database file inside the image the record came from.

Both tables are `WITHOUT ROWID` and carry the `checksum` / `version` / `sync` columns used by
every other inventory table.

---

## Key technical decisions

### 1. Whole-table package sync (delete scoping)

DBSync transaction deletion is table-scoped: a row absent from the synced set is reported as
deleted. Packages from **all** references are therefore synced in a **single** transaction,
so a package that disappears from one reference is correctly detected while packages of other
references are left untouched. Syncing per reference would wrongly delete every other
reference's packages.

### 2. Document id and change detection

- **Document id**: `sha1(table + primary-key fields)`. For packages the reference fields are
  always part of the key, since the reference owns the inventory.
- **Change detection**: a per-row `checksum` (sha1 of the row content) is stored; DBSync
  reports a row as MODIFIED when the incoming checksum differs. A change to a primary-key
  field (e.g. a package `version_`) is a different identity, so it surfaces as a delete of the
  old row plus a create of the new one, not a modify. This matches the host package inventory
  behavior.

### 3. Schema versioning

DBSync records the schema version in `PRAGMA user_version` and treats the current version as
`upgradeStatements.size() + 1`. `ContainerImagesDB` passes an explicit upgrade list, empty
while the schema is on its first revision.

Rule for any future schema change: **append** the migrating statement to that list, never
edit or reorder existing entries. An agent whose database is behind replays only the pending
entries; rewriting an earlier one makes it skip a step. A database with no recorded version
is recreated from the CREATE TABLE statements.

### 4. Cleanup

`ContainerImagesDB::dropTables()` removes every row from both tables while keeping the schema
and its recorded version, so the inventory this module owns does not survive as stale state
when the module is disabled or uninstalled, and a later re-enable reuses the same database
instead of triggering a recreate.

### 5. Stub inventory source (extraction deferred)

The reader factory (`makeReader`) returns a `StubImageReader` that emits one reference
(`debian:12`) with a handful of packages. The fixture **mutates across scans** (a package is
added, one changes version, one is removed) so that create / modify / delete deltas are
produced and can be observed. This is the seam the real readers replace; nothing downstream
depends on it. A deterministic mutating fixture validates all three delta types without
needing real image parsing.

---

## Component layout

| File | Role |
|------|------|
| `container_images_impl/include/image_inventory_types.hpp` | Adds `ImagePackageRecord`; references carry their packages. |
| `container_images_impl/{include,src}/stub_image_reader.*` | Temporary mutating inventory source. |
| `container_images_impl/{include,src}/container_images_db.*` | Owns DBSync, holds the CREATE TABLE statements and the upgrade list, runs the transactions, emits deltas. |
| `container_images_impl/{include,src}/container_images_impl.*` | Orchestrator: scan -> DB -> delta callback. |
| `container_images/{include,src}/container_images.{h,hpp,cpp}` | C ABI + facade; initializes DBSync. |

## Database location (agent)

- Inventory: `queue/container_images/db/container_images.db`

## Build wiring

`container_images_impl` and the `container_images` shared library link `dbsync`, and add the
OpenSSL include path used by the hash helper.

## Implementation note: consuming the DBSync callback row

The JSON object delivered in the DBSync transaction callback must be consumed **directly**
(`data.contains("new") ? data["new"] : data`, then field access). It must not be serialized
and re-parsed, because `libdbsync.so` exports its own `nlohmann::json` template symbols that
interpose the module's, and a `dump()` + `parse()` round-trip can misreport the value's type.
Field-level access on the callback object is reliable; this mirrors how Syscollector consumes
its own callback.

## Open items

- Replace the stub reader with real package extraction (dpkg / apk / rpm).
- Manager synchronization: index names and indexer templates, ECS field mapping for the event
  payload, and whether a document limit / promotion is needed. The `sync` column already
  exists so a limit can be layered on without a migration.
