# Package inventory persistence

This document describes how the Container Images module stores the package inventory it
discovers, and the technical decisions behind the storage model.

> **Status:** image references and their packages are read from the configured inputs on disk
> and stored. RPM extraction is a later stage, so an RPM-based image is stored with zero
> packages today; adding it fills the same rows without changing this layer.

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
- **Change detection**: DBSync compares every non-ignored column and reports a row as
  MODIFIED when any of them differs. The per-row `checksum` (sha1 of the row content) is
  stored like every other inventory table keeps one, but it holds no special status in that
  comparison, so leaving a field out of the checksum does not hide it from change detection.
  A change to a primary-key
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

### 4. Reads that did not happen

The inventory is stored as one set covering every configured reference, so a reference left
out of that set is reported as deleted. A reference that could not be read is therefore not
left out: what an earlier scan stored for it is carried into this scan unchanged, and a
warning names it. An empty read is different and is stored as the emptiness it reports,
because a reference that was read and holds nothing really is empty. A scan cut short by a
stop is abandoned rather than stored, for the same reason.

An image still reporting the configuration digest already stored is not read again either,
and its stored inventory is kept: its contents cannot have changed.

### 5. Cleanup

`ContainerImagesDB::dropTables()` removes every row from both tables while keeping the schema
and its recorded version, so the inventory this module owns does not survive as stale state
when the module is disabled or uninstalled, and a later re-enable reuses the same database
instead of triggering a recreate.

### 6. Inventory source

The reader factory (`makeReader`) returns an `ArchiveImageReader` bound to each configured
`<archive>` reference, so everything stored comes from the images the user configured: the
references from the image metadata, the packages from the package databases their layers
carry. The module holds no synthetic reader, so an agent cannot persist inventory it did not
find.

The three delta types are exercised by the unit tests over images built on disk, whose layers
change between scans.

### 7. Image identity on the package row

A package row carries `reference_type` and `reference_value`, which identify the source type
and the path it was found under. It deliberately does **not** repeat the image digest, name,
tags or platform: those live once on the reference row, and duplicating them onto every
package is what the storage analysis behind this model set out to avoid.

The consequence for the stage that follows: the synchronization layer must **join the
reference row** to build a package document, because a raw package row alone does not carry
the digest, the image name or the OS that Vulnerability Detector needs to select a feed.
Issue #37529's scope asks for that metadata in the package state; this model answers it by
reference rather than by duplication, and the choice needs confirming on the objective before
the sync layer is built.

---

## Component layout

| File | Role |
|------|------|
| `container_images_impl/include/image_inventory_types.hpp` | Adds `ImagePackageRecord`; references carry their packages. |
| `container_images_impl/{include,src}/archive_image_reader.*` | Reads the configured inputs on disk and returns references with their packages. |
| `container_images_impl/{include,src}/layer_reader.*`, `layer_composer.*`, `byte_stream.*` | Stream a layer, compose the layers of an image, and keep only its package databases. |
| `container_images_impl/{include,src}/package_db_parser.*` | The package database formats: parsed, and recognized but not implemented yet. |
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

- Add RPM package extraction, which needs the header parsing that lives in shared agent code. Until it lands, an RPM-based image is stored with zero packages.
- Manager synchronization: index names and indexer templates, ECS field mapping for the event
  payload, and whether a document limit / promotion is needed. The `sync` column already
  exists so a limit can be layered on without a migration.
