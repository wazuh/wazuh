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
under. The image configuration digest names the image in the shared container block (`image_id`), but the
row key stays the reference.

### `dbsync_container_image_references`

Primary key `(reference_type, reference_value)`. Columns: the key, `image_id`,
`manifest_digest`, `image_hash_all`, `image_name`, `image_tag`, `platform_os`, `platform_architecture`,
`platform_variant`, `platform_os_version`, `os_name`, `os_version`, `os_id`, `os_family`,
`os_codename`, `os_pretty_name`, plus `checksum`, `version`, `sync`.

`manifest_digest` is metadata only. A reference resolved through an index holds the digest of the selected index entry. A reference that named a manifest directly holds the digest the registry reported for it in `Docker-Content-Digest`, else the digest the reference is pinned to, else the sha256 of the manifest as served.

`image_hash_all` is every digest the image is known by, serialized as a JSON array and ordered from the outside in: the indexes the image was reached through (outermost first), then the manifest, then the configuration. A tag that resolves to a multi-platform index holds three or more, and an image reached through a manifest holds two. A saved image in the `docker save` layout names only its configuration file, so it holds one. They are metadata only, like `manifest_digest`, and the reference stays the primary key. The unchanged-image check compares `image_id` and nothing else, and no layer is read for an unchanged image. A registry reference that takes that short cut still reports the digests it resolved this scan, and the stored `image_hash_all` list is rewritten only when it differs, so a tag whose index moved while the platform configuration did not is kept current at the cost of one row update. The name and tags are refreshed the same way, in the same update: an archive saved again under other tags, or a registry reference, reports the names it has now, so a retagged image keeps its stored `image_name` and `image_tag` current without its layers being read.

`platform_*` columns describe the image configuration: the `os` and `architecture` it was built for. The `os_*` columns describe the distribution the image is built on, read from its `os-release` file: `etc/os-release`, else `usr/lib/os-release`, taken from the composed layers so a file a later layer deletes is not read. `os_name` is `NAME`, `os_version` is `VERSION_ID`, `os_id` is `ID`, `os_family` is the first word of `ID_LIKE`, `os_codename` is `VERSION_CODENAME` and `os_pretty_name` is `PRETTY_NAME`. An image with no `os-release` (a scratch or static distroless image) is not an error: its `os_*` columns are empty, and the scan logs once at info level that the image has no operating system.

### Image identity columns

Four columns carry the fields of the shared container block, named after `container.image.*` with the dots
written as underscores, so the image side and the runtime side describe an image alike:

| Column | Shared field | Holds |
|--------|--------------|-------|
| `image_id` | `container.image.id` | The configuration digest. It is what a Docker engine reports as the image id of a running container. |
| `image_hash_all` | `container.image.hash.all` | Every digest the image is known by (see above). A running container joins an image when the digest its engine reports is the `image_id` or any entry of this list: Docker reports the configuration digest, Kubernetes the digest of the repository entry (index or manifest) the image was pulled by, when the pod reports one. |
| `image_name` | `container.image.name` | The full normalised name, `registry/repository` with neither tag nor digest. Docker Hub is made explicit, so `nginx` and `library/nginx:1` are both `docker.io/library/nginx`. Empty when the source gives the image no name. |
| `image_tag` | `container.image.tag` | The tags of that name, serialized as a JSON array (`["1.4","latest"]`). |

Where the name comes from depends on the source:

- A remote reference: the registry and repository of the configured `<ref>`, and its tag when it carries one (`latest` when it names neither tag nor digest). A reference pinned only by digest has no tag.
- A saved image in the `docker save` layout: the `RepoTags` it lists, normalised. The first one fixes the name and every tag of that name is listed once. A name on another repository than the first is not reported, and an entry that is not a reference (`<none>:<none>`) is skipped; both are logged at debug with the reason. Only the first 64 names of an image are read, and one debug line says when the rest is dropped.
- An OCI image layout: the `io.containerd.image.name` annotation, normalised, and the `org.opencontainers.image.ref.name` annotation, which is read as a whole reference when it holds a `:`, `/` or `@` and as a tag otherwise. A layout that carries only a bare tag has a tag and no name: a repository is never guessed from a tag.

The reference stays the key, so two references of one repository (`app:1.0`, `app:2.0`) are two rows that share an `image_name`.

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

### 6b. Local engine images

A `<local>` reference stands for every image a container engine holds, so it owns many rows. Each
image is one row of the references table, keyed `(reference_type, reference_value)` =
(`local`, `<engine>/<image id>`), for example `local` and `docker/sha256:3f...`, written
`local:docker/<image id>` in logs and documents.

- **Why the image id.** It is the engine's identity for an image and is stable: a retag keeps the
  row and rewrites `image_name`, `image_tag` and `image_hash_all`; a rebuilt image has a new id and
  is a new row; an image the engine no longer lists is not in the scan's set, so the whole-table sync
  reports it as deleted like any reference that goes away. The configured value (`docker`) is not
  stored, since it names the engine and not an image.
- **Why not the name.** An image can carry several names or none (a dangling image still describes a
  running container), and a name moves between images, which would replace a row's packages.
- **Change detection.** For Docker the id is the configuration digest, so an image whose id is the stored
  `image_id` is not exported again. An engine that identifies images by their manifest is recognised
  through the id kept in `image_hash_all`, so the row is not exported again either.
- **Names and digests come from the engine's listing**, not from the export, which carries no names
  when an image is saved by id. `image_hash_all` is the digests the engine pins the name to
  (`RepoDigests`), then `image_id`, then the engine id when it is neither.
- **An unreachable engine** carries every stored row of that engine into the scan, like any reference
  that could not be read. An image that cannot be exported keeps its stored row, and has none when
  nothing was stored.

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

### 8. State index

Nothing synchronizes yet. The name below is proposed, pending agreement with the runtime team, and is recorded so the
synchronization layer and the manager can settle on it (`IMAGE_PACKAGES_INDEX` in `container_images_db.hpp`):

| Table | Index |
|---

## Component layout

| File | Role |
|------|------|
| `container_images_impl/include/image_inventory_types.hpp` | Adds `ImagePackageRecord`; references carry their packages. |
| `container_images_impl/{include,src}/archive_image_reader.*` | Reads the configured inputs on disk and returns references with their packages. |
| `container_images_impl/{include,src}/layer_reader.*`, `layer_composer.*`, `byte_stream.*` | Stream a layer, compose the layers of an image, and keep only its package databases. |
| `data_provider/src/packages/packageDbParser.hpp` | The package database formats, shared with container runtime security. The composer in `layer_composer.cpp` also lists the formats that are recognized but not implemented yet. |
| `container_images_impl/{include,src}/engine_image_reader.*`, `engine_image_source.hpp`, `docker_image_source.*` | Read the images of a container engine (`<local>`): the interface, the Docker Engine API client and the reader that keys one row per image. |
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
- Manager synchronization: the indexer templates for the indices above, ECS field mapping for the event
  payload, and whether a document limit / promotion is needed. The `sync` column already
  exists so a limit can be layered on without a migration.
