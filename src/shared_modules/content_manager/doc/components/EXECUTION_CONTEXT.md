# Execution Context

## Details

The [execution context](../../src/components/executionContext.hpp) is what a registration is checked
and prepared by, once, before any cycle runs. It does two things and nothing else:

- **Configuration validation**: every rule that can be checked without touching the indexer is
  checked here, so a broken configuration is reported to the host as an exception at registration
  rather than as a `CycleStatus::FailedConfig` on every cycle for the rest of the process's life.
- **Database initialization**: when `configData.databasePath` is present, it opens the updater
  RocksDB and creates the `current_offset` column if it is missing. That column is where
  `RocksDbTokenStore` keeps the change-detection token. Hosts that own their own state — the Engine
  keeps its tokens in `store::IStore` documents — omit `databasePath` and supply an
  `IContentTokenStore` instead, and then no database is opened at all.

It used to also create `downloads/` and `contents/` folders for file-based downloaders. There are
none left: content streams from the indexer straight into the sink, so those folders were pure
overhead and are gone.

## What it rejects

- a missing or empty `consumerName`;
- a `changeDetection` that is not `cursor` or `hash`;
- a missing `indexer` object, or one without a non-empty `index`/`indices`;
- a `consumerStatusIndex` that is not a **concrete** index name — no wildcard, comma list or leading
  `-`. Both defences against consumer documents leaking into the content compare against the
  `_index` metafield, which reports concrete backing index names; a pattern would simply never
  match, and the leak would be silent;
- a `consumerStatusIndex` without a `consumerStatusId`;
- in hash mode: anything other than exactly one of `hashDocId` / `hashIndex`, a `hashIndex` without
  a `hashQuery`, an empty or malformed `hashPointers`, or a missing `dataQuery`;
- a mistyped key in the query shape: `numSlices` (must be a positive integer), `pageSize`,
  `consumerStatusCacheSeconds`, `keepAlive`, `expandWildcards`, `cursorField`, `sortKeys`,
  `sourceFilter` or `requiredDocumentIds`.

  The last two are the reason this group exists at all. Both are read behind an `is_object` /
  `is_array` test, so a mistyped one is not an error at cycle time — it is *silently ignored*. A
  feed downloaded without its `_source` filter still works; it is simply several gigabytes instead
  of a few hundred megabytes, and nothing downstream would ever report it. The rest are read with
  `json::value(key, default)`, which throws a `type_error` naming nothing useful, on a topic that
  had registered cleanly.

## Recovering an unusable database

`RocksDBWrapper` attempts its own repair when it finds a corrupt database, so this only covers the
case where that repair fails too. It matters because the failure mode is otherwise a *host that will
not start*: the open throws, the registration constructor propagates it, and the vulnerability
scanner dies with it. That used to be survivable only by accident — the scanner deleted the whole
updater directory before registering, a reach-in that no longer exists.

Discarding the file is the right answer here in a way it would not be for content: this database
holds one thing, the change-detection token, and losing it costs exactly one full re-download —
which is also precisely what a database that could not be repaired needs. A rebuild that fails as
well is left to throw: registering with no token store at all would silently re-download the whole
feed on every cycle for ever, which is worse than refusing to register.
