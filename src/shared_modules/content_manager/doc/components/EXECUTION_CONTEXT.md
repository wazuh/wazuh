# Execution Context

## Details

The [execution context](../../src/components/executionContext.hpp) opens whatever storage a
registration asks for, once, before any cycle runs: when `state.databasePath` is set, the updater
RocksDB, with the `current_offset` column created if it is missing. That column is where
`RocksDbTokenStore` keeps the change-detection token. Hosts that own their own state — the Engine
keeps its tokens in `store::IStore` documents — leave `databasePath` unset and supply an
`IContentTokenStore` instead, and then no database is opened at all.

It used to validate the registration too. That moved to
[`TopicSpecParser`](../../src/components/topicSpecParser.hpp) with D2 of the
[library README](../../README.md#d2-in-detail): the parameters are parsed once into a typed
`content_manager::TopicSpec`, every block rejects keys it does not know (naming key and block), and
every later stage reads the typed model. A broken registration is still reported to the host as an
exception at construction, never as a `CycleStatus::FailedConfig` on every cycle.

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
