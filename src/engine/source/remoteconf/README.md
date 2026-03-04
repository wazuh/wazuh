# Remote Runtime Configuration

Fetches runtime settings from the `.wazuh-settings` index in wazuh-indexer and applies them to engine modules without restarting.

## Supported keys

| Key | Type | Path in indexer |
|---|---|---|
| `index_raw_events` | bool | `engine.index_raw_events` |

## Architecture

```
main.cpp
  └── makeIndexerSettingsSource(IWIndexerConnector)  →  IndexerSettingsSource
  └── RemoteConfManager(ISettingsSource, IStore)
        ├── initialize()   — called once at startup
        └── refresh()      — called periodically by IScheduler
```

`RemoteConfManager` depends on `ISettingsSource` and an optional `IStore` cache:

```cpp
auto source  = remoteconf::makeIndexerSettingsSource(indexerConnector);
auto manager = std::make_shared<remoteconf::RemoteConfManager>(source, store);
```

## Indexer document

Index `.wazuh-settings`, document id `1`:

```json
{
  "_source": {
    "engine": {
      "index_raw_events": false
    }
  }
}
```

## Behavior

**`initialize()`** — fetches once at startup. On success, applies settings and persists cache. On remote failure, tries cache; if cache is unavailable/invalid, defaults are applied. Never throws.

**`refresh()`** — fetches the current document and applies per-key diffs only when payload changed. On valid changes, cache is updated. On failure, in-memory state is preserved.

**Per-key sync** — for each key with a registered subscriber, the callback is invoked only if the value changed. If the callback returns `false`, the previous committed value is kept. Keys absent from the remote payload are left unchanged.

## Cache contract

- Store document name: `remote-config/engine-cnf/0`
- Stored payload format: normalized engine variables object (for example: `{ "index_raw_events": false }`)
- Corrupt/non-object cache document: ignored with warning log

## Subscriber registration

```cpp
manager.addTrigger(conf::key::REMOTE_RAW_EVENT_INDEXER,
    [](const json::Json& value) -> bool
    {
        if (!value.isBool()) return false;
        value.getBool().value() ? enable() : disable();
        return true;
    },
    json::Json("false"));
```

Can be called before or after `initialize()`. Type validation is callback-owned.
