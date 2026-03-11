# Remote Runtime Configuration

Manages runtime engine settings fetched from wazuh-indexer and persisted in the local store.

## Supported keys

| Key | Type |
|---|---|
| `index_raw_events` | bool |

## Architecture

```
main.cpp
  └── RemoteConfManager(IWIndexerConnector, IStore)
        ├── constructor    — loads last persisted settings from store
        ├── addTrigger()   — registers a callback and returns persisted/default value
        └── synchronize()  — fetches current settings from wazuh-indexer
```

`RemoteConfManager` depends on `IWIndexerConnector` to fetch remote settings and `IStore` to load and persist the last successfully applied settings:

```cpp
auto manager = std::make_shared<remoteconf::RemoteConfManager>(indexerConnector, store);
```

## Indexer fetch contract

`IWIndexerConnector::getEngineRemoteConfig()` returns a normalized flat JSON object with engine runtime settings:

```json
{
  "index_raw_events": true
}
```

## Behavior

**Construction** — loads the last persisted settings from store document `remote-config/engine-cnf/0`. If the document does not exist, the manager starts with empty runtime state. If the document is invalid, it is ignored and a warning is logged.

**`addTrigger()`** — registers a callback for a setting key. Returns the last persisted value for that key if available, or the provided default value when no persisted value exists. The manager does not apply the returned value; the caller is responsible for applying it at startup.

**`synchronize()`** — fetches the current flat settings object from wazuh-indexer. Ignores keys that have no registered callback. For registered keys, invokes the callback only when the remote value differs from the last applied value. If the callback returns `false`, the current value is kept and nothing is persisted. If the callback throws, the error is logged and the current value is kept. After a successful callback, the new value is persisted to store.

## Store contract

- Store document name: `remote-config/engine-cnf/0`
- Stored payload format: flat object containing only successfully applied settings
- Corrupt or non-object cache document: ignored with warning log

Example stored document:

```json
{
  "index_raw_events": true
}
```

## Subscriber registration

```cpp
const auto initialValue = manager.addTrigger(
    "index_raw_events",
    [](const json::Json& value) -> bool
    {
        if (!value.isBool())
        {
            return false;
        }

        value.getBool().value() ? enable() : disable();
        return true;
    },
    json::Json("false"));

applyInitialConfig(initialValue);
```

`addTrigger()` returns the persisted value if one exists, or the default otherwise. The caller applies it at startup. Type validation is callback-owned.

## Notes

- The manager does not persist rejected or failed updates.
- Unregistered remote keys are silently ignored.
- The store document reflects applied state only, not the raw payload from wazuh-indexer.
