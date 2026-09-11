# Keystore

`wazuh-manager-keystore` is a CLI utility that stores encrypted credentials for the Wazuh Manager. Other components (Indexer Connector, Server API) read secrets from the keystore at runtime — C++ consumers via the `Keystore` library directly, and the Python framework through the `keystore_server` module (below).

Source: `src/shared_modules/keystore/`

## Storage

Secrets are stored in a RocksDB database at `queue/keystore/` (relative to the Wazuh install directory, i.e. `/var/wazuh-manager/queue/keystore/`). All values are encrypted with AES-256-CBC before being written to disk.

Secrets are organized into **column families** (namespaces). The main column families used by the manager are:

| Column family | Contents |
|---------------|----------|
| `indexer` | Wazuh Indexer credentials (`username`, `password`) |

## CLI usage

```bash
# Store a value inline
wazuh-manager-keystore -f indexer -k username -v admin

# Store a value from stdin (avoids the value appearing in shell history)
echo 'MySecretPassword' | wazuh-manager-keystore -f indexer -k password

# Store a value from a file
wazuh-manager-keystore -f indexer -k password -vp /path/to/secret.txt
```

| Flag | Description |
|------|-------------|
| `-f <family>` | Column family (namespace) |
| `-k <key>` | Key name |
| `-v <value>` | Value (inline) |
| `-vp <path>` | Value read from file |
| (stdin) | Value read from standard input when `-v` and `-vp` are omitted |

## `keystore_server`

`keystore_server` (source: `src/wazuh_modules/keystore_server/`) is the modulesd-loaded module
that exposes the `Keystore` library above to non-C++ callers. Its one production consumer is the
Python framework: `credential_manager.py` (`framework/wazuh/core/indexer/credential_manager.py`)
fetches the Wazuh Indexer credentials the manager API needs from it.

- **Loading:** modulesd resolves it with `dlopen`/`dlsym`, calling the exported
  `keystore_server_start(callbackLog, socketPath)` and `keystore_server_stop(void)` entry points
  (see `wazuh_modules/src/wm_keystore_server.c` and
  `src/wazuh_modules/keystore_server/include/keystore_server.h`). A failure to bind the socket is
  treated as fatal, since an API that silently lost its indexer credentials is worse than one that
  refuses to start.
- **Transport:** a Unix domain socket at `queue/sockets/keystore.sock` (relative to the install
  directory), served over the same size-prefixed socket protocol used elsewhere in modulesd
  (`SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>`).
- **Protocol:** a simple pipe-delimited text query answered with JSON — `GET|<columnFamily>|<key>`,
  `PUT|<columnFamily>|<key>|<value>`, `DELETE|<columnFamily>|<key>` (a DELETE is implemented as a
  PUT of an empty value). Responses look like
  `{"status": "ok", "operation": "get", "columnFamily": ..., "key": ..., "value": ...}`. This wire
  format is a live contract with `KeystoreClient` on the Python side and is not expected to change.
  One quirk worth knowing: a `GET` for an empty/absent value returns the literal string
  `"wazuh-manager"` rather than an empty value or an error.
- **Relationship to `src/shared_modules/keystore/`:** `keystore_server` itself holds no storage or
  crypto logic — every request is translated directly into a call to `Keystore::get()` or
  `Keystore::put()` from the shared library documented above, which does the RocksDB persistence
  and AES-256 encryption/decryption. `keystore_server` is purely the IPC front door that lets
  Python reach that library without a C++ binding.

## Encryption version

The current keystore format is v2 (AES-256-CBC via EVP). Every `put()`/`get()` call stamps a
`version` field in the target column family so future format changes can key off it — but there
is no automatic migration of older data. Pre-5.0 keystores are not carried forward: in-place 4.x →
5.x manager upgrades are not supported, so no legacy keystore ever reaches this code path, and no
migration logic exists (see the `upgrade()` comment in `src/keyStore.cpp`).

## Key source files

| File | Purpose |
|------|---------|
| `include/keyStore.hpp` | Public API: `Keystore::put()`, `Keystore::get()` |
| `src/keyStore.cpp` | AES-256 encrypt/decrypt, RocksDB persistence, version stamping |
| `src/main.cpp` | CLI argument handling, stdin/file input |
| `src/argsParser.hpp` | Command-line parser (`-f`, `-k`, `-v`, `-vp`) |
