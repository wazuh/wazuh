# Keystore

The keystore holds the secrets the manager must not keep in `wazuh-manager.conf` — today, the
credentials the manager uses to authenticate to the Wazuh Indexer. It has three parts:

- the `Keystore` library (`src/shared_modules/keystore/`), which C++ components link directly — the
  [Indexer Connector](../indexer_connector/README.md) reads its credentials through it;
- the `wazuh-manager-keystore` command-line tool, which writes and reads entries;
- the `keystore_server` module of `wazuh-manager-modulesd`, which serves the library to the Python
  framework over a Unix socket.

## Storage

Secrets are stored in a RocksDB database at `/var/wazuh-manager/queue/keystore/` (directory
`wazuh-manager:wazuh-manager` 0750, files 0640). Secrets are organized into **column families**
(namespaces):

| Column family | Keys |
|---------------|------|
| `indexer` | `username`, `password` — the manager's Indexer account |

Every value is encrypted with AES-256-CBC under a random key and IV generated for that value, and the
key and IV are stored together with the ciphertext. The encryption therefore keeps values from being
read as plain text in the files; what protects them is the ownership and mode of the directory.

The [credential resolver](../../getting-started/credentials.md) writes the `indexer` entries at
installation and before every start: `username` is set to `wazuh-manager` when absent, and `password`
comes from `WAZUH_INDEXER_MANAGER_PASSWORD`.

## CLI usage

`/var/wazuh-manager/bin/wazuh-manager-keystore` is installed `root:root` 0750, so run it as root; it
switches to the `wazuh-manager` user before opening the database.

```bash
# Store a value inline (visible in the process list and shell history)
/var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username -v wazuh-manager

# Store a value from stdin
printf '%s' '<password>' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password

# Store a value from a file (its first line)
/var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -vp /path/to/secret.txt

# Print a stored value; exits 1 when the key is not set
/var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username -g
```

| Flag | Description |
|------|-------------|
| `-f <family>` | Column family (namespace). Required |
| `-k <key>` | Key name. Required |
| `-v <value>` | Value (inline) |
| `-vp <path>` | Value read from the first line of a file |
| (stdin) | When neither `-v` nor `-vp` is given, the value is the first line of standard input; an empty line is an error |
| `-g` | Print the stored value instead of writing one; exits 1 when the key is not set or empty. Cannot be combined with `-v`/`-vp` |
| `-h` | Print the usage |

The tool exits 0 on success and 1 on any error, printing the error (and the usage, for an argument
error) to standard error. There is no delete operation; the resolver's
`--clear` mode removes the whole database instead.

Components read the credentials once per process: restart the manager after changing them.

## `keystore_server`

`keystore_server` (source: `src/wazuh_modules/keystore_server/`) is the modulesd module that exposes
the `Keystore` library to non-C++ callers. Its one production consumer is the Python framework:
`KeystoreClient` (`framework/wazuh/core/indexer/credential_manager.py`) fetches the Indexer
credentials the framework's Indexer client needs.

- **Loading:** it is always loaded on a manager and has no configuration. modulesd resolves
  `libkeystore_server.so` with `dlopen`/`dlsym` and calls its exported
  `keystore_server_start(callbackLog, socketPath)` and `keystore_server_stop(void)`
  (`src/wazuh_modules/src/wm_keystore_server.c`,
  `src/wazuh_modules/keystore_server/include/keystore_server.h`). A missing library, a missing
  symbol or a socket that cannot be bound is fatal for `wazuh-manager-modulesd`
  (`The keystore server cannot bind its socket; see the preceding error. Not running without keystore
  access.`), since an API that silently lost its Indexer credentials is worse than one that refuses
  to start. Its log tag is `wazuh-manager-modulesd:keystore-server`.
- **Transport:** the Unix domain socket `/var/wazuh-manager/queue/sockets/keystore.sock`, mode 0660,
  speaking the size-prefixed socket protocol used elsewhere in modulesd. Socket permissions are its
  only access control.
- **Protocol:** a pipe-delimited text query answered with JSON — `GET|<columnFamily>|<key>`,
  `PUT|<columnFamily>|<key>|<value>`, `DELETE|<columnFamily>|<key>` (a DELETE is implemented as a
  PUT of an empty value). Successful responses look like
  `{"status": "ok", "operation": "get", "columnFamily": ..., "key": ..., "value": ...}` (`value` only
  for `GET`, empty when the key is not set); failures are `{"status": "error", "message": ...}`. This
  wire format is a live contract with `KeystoreClient` on the Python side.
- **Relationship to the library:** `keystore_server` holds no storage or crypto logic — every request
  is translated directly into `Keystore::get()` or `Keystore::put()`.

## Format version

The current keystore format is v2. Every `put()`/`get()` stamps a `version` key in the target column
family so future format changes can key off it. There is no migration of older data: a 5.x manager is
always a fresh installation, so no pre-5.0 keystore reaches this code (see the `upgrade()` comment in
`src/shared_modules/keystore/src/keyStore.cpp`).

## Key source files

| File | Purpose |
|------|---------|
| `src/shared_modules/keystore/include/keyStore.hpp` | Public API: `Keystore::put()`, `Keystore::get()` |
| `src/shared_modules/keystore/src/keyStore.cpp` | Encryption, RocksDB persistence, version stamping |
| `src/shared_modules/keystore/src/main.cpp` | CLI: input handling, privilege drop, `-g` |
| `src/shared_modules/keystore/src/argsParser.hpp` | Command-line parser (`-f`, `-k`, `-v`, `-vp`, `-g`) |
| `src/shared_modules/utils/evpHelper.hpp` | AES-256-CBC encryption with a per-value random key and IV |
| `src/wazuh_modules/keystore_server/src/keystoreServer.cpp` | `keystore.sock` server and request handler |
