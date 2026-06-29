# Keystore

`wazuh-manager-keystore` is a CLI utility that stores encrypted credentials for the Wazuh Manager. Other components (Indexer Connector, Server API) read secrets from the keystore at runtime via the `Keystore` C++ library.

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

## Encryption versions

The keystore has undergone one version upgrade:

| Version | Encryption | Notes |
|---------|-----------|-------|
| v1 | RSA (via `etc/sslmanager.key`) | Legacy format |
| v2 | AES-256-CBC (EVP) | Current format, no key file dependency |

On first access after an upgrade, the daemon automatically migrates v1 entries to v2.

## Key source files

| File | Purpose |
|------|---------|
| `include/keyStore.hpp` | Public API: `Keystore::put()`, `Keystore::get()` |
| `src/keyStore.cpp` | AES-256 encrypt/decrypt, RocksDB persistence, v1→v2 migration |
| `src/main.cpp` | CLI argument handling, stdin/file input |
| `src/argsParser.hpp` | Command-line parser (`-f`, `-k`, `-v`, `-vp`) |
