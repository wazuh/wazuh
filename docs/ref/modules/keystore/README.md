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

The [credential resolver](../../getting-started/credentials.md) writes the `indexer` entries, through
`wazuh-manager-keystore`, at installation and before every start: `username` is set to `wazuh-manager`
when absent, and, only while the keystore holds no `password`, `password` comes from
`WAZUH_INDEXER_MANAGER_PASSWORD`. A stored password is never replaced by the resolver; change it with
the CLI below.

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
| `-vp <path>` | Value read from the first line of a file (opened before the tool switches user, so a root-only file works) |
| (stdin) | When neither `-v` nor `-vp` is given, the value is the first line of standard input; an empty line is an error |
| `-g` | Print the stored value instead of writing one; exits 1 when the key is not set or empty. Cannot be combined with `-v`/`-vp` |
| `-h` | Print the usage |

The tool exits 0 on success and 1 otherwise. An error is printed to standard error (and, for an
argument error, the usage to standard output); any argument not in the table is refused as
`Unknown option: <argument>` before the keystore is opened. The one silent exit 1 is `-g` on a key that is not
set or is empty: that is an answer, not an error, so nothing is printed. There is no delete
operation; the resolver's `--clear` mode empties the whole `queue/keystore/` directory instead.

The C++ components read the credentials once per process (`wazuh-manager-modulesd`,
`wazuh-manager-analysisd`): restart the manager after changing them. The Python framework reads them
again for every Indexer client it builds.

## Concurrent access

Every `get()` and `put()` — from the CLI, from `keystore_server` and from the C++ components that read
the credentials at start (the Indexer Connector inside the vulnerability scanner, the inventory sync
server and the engine) — opens the database for that one operation and closes it again. RocksDB allows a single
open handle per database, so two operations at the same moment contend for its lock. The second one
waits: it retries the open with a growing backoff, each step randomized so that callers that collided
once do not collide again on every retry. A daemon waits up to 5 seconds, then fails that one
request (`keystore_server` answers it with `{"status": "error", …}`). The CLI waits up to 30 seconds,
then prints `The keystore is busy: other Wazuh processes kept it locked for 30 s. Nothing was read or
written. Run the command again.` and exits 1.

Operations take milliseconds, so running the CLI while the manager starts or runs is safe. A heavy
burst of reads through `keystore.sock` (hundreds at once) can still outlast a wait: nothing is
changed when that happens, so retry the command, or the request, on exit 1.

A held lock is never treated as damage. The database is repaired (RocksDB `RepairDB`, which may not
recover every value) only when opening it reports corruption; any other open error is reported
without a repair.

## Design decisions

| Decision | Why |
|---|---|
| The database is opened per operation, never held open by a daemon | A RocksDB handle holds the database's `LOCK` file for as long as it lives. The keystore is shared by separate processes — modulesd (`keystore_server`, the Indexer Connector), the engine and the CLI — and a long-lived handle in any one of them would lock every other one out for the life of that process; the CLI, which the resolver runs before every start, would never get in. The cost is one open per request, which is cheap next to the lock contention a long-lived handle would turn into a permanent refusal. At idle the requests come from the master's framework, two (`username`, `password`) each time it builds an Indexer client: the active-response poll every 30 s (`active_response_polling`), which builds two clients per cycle even when it finds nothing (one to search for active responses, one to look up their events), and the indexer check, disconnected-agent and metrics tasks every 5 to 10 minutes — about nine to ten opens a minute. Each open of the read-write database writes a new `MANIFEST`, write-ahead log and `OPTIONS` file, so the file numbers in `queue/keystore/` climb several times faster than the opens; they are not an open counter |
| Contention is waited out with a jittered backoff; the CLI waits longer than the daemons | Callers that lost the same race used to retry on the same schedule and collide again, so under a burst some exhausted their wait without ever seeing the lock free. Randomizing each step spreads them out. Daemons keep a short wait (5 s) because they are answering a caller that retries; the CLI waits 30 s because it runs once, and a burst of daemon reads should delay it, not fail it |

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
  only access control. An empty frame is answered with an error; a client that sends part of a frame and then
  goes quiet keeps its connection open (there is no idle timeout), which costs nothing to other clients
  because the server is event-driven.
- **Protocol:** a pipe-delimited text query answered with JSON — `GET|<columnFamily>|<key>`,
  `PUT|<columnFamily>|<key>|<value>`, `DELETE|<columnFamily>|<key>` (a DELETE is implemented as a
  PUT of an empty value). Successful responses look like
  `{"status": "ok", "operation": "get", "columnFamily": ..., "key": ..., "value": ...}` (`value` only
  for `GET`, empty when the key is not set); failures are `{"status": "error", "message": ...}`. This
  wire format is a live contract with `KeystoreClient` on the Python side.
- **Relationship to the library:** `keystore_server` holds no storage or crypto logic — every request
  is translated directly into `Keystore::get()` or `Keystore::put()`.

## Format version

The current keystore format is v2. Every `put()` stamps a `version` key in the target column family
so future format changes can key off it. A `get()` from a column family that does not exist returns
an empty value without creating the family. There is no migration of older data: a 5.x manager is
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
