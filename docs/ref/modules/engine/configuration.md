# Engine Configuration Reference

Complete configuration reference for the Wazuh Engine, the `wazuh-manager-analysisd` daemon (manager only).

The engine has no configuration section of its own: its connection to `wazuh-indexer` comes from the manager's
shared `<indexer>` section, its credentials from the keystore, and every other setting from `analysisd.*` internal
options, each of which can be overridden by an environment variable. For what the engine does with them, see
[Engine](README.md) and [Architecture](architecture.md).

## Configuration sources

| What | Where it comes from |
|------|---------------------|
| Indexer hosts and TLS material | The `<indexer>` section of `/etc/wazuh-manager/wazuh-manager.conf` (`hosts` and `ssl`). See [`indexer`](../../configuration/manager/reference.md#indexer). |
| Indexer username and password | The manager keystore only (`wazuh-manager-keystore -f indexer -k username` / `-k password`). See [Store the credentials in the keystore](../../../guide/migration/filebeat-to-indexer-connector.md#3-store-the-credentials-in-the-keystore). |
| Every other engine setting | `analysisd.*` lines in `/etc/wazuh-manager/wazuh-manager-internal-options.conf` — see [Settings reference](#settings-reference). |
| Overrides | Each `analysisd.*` setting has a `WAZUH_*` environment variable that takes precedence over the file. |
| Process behaviour for one run | The [command-line options](#command-line-options) of `wazuh-manager-analysisd`. |

The engine has no `analysisd.indexer_username` or `analysisd.indexer_password` setting. A line with either key in
the internal options file is ignored; set the credentials in the keystore.

When the engine runs standalone (`WAZUH_ENGINE_STANDALONE=true`, as inside `wazuh-indexer`), it does not read the
internal options file at all: only environment variables and built-in defaults apply, and the indexer connection
comes from the `WAZUH_INDEXER_HOSTS` and `WAZUH_INDEXER_SSL_*` variables instead of `<indexer>`.

## How values are resolved

- Precedence for each setting is environment variable > file value > compiled-in default. The `wazuh-manager`
  systemd unit sets no environment, so an environment variable only reaches an engine started by hand.
- The shipped `wazuh-manager-internal-options.conf` has no `analysisd.*` lines — every setting starts at its default
  until an operator adds one. Edit the file and restart the `wazuh-manager` service for a change to take effect.
- File syntax: one `analysisd.<setting>=<value>` per line. A line starting with `#` is a comment, and an unescaped
  `#` ends the value (`\#` keeps it); surrounding quotes are removed. A list setting takes comma-separated values
  without brackets (`[a,b]` stops the engine at start-up).
- Lines whose key does not start with `analysisd.` are skipped silently (a line with no `=`, or with no `.` before
  it, logs `Invalid configuration line ignored: '<line>'`), and so is an `analysisd.*` key the engine does not know
  (a misspelled setting has no effect). A missing or unreadable file only logs the warning
  `Failed to load configuration: Cannot open configuration file: <path>`, and the defaults apply.
- Boolean settings only accept `true`/`false` (case-insensitive). A value in the file that does not match the
  setting's type (for example `analysisd.dumper_enabled=yes` or `analysisd.event_queue_size=10k`) stops the engine at
  start-up with `Error loading configuration: Invalid configuration type for key '<key>'. …` in
  `wazuh-manager.log`. An environment variable that cannot be converted is logged as a warning and the file value or
  the default is used.
- `wazuh-manager-analysisd -t` (run by every `wazuh-manager-control start`) never reads this file, so a bad
  `analysisd.*` value passes the start checks and then stops the daemon.
- In standalone mode the file is never loaded: only the environment variable and the default apply.
- `Mode` in the tables tells where a setting is read: `both`, `manager` (only when the engine runs inside
  `wazuh-manager`) or `standalone` (only in standalone mode, so only its environment variable can set it).

## Command-line options

```
wazuh-manager-analysisd [-f] [-t] [-d [-d]] [-h] [-V]
```

| Option | Effect |
|--------|--------|
| `-f` | Run in the foreground instead of daemonizing. |
| `-t` | Test the configuration and exit. In manager mode it validates `/etc/wazuh-manager/wazuh-manager.conf`, including the files it references, and exits `0`, or prints `Error loading configuration: <reason>` to stderr and exits `1`. It does not read the internal options file. In standalone mode it exits `0` without checking anything. |
| `-d` | Debug logging for this run: once for debug, twice or more for trace. It takes priority over `analysisd.debug` (`analysisd.logging_level` in standalone mode). |
| `-h` | Print the usage to stdout and exit `0`. An unknown option prints the error and the usage to stderr and exits `1`. |
| `-V` | Print the version (`Wazuh v<version> - Wazuh Inc.`) to stderr, as the other manager daemons do, and exit `0`. |

`wazuh-manager-control start` runs `wazuh-manager-analysisd -t` (with `-d` while debug is enabled with
`wazuh-manager-control enable debug`) as one of its start checks, then launches the daemon **without any option**.
The debug level of the running engine is therefore set only by `analysisd.debug`, not by
`wazuh-manager-control enable debug`.

After launching it, `start` waits up to 10 seconds for the PID file
`/var/wazuh-manager/var/run/wazuh-manager-analysisd-<pid>.pid`, then sends `GET /status` to
`/var/wazuh-manager/queue/sockets/engine-api-http.sock` once per second, up to 120 times, until the engine answers
with a status below `400`. On failure it prints `Failed to obtain PID for wazuh-manager-analysisd`,
`wazuh-manager-analysisd died during the readiness check.` or
`wazuh-manager-analysisd did not respond correctly after 120 attempts.` (the last one also kills the engine), and
the start fails with `wazuh-manager-analysisd did not start correctly.`

## Environment variables outside the settings

These variables are read directly by the process, not through an `analysisd.*` setting:

| Variable | Effect |
|----------|--------|
| `WAZUH_ENGINE_STANDALONE` | `true` (case-insensitive) runs the engine in standalone mode: no manager configuration, no internal options file, no privilege drop, no PID file, and default paths relative to the working directory. Any other value, or unset, is manager mode. |
| `WAZUH_MANAGER_HOME` | Manager mode only: the home directory, used as is when not empty. Without it the home is the executable's directory cut at the first `/bin` (`/var/wazuh-manager`). When the result is not a directory the daemon writes `(1108): Unable to find Wazuh install directory. Export it to WAZUH_MANAGER_HOME environment variable.` to stderr and exits `1`. |
| `WAZUH_MANAGER_FORCE_HOME` | Manager mode only: when defined (even empty) it is the home, unchecked, and takes priority over `WAZUH_MANAGER_HOME`. |
| `WAZUH_STANDALONE_LOG_*` | Standalone mode only: log file path, rotation and compression of the standalone log. Listed in `src/engine/standalone/README.md`. |

The home only moves the paths derived from it; the configuration directory `/etc/wazuh-manager` is fixed.

## Settings reference

All settings below go in `/etc/wazuh-manager/wazuh-manager-internal-options.conf`, resolved as described in
[How values are resolved](#how-values-are-resolved).

### Logging

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.debug` | `WAZUH_LOG_LEVEL` | Log verbosity for the manager-mode engine process: `0` info, `1` debug, `2` (or higher) trace. The `-d` command-line option overrides it. See [How to enable debug logging](README.md#how-to-enable-debug-logging). | `0` | manager |
| `analysisd.logging_level` | `WAZUH_STANDALONE_LOG_LEVEL` | Log verbosity for the standalone engine process, as a level name (`info`, `debug`, `trace`, ...). | `info` | standalone |

### Process

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.pid_path` | `WAZUH_ENGINE_PID_FILE_PATH` | Directory where the manager-mode engine process writes its PID file, `wazuh-manager-analysisd-<pid>.pid`. Do not change it on a manager: `wazuh-manager-control start` looks for the PID file only in `/var/wazuh-manager/var/run/` and fails the start when it is not there within 10 seconds. | `/var/wazuh-manager/var/run/` | manager |
| `analysisd.drop_privileges` | `WAZUH_ENGINE_DROP_PRIVILEGES` | Whether the manager-mode engine process drops root privileges after start-up. Has no effect in standalone mode. | `true` | manager |

#### Process privileges

The engine daemon is launched as `root` and, in manager mode, switches to the `wazuh-manager` group and user at
start-up, before it opens its store and sockets. The user and group are hard-coded; only the switch itself is
configurable, with `analysisd.drop_privileges` (set it to `false` only for debugging). In standalone mode (inside
`wazuh-indexer`) the engine keeps the user and group it was launched with. If the user or group change fails, the
daemon logs the error and exits at start-up.

##### Switching back to `true` after running as `root`

While `analysisd.drop_privileges` is `false` the daemon keeps running as `root`, so every file and directory it
creates under `/var/wazuh-manager` belongs to `root:root` and is not group-writable. Setting the option back to
`true` (or removing it, since `true` is the default) makes the daemon start as `wazuh-manager`, which can no longer
write that content, and start-up fails with a permission error naming the offending path. For example:

```
Cannot create directory in base path: /var/wazuh-manager/data/ruleset: Permission denied
Failed to create KVDB root directory: Permission denied
```

The ownership must be fixed manually before restarting the daemon. The paths the engine creates or writes at
runtime are:

| Path | Contents |
|------|----------|
| `/var/wazuh-manager/data/store` | Engine store documents |
| `/var/wazuh-manager/data/ruleset` | Content Manager ruleset (write-tested at start-up) |
| `/var/wazuh-manager/data/kvdb-ioc` | IOC KVDB (RocksDB files, must be owner-writable) |
| `/var/wazuh-manager/data/mmdb` | Downloaded geolocation databases |
| `/var/wazuh-manager/data/tzdb` | Time-zone database |
| `/var/wazuh-manager/logs/<channel>/` | Stream-log channels: `file` outputs and the event dumper |
| `/var/wazuh-manager/var/run` | PID file (the directory is group-writable, so it needs no fix) |

With the daemon stopped, restore the ownership of the affected paths and start it again:

```bash
cd /var/wazuh-manager
chown -R wazuh-manager:wazuh-manager data/store data/ruleset data/kvdb-ioc data/tzdb
chown wazuh-manager:wazuh-manager data/mmdb/*.mmdb
# Every stream-log channel directory the engine created while running as root, for example:
chown -R wazuh-manager:wazuh-manager logs/event-dumps
```

The reverse transition (`true` → `false`) needs no fix, since `root` can write files owned by `wazuh-manager`. To
avoid the problem altogether, restore the ownership right after every debugging session run with
`analysisd.drop_privileges=false`.

#### Process limits

At start-up the engine raises its own soft file-descriptor limit to a fixed **`8192`**. This is not configurable —
there is no option or environment variable for it. The engine only ever raises the soft limit, and never above the
hard limit, which belongs to whatever starts the process (`LimitNOFILE=` in the service unit, which the
`wazuh-manager` unit sets to `65536`; `ulimit -n`; container `ulimits`); it never lowers a soft limit that is
already higher. When the hard limit is below `8192`, the engine keeps the hard limit and logs one warning:

```
File descriptor limit is 4096, below the 8192 requested by the engine. Raise the limit the process is started with (LimitNOFILE, ulimit -n, container ulimits) to go higher.
```

To go higher, raise the limit the process is started with: a drop-in with `LimitNOFILE=` for
`wazuh-manager.service` (or `wazuh-indexer.service` for the engine embedded in wazuh-indexer), `ulimit -n` before
the init script, or `ulimits` in the container definition. The limits of every manager daemon are described in
[File descriptor limits](../../configuration/manager/README.md#file-descriptor-limits).

**Stack size.** The engine does not set the stack size of any of its threads. Every thread takes the soft
`RLIMIT_STACK` the process was started with (`8 MiB` by default on Linux, inherited from systemd or from the shell
that launches the process). The engine needs that limit to be **finite and at least `8 MiB`**; it does not check it
at start-up. To set it, use a drop-in with `LimitSTACK=` for `wazuh-manager.service` (or `wazuh-indexer.service` for
the engine embedded in wazuh-indexer), or `ulimit -s` before the init script. Do not set it to `infinity`
(`unlimited`): with an unlimited limit glibc ignores it and gives each thread only `2 MiB`, below the requirement.
The parsers limit their nesting to 256 levels (see [Parser reference](ref-parser.md)), a bound sized for this
minimum stack.

### Paths

The manager process creates and writes these paths at start-up (except the IoC input directory, which it only
reads); they must remain owned by `wazuh-manager` (see [Process privileges](#process-privileges)).

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.store_path` | `WAZUH_STORE_PATH` | Directory holding the engine's compiled policy store. | `/var/wazuh-manager/data/store` | both |
| `analysisd.output_path` | `WAZUH_OUTPUTS_PATH` | Directory holding the default output definitions. In standalone mode the default is `etc/outputs/` under the working directory. | `/etc/wazuh-manager/outputs/` | both |
| `analysisd.kvdb_ioc_path` | `WAZUH_KVDB_IOC_PATH` | Directory holding the IoC key-value databases. | `/var/wazuh-manager/data/kvdb-ioc` | both |
| `analysisd.kvdb_ioc_input_path` | `WAZUH_KVDB_IOC_INPUT_PATH` | The only directory `POST /content/ioc/update` accepts IoC feed files from; the path must resolve to a regular file inside it. The manager installer does not create it: in manager mode the IOC set comes from the in-process indexer sync, so every request to this endpoint is rejected until an operator creates the directory, readable by the `wazuh-manager` user (for example `wazuh-manager:wazuh-manager`, `0750`). In standalone mode `run_engine.sh` sets it to the bundle's `data/` directory, where `wazuh-indexer` writes `iocs.ndjson`. | `/var/wazuh-manager/data/ioc-input` | both |
| `analysisd.cm_ruleset_path` | `WAZUH_CM_RULESET_PATH` | Directory holding the content-manager ruleset synced from `wazuh-indexer`. | `/var/wazuh-manager/data/ruleset` | both |

### Event queue

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.event_queue_size` | `WAZUH_EVENT_QUEUE_SIZE` | Maximum number of events waiting in the router input queue. Events can be dropped when this queue is full. Minimum `8192`; a smaller value stops the engine at start-up. | `131072` | both |
| `analysisd.event_queue_eps` | `WAZUH_EVENT_QUEUE_EPS` | Maximum number of events per second the router takes from its input queue. `0` means unlimited. Above this rate the queue fills up and new events are dropped (`router.events.dropped`). | `0` | both |
| `analysisd.event_queue_max_bytes` | `WAZUH_EVENT_QUEUE_MAX_BYTES` | Maximum total byte size of events waiting in the router input queue. Events are dropped when this quota is full. `0` means unlimited. | `33554432` (32 MB) | both |

### Agent metadata cache

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.agent_metadata_cache_ttl` | `WAZUH_AGENT_METADATA_CACHE_TTL` | Time-to-live in seconds for cached agent metadata. | `300` | both |
| `analysisd.agent_metadata_cache_clean_interval` | `WAZUH_AGENT_METADATA_CACHE_CLEAN_INTERVAL` | Interval in seconds between best-effort evictions of stale agent metadata cache entries. | `60` | both |

### Orchestrator

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.orchestrator_threads` | `WAZUH_ORCHESTRATOR_THREADS` | Number of orchestrator worker threads. `0` uses one worker per CPU core. Allowed range: `0` to `128`, else the engine fails to start. | `0` | both |

### Indexer connector settings

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.indexer_queue_max_bytes` | `WAZUH_INDEXER_QUEUE_MAX_BYTES` | Maximum number of bytes of events waiting in the indexer output queue. Events can be dropped when this queue is full. | `67108864` (64 MB) | both |
| `analysisd.indexer_bulk_max_bytes` | `WAZUH_INDEXER_BULK_MAX_BYTES` | Maximum byte size of the bulk payload accumulated before a `_bulk` request is dispatched to `wazuh-indexer`. When the buffered data reaches this threshold, a batch is flushed. Allowed range: `64KB` to `100MB`. | `8388608` (8 MB) | both |
| `analysisd.indexer_flush_interval` | `WAZUH_INDEXER_FLUSH_INTERVAL` | Seconds between periodic flushes of the asynchronous indexer bulk buffer. Drives the background timer that forwards buffered events to `wazuh-indexer` when the byte threshold has not been reached. Allowed range: `1` to `3600`. | `20` | both |
| `analysisd.indexer_logger_queue_size` | `WAZUH_INDEXER_LOGGER_QUEUE_SIZE` | Maximum number of `_bulk` responses (with their payloads) that can wait in the indexer error-logger queue. Only responses whose bulk reported item errors are queued; when the queue is full the error details are dropped and a warning is logged. Allowed range: `1` to `1024`. | `8` | both |
| `analysisd.indexer_logger_threads` | `WAZUH_INDEXER_LOGGER_THREADS` | Number of worker threads that parse `_bulk` error responses to log per-item failures. Allowed range: `1` to `16`. | `1` | both |
| `analysisd.indexer_max_retry_delay` | `WAZUH_INDEXER_MAX_RETRY_DELAY` | Maximum exponential-backoff delay in seconds between retries of a failed `_bulk` request (e.g. `429 Too Many Requests`, `503 Service Unavailable`, connection errors). See [Indexer Connector - Retry and backoff behavior](../indexer_connector/README.md#retry-and-backoff-behavior) for how the delay scales. Allowed range: `1` to `3600`. | `15` | both |
| `analysisd.indexer_request_timeout` | `WAZUH_INDEXER_REQUEST_TIMEOUT` | Upper bound in seconds for one data request against `wazuh-indexer`. Catches a host that accepted the connection and then never answers; a timed-out bulk request is retried with backoff, not discarded. Allowed range: `0` to `3600` (`0` disables the bound). | `60` | both |
| `analysisd.indexer_monitoring_interval` | `WAZUH_INDEXER_MONITORING_INTERVAL` | Polling period in seconds of the indexer health monitor that marks each `wazuh-indexer` host as available or unavailable for the connector. Allowed range: `1` to `3600`. | `10` | both |

### Indexer connection (standalone only)

These keys configure the `wazuh-indexer` connection used by the standalone engine process only. In manager mode
they are not read at all — hosts and TLS material come from the `<indexer>` section of `wazuh-manager.conf`, and
credentials from the keystore (see [Configuration sources](#configuration-sources)).

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.indexer_hosts` | `WAZUH_INDEXER_HOSTS` | List of `wazuh-indexer` base URLs. | `["http://localhost:9200"]` | standalone |
| `analysisd.indexer_ssl_certificate_authorities` | `WAZUH_INDEXER_SSL_CA_BUNDLE` | List of CA bundle file paths used to validate the `wazuh-indexer` TLS certificate. | `[]` | standalone |
| `analysisd.indexer_ssl_certificate` | `WAZUH_INDEXER_SSL_CERTIFICATE` | Path to the client TLS certificate presented to `wazuh-indexer`. | `""` | standalone |
| `analysisd.indexer_ssl_key` | `WAZUH_INDEXER_SSL_KEY` | Path to the client TLS private key presented to `wazuh-indexer`. | `""` | standalone |

### Synchronization

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.remote_conf_sync_interval` | `WAZUH_REMOTE_CONF_SYNC_INTERVAL` | Seconds between remote engine configuration synchronization cycles. | `120` | both |
| `analysisd.remote_conf_indexer_connector_max_retries` | `WAZUH_REMOTE_CONF_INDEXER_CONNECTOR_MAX_RETRIES` | Maximum retry attempts for remote configuration requests to the Wazuh Indexer. | `3` | both |
| `analysisd.remote_conf_indexer_connector_retry_interval` | `WAZUH_REMOTE_CONF_INDEXER_CONNECTOR_RETRY_INTERVAL` | Seconds between retry attempts for remote configuration synchronization. | `5` | both |
| `analysisd.cm_sync_interval` | `WAZUH_CM_SYNC_INTERVAL` | Seconds between content synchronization cycles from the Wazuh Indexer. | `120` | both |
| `analysisd.cm_sync_retry_interval` | `WAZUH_CM_SYNC_RETRY_INTERVAL` | Seconds until the next content synchronization cycle while a space has no route and its policy is not disabled (the indexer failed, or the content is not ready yet). A policy with no integrations or no root decoder counts as disabled, so it does not trigger the early retry. Replaces `analysisd.cm_sync_interval` until every space is loaded, and is capped at it. `0` disables the early retry. Allowed range: `0` to `3600`, else the engine fails to start. | `30` | both |
| `analysisd.cmsync_indexer_connector_sync_batch_size` | `WAZUH_CMSYNC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE` | Maximum number of content documents requested per Wazuh Indexer page during content synchronization. | `100` | both |
| `analysisd.cmsync_indexer_connector_max_retries` | `WAZUH_CMSYNC_INDEXER_CONNECTOR_MAX_RETRIES` | Maximum retry attempts for content synchronization requests to the Wazuh Indexer. | `3` | both |
| `analysisd.cmsync_indexer_connector_retry_interval` | `WAZUH_CMSYNC_INDEXER_CONNECTOR_RETRY_INTERVAL` | Seconds between retry attempts for content synchronization. | `5` | both |
| `analysisd.ioc_sync_interval` | `WAZUH_IOC_SYNC_INTERVAL` | Seconds between IoC database synchronization cycles. `0` disables IoC sync. | `360` | both |
| `analysisd.ioc_indexer_connector_max_retries` | `WAZUH_IOC_INDEXER_CONNECTOR_MAX_RETRIES` | Maximum retry attempts for IoC synchronization requests to the Wazuh Indexer. | `3` | both |
| `analysisd.ioc_indexer_connector_retry_interval` | `WAZUH_IOC_INDEXER_CONNECTOR_RETRY_INTERVAL` | Seconds between retry attempts for IoC synchronization. | `5` | both |
| `analysisd.ioc_indexer_connector_sync_batch_size` | `WAZUH_IOC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE` | Maximum number of IoC documents streamed per Wazuh Indexer page while synchronizing IoC databases. | `1000` | both |

### Geo

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.geo_sync_interval` | `WAZUH_GEO_SYNC_INTERVAL` | Seconds between GeoIP database synchronization cycles. `0` disables GeoIP sync. | `360` | both |
| `analysisd.geo_db_path` | `WAZUH_GEO_DB_PATH` | Directory holding the downloaded GeoIP (MaxMind) database. Only read while GeoIP sync is enabled. | `/var/wazuh-manager/data/mmdb` | both |
| `analysisd.geo_manifest_url` | `WAZUH_GEO_MANIFEST_URL` | URL of the GeoIP database manifest used to check for updates. | `https://api.pre.cloud.wazuh.com/maxmind_geoip/manifest.json` | both |
| `analysisd.geo_download_timeout` | `WAZUH_GEO_DOWNLOAD_TIMEOUT` | Timeout in milliseconds for downloading the GeoIP database. | `60000` (60 s) | both |

> **Note:** the default `analysisd.geo_manifest_url` points to the **pre-production** Wazuh cloud endpoint
> (`api.pre.cloud.wazuh.com`), so the GeoIP databases a default installation downloads come from it. To use another
> manifest, set the option in `/etc/wazuh-manager/wazuh-manager-internal-options.conf` and restart the manager:
>
> ```ini
> analysisd.geo_manifest_url=https://<your-manifest-host>/<path>/manifest.json
> ```
>
> The `WAZUH_GEO_MANIFEST_URL` environment variable overrides the file, but the `wazuh-manager` systemd unit sets no
> environment, so it only reaches an engine started by hand (or in standalone mode, where the file is not read).

### Time-zone database

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.tzdb_path` | `WAZUH_TZDB_PATH` | Directory holding the local IANA time-zone database used by the engine. | `/var/wazuh-manager/data/tzdb` | both |
| `analysisd.tzdb_auto_update` | `WAZUH_TZDB_AUTO_UPDATE` | Whether the engine automatically downloads time-zone database updates. | `false` | both |
| `analysisd.tzdb_force_version_update` | `WAZUH_TZDB_FORCE_VERSION_UPDATE` | Time-zone database version to force-install, overriding auto-detection. Empty means no forced version. | `""` | both |

### Stream log

The events streams (one channel per `file` output, named `<space>-<file value>`, written as `.json`) and the
dumper stream (channel `event-dumps`, written as `.log`) share these settings; each one is read once for the events
streams and once for the dumper stream. A channel's files are
`<streamlog_base_path>/<channel>/<pattern>.<extension>`, and `<channel>.<extension>` in the channel directory
links to the current file.

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.streamlog_base_path` | `WAZUH_STREAMLOG_BASE_PATH` | Base directory for the events and dumper stream-log files. | `/var/wazuh-manager/logs/` | both |
| `analysisd.streamlog_compress` | `WAZUH_STREAMLOG_SHOULD_COMPRESS` | Whether rotated stream-log files (events and dumper) are compressed. | `true` | both |
| `analysisd.streamlog_compression_level` | `WAZUH_STREAMLOG_COMPRESSION_LEVEL` | Compression level applied to rotated stream-log files (events and dumper). | `5` | both |
| `analysisd.streamlog_events_pattern` | `WAZUH_STREAMLOG_EVENTS_PATTERN` | File-name pattern for the events stream log, relative to `analysisd.streamlog_base_path`. | `${YYYY}/${MMM}/wazuh-${name}-${DD}` | both |
| `analysisd.streamlog_events_max_size` | `WAZUH_STREAMLOG_EVENTS_MAX_SIZE` | Maximum size in bytes of one events stream-log file before rotation. `0` disables size-based rotation; a value below `1048576` (1 MB) is raised to 1 MB. | `0` | both |
| `analysisd.streamlog_events_buffer_size` | `WAZUH_STREAMLOG_EVENTS_BUFFER_SIZE` | Capacity, in messages, of the events stream log's write queue (`0` means the default). | `1048576` | both |
| `analysisd.streamlog_dumper_pattern` | `WAZUH_STREAMLOG_DUMPER_PATTERN` | File-name pattern for the dumper stream log, relative to `analysisd.streamlog_base_path`. | `${YYYY}/${MMM}/wazuh-${name}-${DD}` | both |
| `analysisd.streamlog_dumper_max_size` | `WAZUH_STREAMLOG_DUMPER_MAX_SIZE` | Maximum size in bytes of one dumper stream-log file before rotation. `0` disables size-based rotation; a value below `1048576` (1 MB) is raised to 1 MB. | `0` | both |
| `analysisd.streamlog_dumper_buffer_size` | `WAZUH_STREAMLOG_DUMPER_BUFFER_SIZE` | Capacity, in messages, of the dumper stream log's write queue (`0` means the default). | `1048576` | both |
| `analysisd.streamlog_max_files` | `WAZUH_STREAMLOG_MAX_FILES` | Maximum number of rotated files kept in each stream-log channel directory (applied to the events and the dumper channel separately) before the oldest is deleted. | `90` | both |
| `analysisd.streamlog_max_accumulated_size` | `WAZUH_STREAMLOG_MAX_ACCUMULATED_SIZE` | Maximum total disk size of the rotated files in each stream-log channel directory (applied to the events and the dumper channel separately). | `21474836480` (20 GB) | both |

### Event dumper

The event dumper exists only while `analysisd.server_enable_event_processing` is `true`; without it the
`/_internal/event-dumper/*` routes answer `500`. Its files are
`<streamlog_base_path>/event-dumps/<YYYY>/<MMM>/wazuh-event-dumps-<DD>.log` (by default under
`/var/wazuh-manager/logs/event-dumps/`), with `event-dumps.log` in the same channel directory linked to the current
file.

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.dumper_enabled` | `WAZUH_DUMPER_ENABLED` | Whether the event dumper, which writes every incoming event to the dumper stream log, is active at start-up. The private API routes `/_internal/event-dumper/activate` and `/_internal/event-dumper/deactivate` switch it until the next restart. | `false` | both |

### Engine API server

| Setting | Env var | Description | Default | Mode |
|:--|:--|:--|:--:|:--:|
| `analysisd.server_api_socket` | `WAZUH_SERVER_API_SOCKET` | Unix domain socket path for the engine's HTTP API server. Do not change it on a manager: the readiness probe of `wazuh-manager-control start` and the Server API use the fixed default path. | `/var/wazuh-manager/queue/sockets/engine-api-http.sock` | both |
| `analysisd.server_api_timeout` | `WAZUH_SERVER_API_TIMEOUT` | Tester timeout in milliseconds: how long a test run (`/logtest`, `/_internal/tester/run/post`) waits for the event's result before answering `400` with `Timeout waiting for ingestTest`. A value below `1` stops the engine at start-up. | `5000` (5 s) | both |
| `analysisd.server_api_payload_max_bytes` | `WAZUH_SERVER_API_PAYLOAD_MAX_BYTES` | Maximum request payload size in bytes for the engine's HTTP API server. `0` means unlimited. A negative value is clamped to `0` with a warning. | `0` | both |
| `analysisd.server_enriched_events_socket` | `WAZUH_SERVER_ENRICHED_EVENTS_SOCKET` | Unix domain socket path for the engine's enriched-events HTTP ingest server (`POST /events/enriched`). Do not change it on a manager: `wazuh-manager-remoted` and the vulnerability scanner send events to the fixed default path. | `/var/wazuh-manager/queue/sockets/engine-ingest-http.sock` | both |
| `analysisd.server_enable_event_processing` | `WAZUH_SERVER_ENABLE_EVENT_PROCESSING` | Master switch for the event-processing pipeline (indexer connector, stream loggers, raw-event indexer, remote-conf and CM/IOC sync, dumper, enriched-events HTTP server). With `false` the manager starts but processes no events: there is no event dumper (its routes answer `500`), and `GET /status` — which the readiness probe of `wazuh-manager-control start` uses — answers with no `spaces` or `ioc` entries and `ready: false`. | `true` | both |
| `analysisd.api_resource_payload_max_bytes` | `WAZUH_SERVER_API_MAX_RESOURCE_PAYLOAD_SIZE` | Maximum payload size in bytes accepted for a resource in the engine's HTTP API server. | `50000` | both |
| `analysisd.api_resource_kvdb_payload_max_bytes` | `WAZUH_SERVER_API_MAX_RESOURCE_KVDB_PAYLOAD_SIZE` | Maximum payload size in bytes accepted for a KVDB resource in the engine's HTTP API server. | `100000` | both |

## Configuration examples

The built-in defaults, written out (adding these lines changes nothing):

```ini
# Event queue
analysisd.event_queue_size=131072
analysisd.event_queue_eps=0

# Indexer connector
analysisd.indexer_bulk_max_bytes=8388608
analysisd.indexer_flush_interval=20

# Synchronization
analysisd.remote_conf_sync_interval=120
analysisd.cm_sync_interval=120

# Database updates
analysisd.ioc_sync_interval=360
analysisd.geo_sync_interval=360
```

A larger queue and bulk payload for a high event rate, with more frequent synchronization:

```ini
analysisd.event_queue_size=262144
analysisd.event_queue_max_bytes=67108864
analysisd.indexer_queue_max_bytes=134217728
analysisd.indexer_bulk_max_bytes=33554432
analysisd.indexer_flush_interval=5
analysisd.remote_conf_sync_interval=60
analysisd.cm_sync_interval=60
```

A smaller footprint for a constrained host. The rate cap drops every event above 100 per second once the queue is
full, so set it only when that loss is acceptable:

```ini
analysisd.event_queue_size=8192
analysisd.event_queue_eps=100
analysisd.indexer_bulk_max_bytes=1048576
analysisd.indexer_flush_interval=60
analysisd.remote_conf_sync_interval=600
analysisd.cm_sync_interval=7200
```

### Tuning notes

- **Event queue.** `analysisd.event_queue_size` (at least `8192`) and `analysisd.event_queue_max_bytes` bound the
  router input queue by count and by bytes; whichever fills first drops new events. `analysisd.event_queue_eps`
  caps how fast the queue is drained, so any non-zero value trades event loss for CPU.
- **Indexer bulk.** A smaller `analysisd.indexer_bulk_max_bytes` and a shorter `analysisd.indexer_flush_interval`
  deliver events to `wazuh-indexer` sooner, in more requests; larger values send fewer, bigger requests.
  `analysisd.indexer_queue_max_bytes` bounds what waits for the indexer.
- **Synchronization.** Shorter `analysisd.cm_sync_interval`, `analysisd.ioc_sync_interval` and
  `analysisd.geo_sync_interval` pick up content changes sooner at the cost of more requests to `wazuh-indexer`
  (content, IOCs) and to the GeoIP manifest URL.

## API access

The engine exposes its HTTP API over a **Unix domain socket**, `/var/wazuh-manager/queue/sockets/engine-api-http.sock`
(`analysisd.server_api_socket`) — not a TCP port. Requests and responses are JSON, validated against protobuf
schemas. Routes, bodies and responses are described in the [API Reference](api-reference.md). Reach it with
`curl --unix-socket`, as root or a member of the `wazuh-manager` group:

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock http://localhost/status
```

The `engine-suite` CLIs (`engine-public`, `engine-private`, `engine-router`, `engine-test`, `engine-event-dumper`)
wrap these calls. They are not installed with the manager — see [Internal Tools](internal-tools.md).

## Monitoring

### Check engine status

```bash
# Process
ps aux | grep wazuh-manager-analysisd

# Readiness of the content spaces, IOC and GeoIP databases (GET /status)
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock http://localhost/status
```

### View engine logs

```bash
# Engine log lines (tag wazuh-manager-analysisd)
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep wazuh-manager-analysisd

# Events written by a `file` output: one channel directory per <space>-<file value>
tail -f /var/wazuh-manager/logs/<channel>/<YYYY>/<MMM>/wazuh-<channel>-<DD>.json
```

### Performance metrics

The metric names are listed in [Available metric names](README.md#available-metric-names).

```bash
# List all registered metric names
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/list \
  -H "Content-Type: application/json" -d '{}'

# Get a single metric's value, e.g. the global event-processing counter
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/get \
  -H "Content-Type: application/json" -d '{"instrumentName": "router.events.processed"}'

# Dump every metric (global + per-space) in one call
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/dump \
  -H "Content-Type: application/json" -d '{}'
```

### Queue monitoring

`router.queue.size`, `router.queue.usage.percent`, `router.queue.bytes.usage.percent` and `router.events.dropped`
show the input queue; `indexer.queue.usage.percent` and `indexer.events.dropped` the output queue. When the input
queue has stayed contended for 10 minutes, the engine logs a warning with the events dropped meanwhile, and repeats
it at most every 10 minutes while the contention lasts:

```bash
grep "Event queue has remained contended" /var/wazuh-manager/logs/wazuh-manager.log
```

## Troubleshooting

### Engine won't start

`wazuh-manager-control start` reports `wazuh-manager-analysisd did not start correctly.` and one of the readiness
messages listed in [Command-line options](#command-line-options). Look for the reason in the engine's own lines:

```bash
grep wazuh-manager-analysisd /var/wazuh-manager/logs/wazuh-manager.log | grep -E "ERROR|CRITICAL|WARNING"
```

- `Error loading configuration: Invalid configuration type for key …` — a bad `analysisd.*` value; fix the line in
  `wazuh-manager-internal-options.conf`.
- A permission error naming a path under `/var/wazuh-manager` — see
  [Switching back to `true` after running as `root`](#switching-back-to-true-after-running-as-root).
- A range error such as `analysisd.indexer_bulk_max_bytes must be between …` — a setting outside its allowed range.

### Events being dropped

**Cause:** the router input queue is full (by count or by bytes), or the EPS cap keeps it from draining.

1. Increase the queue (defaults `131072` events, `33554432` bytes):
   ```ini
   analysisd.event_queue_size=262144
   analysisd.event_queue_max_bytes=67108864
   ```
2. Remove the EPS cap (`0`, the default, means unlimited):
   ```ini
   analysisd.event_queue_eps=0
   ```
3. Restart the manager:
   ```bash
   systemctl restart wazuh-manager
   ```

### Slow delivery to the indexer

**Cause:** the bulk buffer waits for its size threshold or its flush timer.

1. Reduce the bulk size (default `8388608`, 8 MB):
   ```ini
   analysisd.indexer_bulk_max_bytes=1048576
   ```
2. Reduce the flush interval (default `20` seconds):
   ```ini
   analysisd.indexer_flush_interval=5
   ```

### Synchronization failures

**Cause:** `wazuh-indexer` unreachable, or its content not ready.

1. Check the connector warnings, tagged `[CMSync]`, `[CM::Sync]` and `[IOC::Sync]`:
   ```bash
   grep -E "CMSync|CM::Sync|IOC::Sync" /var/wazuh-manager/logs/wazuh-manager.log
   ```
2. Check the `<indexer>` section of `wazuh-manager.conf` and the indexer credentials in the keystore (see
   [Configuration sources](#configuration-sources)).
3. Check the per-space state with `GET /status`.

## See also

- [Engine](README.md) — data flow, assets, metrics and debugging
- [API Reference](api-reference.md) — engine API endpoints
- [Architecture](architecture.md) — engine modules
- [Helper Functions Reference](ref-helper-functions.md), [Parsers Reference](ref-parser.md),
  [Outputs Reference](ref-output.md)
- [Manager Configuration Reference](../../configuration/manager/README.md) — all manager configuration options
