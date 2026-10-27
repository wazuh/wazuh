# Wazuh Engine Standalone

## Building the standalone package locally

You can build the Wazuh Engine Standalone package locally using the `generate_package.sh` script:

```bash
cd wazuh/src/engine/standalone
./generate_package.sh -a amd64
```

Available options (`help()` and `main()` in `generate_package.sh`):
- `-a, --architecture <arch>`: Target architecture [amd64/x86_64/x64/arm64/aarch64]. Default: amd64
- `-j, --jobs <number>`: Number of parallel jobs for compilation. Default: 2
- `-d, --debug`: Build with debug flags (without optimizations)
- `-s, --store <path>`: Set destination path for the package. Default: ./output
- `--dont-build-docker`: Use existing docker image instead of building a new one
- `--tag <tag>`: Docker image tag to use. Default: latest
- `-h, --help`: Show help

The script will:
1. Build the Docker image `pkg_rpm_manager_builder_<arch>` from `packages/rpms/<arch>/manager` (or use the
   existing one with `--dont-build-docker`)
2. Run `docker-entrypoint.sh` in the container, which builds the whole manager tree
   (`make deps TARGET=manager`, then `make TARGET=manager`) and copies the toolchain's `libstdc++.so.6`
3. Generate the engine schemas with `tools/engine-schema/engine_schema.py generate`
4. Create the standalone package structure
5. Generate a `.tar.gz` file in the output directory

Example output: `wazuh-engine-5.0.0-linux-amd64.tar.gz`, which unpacks into `wazuh-engine-standalone-5.0.0/`
(the version comes from `VERSION.json`).

## How to use the standalone engine

Run the `run_engine.sh` script at the root of the unpacked package. It exports the variables described
below (including `WAZUH_ENGINE_STANDALONE=true`), creates the `sockets/`, `logs/`, `data/outputs/default/`
and `data/content/` directories if missing, and replaces itself (`exec`) with `bin/wazuh-engine -f` (foreground).

```bash
cd wazuh-engine-standalone-5.0.0
./run_engine.sh
```

In standalone mode the engine reads no internal-options file and does not drop privileges: every setting
comes from the environment or its built-in default.

## Directory structure

The package and `run_engine.sh` provide the following directory structure:

- **bin/**: Contains the engine (`bin/wazuh-engine`)
    - **bin/lib**: Contains the shared libraries used by the engine
- **data/**: Contains the data files used by the engine in runtime, this directory should
    not be modified manually
    - **data/store**: The engine's internal store (`WAZUH_STORE_PATH`): schemas, enrichment and GeoIP
      documents seeded by the package
    - **data/kvdb-ioc**: The IOC key-value databases (`WAZUH_KVDB_IOC_PATH`), created by the engine
    - **data/content**: The content-manager ruleset store (`WAZUH_CM_RULESET_PATH`)
    - **data/outputs**: Output definitions (`WAZUH_OUTPUTS_PATH`)
    - **data/tzdb**: The time zone database (`WAZUH_TZDB_PATH`; the IANA files are under `data/tzdb/iana`)
    - **data/mmdb**: The MaxMind GeoIP database files (`WAZUH_GEO_DB_PATH`)
    - **data/kvdb**: Created empty by the package; the engine does not use it
- **schemas/**: The generated `wazuh-decoders.json` and `wazuh-filters.json` schemas
- **logs/**: The base directory of the engine's stream logs (`WAZUH_STREAMLOG_BASE_PATH`), and the engine
  log `wazuh-engine.log` when `/var/log/wazuh-indexer` does not exist (see below)
- **sockets/**: Used for engine sockets
    - **sockets/engine-api-http.sock**: Engine HTTP API socket (`WAZUH_SERVER_API_SOCKET`).

## Configuration variables

`run_engine.sh` exports these variables unconditionally (edit the script to change them); the values shown are
the ones it sets. Every other `WAZUH_*` variable registered in `source/conf/src/conf.cpp` is also honoured
when exported before launching the script.

### General

| Variable | Default | Description |
|---|---|---|
| `WAZUH_STANDALONE_LOG_LEVEL` | `info` | Log verbosity level |
| `WAZUH_SERVER_ENABLE_EVENT_PROCESSING` | `false` (the engine's own default is `true`) | Enable/disable event processing |
| `WAZUH_SERVER_API_MAX_RESOURCE_PAYLOAD_SIZE` | `50000` | Max payload size (bytes) for API resource requests |
| `WAZUH_SERVER_API_MAX_RESOURCE_KVDB_PAYLOAD_SIZE` | `100000` | Max payload size (bytes) for KVDB API requests |

With event processing disabled the engine opens no event socket (`engine-ingest-http.sock`); only the
API socket is served.

The engine raises its own soft file-descriptor limit to `8192` when it starts lower (there is no variable
for it), and needs the soft stack limit (`RLIMIT_STACK`) it inherits to be finite and at least `8 MiB`
(`infinity` does not qualify), as described in
[Process Limits](../../../docs/ref/modules/engine/configuration.md#process-limits).

### Log file and rotation

These variables mirror the Log4j2 rolling-file settings of wazuh-indexer (the engine implements rotation itself
in `source/base/src/logging.cpp`; the right column is the Log4j2 equivalent, not something the engine reads):

| Variable | Default | Log4j2 equivalent |
|---|---|---|
| `WAZUH_STANDALONE_LOG_FILE_PATH` | `/var/log/wazuh-indexer/wazuh-engine.log` when that directory exists, else `logs/wazuh-engine.log` in the package | `<RollingFile fileName="...">` |
| `WAZUH_STANDALONE_LOG_ROTATION_HOUR` | `0` (midnight) | `<TimeBasedTriggeringPolicy interval="1" modulate="true"/>` |
| `WAZUH_STANDALONE_LOG_ROTATION_MINUTE` | `0` | same as above |
| `WAZUH_STANDALONE_LOG_MAX_FILE_SIZE` | `134217728` (128 MB) | `<SizeBasedTriggeringPolicy size="128 MB"/>` |
| `WAZUH_STANDALONE_LOG_MAX_FILES` | `7` | `<DefaultRolloverStrategy max="7">` |
| `WAZUH_STANDALONE_LOG_MAX_ACCUMULATED_SIZE` | `2147483648` (2 GB) | `<IfAccumulatedFileSize exceeds="2 GB"/>` |

The following variables are custom extensions with no direct Log4j2 equivalent:

| Variable | Default | Description |
|---|---|---|
| `WAZUH_STANDALONE_LOG_ROTATION_ENABLED` | `true` | Enable/disable the entire log rotation subsystem |
| `WAZUH_STANDALONE_LOG_COMPRESSION_ENABLED` | `true` | Enable gzip compression of rotated files. Compression runs asynchronously; the active log file is never compressed |
| `WAZUH_STANDALONE_LOG_COMPRESSION_LEVEL` | `5` | zlib compression level: `0` = store only, `1` = fastest, `9` = maximum compression |

## License

The Wazuh engine is licensed under the GNU Affero General Public License, version 3 or (at your option) any later version. The bundle ships the notice in `COPYING-engine`, the full license text in `LICENSE-engine`, and the notices of the bundled third-party components in `THIRD-PARTY-NOTICES`.
