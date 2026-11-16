# Optional zstd compression for Wazuh 4

Base: Wazuh `4.14.13`, commit `8b6c19e1e623aabff26603e3ea46e9aaa8e8c0fd`
(`VERSION.json`: 4.14.13 alpha0). Upstream `main` and `master` are v5;
this implementation targets the latest v4 branch available at development time.

Add this setting inside the existing `<global>` section of `etc/ossec.conf`:

```xml
<compression_method>zstd</compression_method>
```

Accepted values are `gzip` and `zstd` (case sensitive). Omitting the setting
preserves gzip. Restart the manager after changing it. Invalid values fail
configuration validation. The selected method is also reported by monitord
and analysisd global configuration inspection.

The setting applies to daily compression of rotated alert and archive `.log`
and `.json` files, including numbered rotations. zstd outputs use `.zst` and
the library's default compression level (3). Active files, checksums, firewall
logs, agent logs, and internal manager log rotation retain their existing behavior.
`monitord.compress=0` in `local_internal_options.conf` still disables compression.

The zstd compressor streams bounded buffers into a private temporary file,
publishes it without replacing an existing archive, and only then removes the
source. Read, write, close, and publication failures preserve the source and
remove temporary output. Old `.gz` files remain readable after selecting zstd;
downstream consumers of compressed archives need to support `.zst` explicitly.

## Build and test

From the repository root, using Docker Desktop in Linux container mode:

```powershell
docker build -f tests/compression/Dockerfile -t wazuh-v4-zstd .
```

The Dockerfile builds manager binaries and runs both test scripts. It uses
Ubuntu 22.04 amd64 when built on an amd64 machine. For manual builds, install
the packages listed there, then:

```sh
make -C src TARGET=server deps -j4
make -C src TARGET=server -j4
cd src
make TARGET=server -f Makefile -f ../tests/compression/Makefile compression-test-driver -j4
cd ..
python3 tests/compression/test_docker.py
python3 tests/compression/test_daemon.py
```

The build downloads zstd 1.5.7 from its official release, verifies SHA-256,
and links its static library into `wazuh-monitord`. No zstd shared library is
required on the destination. Existing Wazuh build dependencies are unchanged.

`test_docker.py` exercises the production configuration reader and daily
compression functions, verifies exact round trips for empty, repetitive, and
random binary content, checks default/explicit gzip, disabled compression,
invalid settings, destination collisions, and write failures.

`test_daemon.py` starts the real foreground daemon with a Unix queue and a
temporary manager directory. libfaketime advances its clock across midnight;
both gzip and zstd must compress all twelve alert/archive rotation fixtures
and produce exact decompressed content. It does not modify the host clock.
