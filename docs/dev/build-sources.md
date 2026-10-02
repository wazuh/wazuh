# Build from Sources

This guide describes how to build Wazuh components from source code.

## Prerequisites

Before building Wazuh from sources, ensure you have the required toolchain installed as described in the [Development Environment Setup](setup.md) guide.

## Build the manager

To build the Wazuh manager, first fetch the dependencies, then compile:

```bash
make -C src TARGET=manager deps
make -C src TARGET=manager
```

`deps` downloads the external libraries and, for the manager, the indexer templates, the WCS flat file and `wazuh-credentials.sh`, which the installer needs. Downloads are never refreshed until `make -C src clean-deps`.

`TARGET=server` is accepted as an alias and rewritten to `manager`. Running `make server`, `make agent` or `make winagent` as a goal (without `TARGET=`) stops with an error, and `make -C src` with no `TARGET` only prints the usage.

### Build Options

You can customize the build with the following options:

```bash
make -C src TARGET=manager DEBUG=1              # Debug build type (no optimization); the default is RelWithDebInfo
make -C src TARGET=manager TEST=1               # Unit-test build: test targets, no daemon executables
make -C src TARGET=manager ENGINE_TEST=1        # Also build the engine tests and benchmarks
make -C src TARGET=manager -j4                  # Parallel build with 4 jobs
```

Boolean flags accept only `YES`, `yes`, `y`, `Y` and `1`; any other value (`TEST=on`, `DEBUG=true`) is silently ignored. Once passed, a flag stays in the CMake cache (`src/build/CMakeCache.txt`): a later plain `make -C src TARGET=manager` still builds with it until the tree is reconfigured with the option set to `OFF` or `make -C src clean-internals` removes the tree. `TEST` and `ENGINE_TEST` do not combine: with any `TEST` value set, `ENGINE_TEST` is skipped with a warning.

`INSTALLDIR` does not choose where `install.sh` installs (that is `USER_DIR`, see [Run from Sources](run-sources.md)); the Makefile uses it only to build the embedded Python interpreter from sources (`PYTHON_SOURCE=yes`).

The engine requires CMake 3.22.1 or newer. `src/` compiles as C++20 and `src/engine/` as C++17.

## Build Agent for UNIX

To build the Wazuh agent for UNIX-like systems (Linux, macOS, BSD, etc.):

```bash
make -C src TARGET=agent deps
make -C src TARGET=agent
```

### Build Options

Similar to the manager build, you can use:

```bash
make -C src TARGET=agent DEBUG=1               # Debug build type (no optimization)
make -C src TARGET=agent TEST=1                # Unit-test build
make -C src TARGET=agent -j4                   # Parallel build with 4 jobs
```

## Build Agent for Windows

To build the Wazuh agent for Windows, you must first install the Windows build requirements (MinGW, Wine, CMocka) as described in the [setup guide](setup.md#windows-agent-build-requirements).

```bash
make -C src TARGET=winagent deps
make -C src TARGET=winagent
```

### Build Options

```bash
make -C src TARGET=winagent IMAGE_TRUST_CHECKS=2   # Module signature verification: 0 disabled, 1 warn (default), 2 enforce
make -C src TARGET=winagent CA_NAME="My Root CA"   # Root CA the verification requires (default: Microsoft Identity Verification Root Certificate Authority 2020)
```

See [Module signature verification](package-generation.md#windows-agent-package).

## Build Output

After a successful build, the artifacts are located in the single CMake build tree under `src/`:

- **Executables** (daemons, CLIs, Windows `.exe` files): `src/build/bin/`
- **Shared libraries** (`libwazuhshared`, `libwazuhext`, module libraries): `src/build/lib/`
- **Engine**: `src/build/engine/wazuh-engine`, installed on the manager as `bin/wazuh-manager-analysisd`
- **Windows agent**: besides the executables in `src/build/bin/`, `make TARGET=winagent` writes the configuration files the MSI packs (`default-ossec.conf`, `internal_options.conf`, `help_win.txt`, …) into `src/win32/`

## Clean Build

The build system provides several clean targets for different purposes:

```bash
make -C src clean                   # Clean all compiled code including external dependency builds
make -C src clean-deps              # Remove the fetched external dependencies
make -C src clean-internals         # Clean compiled code, but keep external dependencies
make -C src clean-windows           # Remove the Windows agent configuration files
make -C src clean-test              # Remove coverage data (*.gcno, *.gcda, coverage-report/)
```

**Clean target descriptions:**

- `clean` - Runs `clean-test`, `clean-internals`, `clean-windows`, the framework clean and the clean of every external dependency's *build* artifacts, but keeps the fetched external sources under `external/`. Use `clean-deps` too for a complete clean build.
- `clean-deps` - Removes everything under `external/` except its tracked `CMakeLists.txt`, the contents of the `shared_modules/http-request` submodule directory and the downloaded WCS flat files, whatever `TARGET` is given.
- `clean-internals` - Removes the build tree (`src/build/*`), `unit_tests/build*`, the generated FlatBuffers headers and the SELinux policy build outputs, and preserves external dependencies. Useful for clearing flags cached in the build tree.
- `clean-windows` - Removes the configuration files `make TARGET=winagent` generates in `src/win32/`.
- `clean-test` - Removes coverage data, which goes stale when the build flags change.

## Troubleshooting

### Dependencies Not Found

If the build fails due to missing dependencies, ensure you've run the `deps` target first, with the same `TARGET` you build (the downloaded set depends on it):

```bash
make -C src deps TARGET=manager
```
