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

`deps` downloads the external libraries pinned in `src/deps.lock.mk` (see [Build External Dependencies](build-external-dependencies.md)), the `shared_modules/http-request` sources when that submodule directory is empty, the indexer templates and, for the manager, also its own indexer templates and the WCS flat file. The templates and the WCS file are looked up in the upstream repositories under this checkout's branch or tag first, then under the branch named after the version in `VERSION.json`, `main` (version 5.0.0 only) and the `v<version>` tag (`tools/get_git_refs.sh`; `GIT_REFS="<ref> ..."` overrides the list). Downloads are never refreshed until `make -C src clean-deps`.

`TARGET=server` is accepted as an alias and rewritten to `manager`. Running `make server`, `make agent` or `make winagent` as a goal (without `TARGET=`) stops with an error, and `make -C src` with no `TARGET` only prints the usage and exits 0, having built nothing.

### Build Options

You can customize the build with the following options:

```bash
make -C src TARGET=manager DEBUG=1              # Debug build type (no optimization); the default is RelWithDebInfo
make -C src TARGET=manager TEST=1               # Unit-test build: test targets, no daemon executables
make -C src TARGET=manager ENGINE_TEST=1        # Also build the engine tests and benchmarks
make -C src TARGET=manager DEBUG=1 FSANITIZE=1  # AddressSanitizer, LeakSanitizer and UBSan on the C++ code (TSANITIZE=1: ThreadSanitizer)
make -C src TARGET=manager -j4                  # Parallel build with 4 jobs
```

Boolean flags accept only `YES`, `yes`, `y`, `Y` and `1`; any other value (`TEST=on`, `DEBUG=true`) is silently ignored. Once passed, a flag stays in the CMake cache (`src/build/CMakeCache.txt`): a later plain `make -C src TARGET=manager` still builds with it until the tree is reconfigured with the option set to `OFF` or `make -C src clean-internals` removes the tree. This holds for `TEST`, `ENGINE_TEST`, `DEBUG`, `FSANITIZE`, `TSANITIZE` and `DISABLE_JEMALLOC`.

- `TEST` and `ENGINE_TEST` do not combine: with any `TEST` value set, `ENGINE_TEST` is skipped with the warning `TEST is defined; skipping CMake engine test option`. A `TEST=1` build still builds the engine tests, but with AddressSanitizer forced on; use `ENGINE_TEST=1` alone for engine work.
- `FSANITIZE` and `TSANITIZE` change only the `Debug` C++ flags, so they have no effect without `DEBUG=1`, and C code is never instrumented. They are mutually exclusive.
- `DISABLE_JEMALLOC=yes` only stops the daemons from linking jemalloc; the library is still fetched and built.

`INSTALLDIR` does not choose where `install.sh` installs (that is `USER_DIR`, see [Run from Sources](run-sources.md)); the Makefile uses it only for the embedded Python interpreter: the `wpython` goal that `install.sh` runs installs it under `<INSTALLDIR>/framework/python`, and `build_python` (building it from sources) refuses to run without it.

The engine requires CMake 3.22.1 or newer (`cmake_minimum_required(VERSION 3.22.1 FATAL_ERROR)` in `src/engine/CMakeLists.txt`); the top-level project accepts 3.12.4, so an older CMake fails only once it reaches the engine. `src/` compiles as C++20 and `src/engine/` as C++17, as do several manager libraries that set it themselves (grep `CXX_STANDARD`).

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

To build the Wazuh agent for Windows, you must first install the MinGW cross-compiler as described in the [setup guide](setup.md#windows-agent-build-requirements) (Wine and a MinGW build of CMocka are needed only for its unit tests).

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
- **Shared libraries** (`libwazuhext`, module libraries): `src/build/lib/`
- **Engine**: `src/build/engine/wazuh-engine`, installed on the manager as `bin/wazuh-manager-analysisd`
- **Windows agent**: besides the executables in `src/build/bin/`, `make TARGET=winagent` writes the configuration files the MSI packs (`default-ossec.conf`, `internal_options.conf`, `help_win.txt`, …) into `src/win32/`

These locations are fixed: the daemons, the CLIs, `libwazuh*.a` and `libwazuhext` go to `src/build/bin/` and `src/build/lib/` even when you configure another build directory with `cmake -B`, and `install.sh` installs only from there. A second build directory for another set of flags therefore overwrites part of the first one; switch flags in place instead (see [Build Options](#build-options)).

A unit-test build (`TEST=1`, or `-DUNIT_TEST=ON`) defines no daemon executables (`wazuh-manager-db`, `-remoted`, `-authd`, `-modulesd`, `-keystore`): `No rule to make target` for one of them means the cached `UNIT_TEST=ON`, not your change. The engine, `wazuh-manager-conf` and `wazuh-manager-certs` are built in every mode.

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

- `clean` - Runs `clean-test`, `clean-internals`, `clean-windows`, the framework clean, `clean-config` (`etc/wazuh.mc` and `src/Config.OS`) and `clean-external`, which cleans every external dependency's *build* artifacts but keeps the fetched external sources under `external/`. Use `clean-deps` too for a complete clean build.
- `clean-deps` - Removes everything under `external/` except its tracked `CMakeLists.txt` and `.gitignore`, the contents of the `shared_modules/http-request` submodule directory (a checked-out submodule loses its `.git` file too: run `git submodule update --init` again) and the downloaded WCS flat files, whatever `TARGET` is given.
- `clean-internals` - Removes the whole build tree (`src/build/*`), `src/unit_tests/build*`, the generated FlatBuffers headers and the SELinux policy build outputs, and preserves external dependencies. Useful for clearing flags cached in the build tree.
- `clean-windows` - Removes the configuration files `make TARGET=winagent` generates in `src/win32/`.
- `clean-test` - Removes coverage data, which goes stale when the build flags change.

## Troubleshooting

### Dependencies Not Found

If the build fails due to missing dependencies, ensure you've run the `deps` target first, with the same `TARGET` you build (the downloaded set depends on it):

```bash
make -C src deps TARGET=manager
```
