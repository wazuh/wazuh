# Unit Tests

This document explains how to compile and run the Wazuh unit tests for the supported targets (Linux server/agent, Windows agent, macOS agent). The high-level flow is the same for every target:

1. Install the required toolchain and libraries (GCC 14, CMake, CMocka, and — for the Windows agent — MinGW and wine).
2. Fetch the external sources with `make TARGET=… deps`.
3. Compile Wazuh with `TEST=1` so internal symbols and test hooks are exposed.
4. Configure and build the unit-test binaries under `src/unit_tests` with CMake.
5. Run them — either all at once with `ctest`, with coverage via `make coverage`, or one binary at a time.

The sections below walk through each target end-to-end. The one appendix at the bottom covers cleanup when switching between targets.

> **Tip:** every `make` invocation in this document accepts `-j$(nproc)` to parallelize across all your CPU cores, which makes a big difference on the C++ link-heavy steps. For example: `make -j$(nproc) TARGET=agent TEST=1`.

## Index
1. [Requirements](#requirements)
2. [Compile and run unit tests for Linux targets](#compile-and-run-unit-tests-for-linux-targets)
3. [Compile and run unit tests for Windows agent](#compile-and-run-unit-tests-for-windows-agent)
4. [Compile and run unit tests for macOS agent](#compile-and-run-unit-tests-for-macos-agent)
5. [Appendix: Cleaning the environment before building a different target](#appendix-cleaning-the-environment-before-building-a-different-target)

## Requirements
1. **GCC 14** (`gcc-14` / `g++-14`) — required on Linux for all targets. On macOS the build uses Apple Clang from Xcode Command Line Tools (Apple Clang 16 on macos-15).
2. **MinGW** (`i686-w64-mingw32-gcc` / `g++-posix`) — required for the Windows agent.
3. **CMake** 3.22.1 or higher. Ubuntu 22.04+ and macOS Homebrew both ship a recent enough version by default.
4. **CMocka** (C unit testing framework). For Linux/macOS targets the distribution package is enough; for the Windows agent it must be cross-built with MinGW (step 0.2 of the [Windows agent section](#compile-and-run-unit-tests-for-windows-agent)).
5. **Wine** (32 bit) — required for the Windows agent.

### Installing dependencies on Ubuntu
Base packages (Linux server/agent + unit tests):
```
sudo apt-get update -y
sudo apt-get install -y \
    gcc-14 g++-14 \
    make cmake python3 libc6-dev \
    automake autoconf libtool \
    libcmocka-dev lcov
```

For the Windows agent there are additional packages (mingw, wine, a cross-compiled cmocka) — they're installed as part of step 0 in the [Windows agent section](#compile-and-run-unit-tests-for-windows-agent).

### Installing dependencies on macOS
Handled in step 0 of the [macOS agent section](#compile-and-run-unit-tests-for-macos-agent) — macOS prereqs are non-trivial (cmocka 1.1.7 from source rather than Homebrew, plus several env vars at build time) and live with the rest of that target's flow.

## Compile and run unit tests for Linux targets

### 0. Point the build at GCC 14
On a fresh Ubuntu install the unversioned `gcc`/`g++` typically resolve to an older GCC (13.x on Ubuntu 24.04) and `g++` may not even be installed — installing `gcc-14`/`g++-14` does **not** by itself change what `make`/CMake pick up. The `Makefile` honors `CC` and `CXX` from the environment, so export them in the shell where you run `make`:
```
export CC=gcc-14
export CXX=g++-14
```
Add the two `export` lines to your `~/.bashrc` if you want them to persist across sessions.

If you'd rather make GCC 14 the system default (e.g. on a VM dedicated to Wazuh dev) so you can drop the exports entirely, you can swap `gcc`/`g++` system-wide with `update-alternatives`:
```
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-14
```

### 1. Fetch the external dependencies
The repo only checks in `src/external/CMakeLists.txt`; OpenSSL, libcurl, audit-userspace, libplist, jemalloc, msgpack, sqlite, etc. are downloaded and extracted on demand. The exact list is target-dependent, so pass the same `TARGET=` you intend to build (one-time per checkout — re-run after `make clean-deps` or a fresh clone):
```
make TARGET=manager|agent deps
```

### 2. Compile Wazuh with the test flag
From `wazuh/src`:
```
make TARGET=manager|agent TEST=1
```

### 3. Build the unit tests
Navigate into `wazuh/src/unit_tests` and run:
```
mkdir build
cd build
cmake -DTARGET=manager|agent ..
make
```

### 4. Run the tests
There are several ways to run them:

#### Batch run
Run `ctest` inside the `build` directory to execute all tests and get a global result. For more detail, inspect `build/Testing/Temporary/LastTest.log` after the run.

#### Coverage run
Point cmake at the matching `gcov-14` before running `make coverage` (the default picks up the unversioned system gcov, which on Ubuntu 24.04 is 13.3 and can't read gcc-14's `.gcno` files):
```
cmake -DGCOV_PATH=$(which gcov-14) ..
make coverage
```
If all tests pass, a `coverage-report/` directory with an HTML report will be generated.

**Note:** To get more accurate coverage mapping on the report, you'll have to add the `DEBUG=1` flag to the `make TARGET=manager|agent` command, so that it compiles without optimizations. Note that this build configuration can take twice as long as the regular test build.

#### Running a specific test
Navigate into the subdirectory where the test resides and run the binary directly. For example, to run tests on `create_db.c`:
```
cd syscheckd
./test_create_db
```

## Compile and run unit tests for Windows agent

> **Note:** the Windows agent is **cross-compiled from a Linux host** — there is no native Windows build path. The MinGW toolchain (`i686-w64-mingw32-…`) produces Windows binaries on Linux, and the resulting `.exe` test binaries are executed under wine on the same Linux host. You don't need a Windows machine at any point.

### 0. Install winagent-specific prerequisites

#### 0.1 Install the MinGW toolchain
```
sudo apt-get install -y gcc-mingw-w64 g++-mingw-w64-i686 g++-mingw-w64-x86-64
```
Stock Ubuntu 24.04 ships GCC 13.2 in these packages, which is sufficient.

#### 0.2 Build cmocka cross-compiled for MinGW
Wazuh's `libwazuh_test.a` (built as part of `make TARGET=winagent TEST=1`) `#include <cmocka.h>` from the test wrappers, so the cmocka headers and a static `.a` must live under `/usr/i686-w64-mingw32/` before the compile step. Ubuntu doesn't package a mingw build of cmocka, so build it from source — pinned to the upstream `stable-1.1` branch (Wazuh's wrappers are written against the 1.1 API):

```
curl -L --retry 3 --retry-delay 2 \
    -o /tmp/cmocka-stable-1.1.tar.gz \
    https://git.cryptomilk.org/projects/cmocka.git/snapshot/stable-1.1.tar.gz
tar -zxf /tmp/cmocka-stable-1.1.tar.gz -C /tmp/
mkdir /tmp/stable-1.1/build && cd /tmp/stable-1.1/build
cmake -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc \
      -DCMAKE_C_LINK_EXECUTABLE=i686-w64-mingw32-ld \
      -DCMAKE_INSTALL_PREFIX=/usr/i686-w64-mingw32/ \
      -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DUNIT_TESTING=OFF \
      -DWITH_EXAMPLES=OFF \
      -DPICKY_DEVELOPER=OFF ..
make
sudo make install
```
After this, `/usr/i686-w64-mingw32/include/cmocka.h` and `/usr/i686-w64-mingw32/lib/libcmocka.a` should exist. The four `-D…=OFF` flags disable cmocka's shared-library build (we want the static `.a`), its own test suite, its examples, and some other things.

Forgetting this step surfaces as `fatal error: cmocka.h: No such file or directory` during the compile.

#### 0.3 Install wine
Wine is needed at **build time** (cmake invokes it as the cross-compile emulator for try-runs in externals — missing wine surfaces as *"compiled but failed to run"* or *"Failed to determine the source files for the regular expression backend"*) and at **test time** to execute the `.exe` binaries. The runtime configuration (`WINEPATH`/`WINEARCH`) is covered in step 3.

The install recipe matches is pinned to wine `10.0.0.0~noble-1`. On Ubuntu 24.04 (noble):

```
# Enable 32-bit packages (Wazuh's wine targets win32)
sudo dpkg --add-architecture i386

# Register WineHQ's signing key and noble repository
sudo mkdir -pm755 /etc/apt/keyrings
sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources

# Install wine + its 32-bit runtime deps
sudo apt-get update
sudo apt-get install -y --allow-downgrades \
    libc6:i386 libgcc-s1:i386 libstdc++6:i386 \
    wine-stable=10.0.0.0~noble-1 \
    wine-stable-i386=10.0.0.0~noble-1 \
    wine-stable-amd64=10.0.0.0~noble-1 \
    winehq-stable=10.0.0.0~noble-1

# Sanity check
wine --version
```

For other Ubuntu releases swap `noble` for the matching codename (`jammy` for 22.04, etc.) in both the `.sources` URL and the version-pin suffix; see the [WineHQ install guide](https://gitlab.winehq.org/wine/wine/-/wikis/Debian-Ubuntu) for the current list.

**Troubleshooting:** if a later `wine` invocation errors with *"wineserver: WINEARCH set to win32 but '/home/…/.wine' is a 64-bit installation"*, a previous `wine` run (possibly from another tool) created a 64-bit prefix at `~/.wine`. Wine can't downgrade a prefix from 64- to 32-bit, so move it aside and let wine create a fresh 32-bit one on the next run:
```
mv ~/.wine ~/.wine.bak
```

#### 0.4 Clear native `CC`/`CXX` before the cross-compile
If you've been doing Linux builds in this shell, you likely have `CC=gcc-14` and `CXX=g++-14` exported (per the [Pointing the build at GCC 14](#pointing-the-build-at-gcc-14) section). Those need to be **unset** before `make TARGET=winagent`

Just unset them and let the Makefile's defaults select the mingw cross-compiler:
```
unset CC CXX
```

### 1. Fetch the external dependencies
The repo only checks in `src/external/CMakeLists.txt`; OpenSSL, libcurl, audit-userspace, libplist, msgpack, sqlite, etc. are downloaded and extracted on demand. From `wazuh/src` (one-time per checkout — re-run after `make clean-deps` or a fresh clone):
```
make TARGET=winagent deps
```

### 2. Compile the Windows agent with the test flag
From `wazuh/src`:
```
make TARGET=winagent TEST=1
```

### 3. Build the unit tests
Navigate into `wazuh/src/unit_tests` and run:
```
mkdir build
cd build
cmake -DTARGET=winagent -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake ..
make
```
`CMAKE_TOOLCHAIN_FILE` configures CMake for cross-compilation.

### 4. Run the tests (via wine)
Wine needs two env vars before it can run the `.exe` test binaries:

- `WINEPATH` — **semicolon-separated, Windows-style** list of directories wine searches for DLLs at runtime. The test binaries need the mingw runtime (`libstdc++-6.dll`, `libgcc_s_*.dll`, `libwinpthread-1.dll`, etc.) and Wazuh's own built libraries (`libagent_metadata.dll`, `libwazuhext.dll`, etc., emitted under `src/build/bin/`).
- `WINEARCH=win32` — pins the wine prefix to 32-bit. Without it, the first run creates a 64-bit prefix at `~/.wine` and subsequent 32-bit runs fail (see the troubleshooting note at the end of step 0.3).

**Recommended:** scope both env vars to the test invocation so they apply only to the run and don't pollute your shell. From `wazuh/src/unit_tests/build`:
```
WAZUH_SRC=$(realpath ../..)
WINEARCH=win32 \
WINEPATH="/usr/i686-w64-mingw32/lib;/usr/lib/gcc/i686-w64-mingw32/13-posix;${WAZUH_SRC};${WAZUH_SRC}/build/bin" \
ctest --output-on-failure
```
`realpath ../..` derives the absolute path to `wazuh/src` on the fly, so you don't have to hardcode it.

**Alternative — persistent shell exports.** Add to `~/.bashrc`, substituting your wazuh checkout's absolute path for `<WAZUH_SRC>`:
```
export WINEARCH=win32
export WINEPATH="/usr/i686-w64-mingw32/lib;/usr/lib/gcc/i686-w64-mingw32/13-posix;<WAZUH_SRC>;<WAZUH_SRC>/build/bin"
```
The `13-posix` path matches the GCC 13.x mingw shipped by Ubuntu 24.04. On other distros run `ls /usr/lib/gcc/i686-w64-mingw32/` to find the right directory.

#### Batch run
Run `ctest` with the env above. CTest invokes wine on each test binary and displays the results; detailed output goes to `build/Testing/Temporary/LastTest.log`.

#### Coverage run
Winagent coverage needs a small gcov wrapper to bridge a version-string incompatibility between `i686-w64-mingw32-gcov-posix` and lcov 2.x — lcov reads `--version` from the gcov tool to decide compatibility, and mingw's gcov reports a string lcov rejects. Generate the wrapper alongside `unit_tests/build/`, point cmake at it, then run `make coverage` with the same wine env as the test run:

```
cat > winagent-gcov-wrapper.sh <<'EOF'
#!/bin/bash
if [[ "$1" == "-v" || "$1" == "--version" ]]; then
    echo "gcov (GCC) 10.3.0"
    echo "Copyright (C) 2020 Free Software Foundation, Inc."
    echo "This is free software; see the source for copying conditions."
    exit 0
fi
exec /usr/bin/i686-w64-mingw32-gcov-posix "$@"
EOF
chmod +x winagent-gcov-wrapper.sh

cmake -DGCOV_PATH=$PWD/winagent-gcov-wrapper.sh ..

WAZUH_SRC=$(realpath ../..)
WINEARCH=win32 \
WINEPATH="/usr/i686-w64-mingw32/lib;/usr/lib/gcc/i686-w64-mingw32/13-posix;${WAZUH_SRC};${WAZUH_SRC}/build/bin" \
make coverage
```
The wrapper intercepts `--version` queries from lcov and reports a known-compatible string; every other invocation passes through to the real mingw gcov. `.github/actions/legacy_unit_tests.sh` generates the same wrapper inline in CI. If `make coverage` succeeds, the HTML report lands under `coverage-report/`.

**Note:** To get more accurate coverage mapping on the report, you'll have to add the `DEBUG=1` flag to the `make TARGET=agent` command, so that it compiles without optimizations. Note that this build configuration can take twice as long as the regular test build.

#### Running a specific test
Useful for iterating on a single failure. From `wazuh/src/unit_tests/build`:
```
WAZUH_SRC=$(realpath ../..)
WINEARCH=win32 \
WINEPATH="/usr/i686-w64-mingw32/lib;/usr/lib/gcc/i686-w64-mingw32/13-posix;${WAZUH_SRC};${WAZUH_SRC}/build/bin" \
wine ./client-agent/test_start_agent.exe
```

## Compile and run unit tests for macOS agent

### 0. Install prerequisites
**Homebrew** (if not already installed):
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**lcov** (CMake is pre-installed on the macos-15 runner / via Xcode Command Line Tools):
```
brew install lcov
```

**CMocka 1.1.7 from source.** Wazuh's test wrappers are written against the cmocka 1.1 API. Homebrew's current `cmocka` formula is newer and not what CI builds against, so install 1.1.7 directly.
```
curl -LO https://cmocka.org/files/1.1/cmocka-1.1.7.tar.xz
tar -xf cmocka-1.1.7.tar.xz
cd cmocka-1.1.7
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make -j$(sysctl -n hw.ncpu)
sudo make install
```
Headers land at `/usr/local/include/cmocka.h`, the static lib at `/usr/local/lib/libcmocka.a`.

### 1. Fetch the external dependencies
The repo only checks in `src/external/CMakeLists.txt`; OpenSSL, libcurl, msgpack, sqlite, etc. are downloaded and extracted on demand. From `wazuh/src` (one-time per checkout — re-run after `make clean-deps` or a fresh clone):
```
make TARGET=agent deps
```

### 2. Compile Wazuh with the test flag
Set the env vars and run from `wazuh/src`. There's no separate "build the unit tests" step — `make TARGET=agent TEST=1` produces the test binaries in `src/build/` alongside the main wazuh build:

```
export CMAKE_POLICY_VERSION_MINIMUM=3.5
export C_INCLUDE_PATH="$C_INCLUDE_PATH:$(brew --prefix)/include"
export LIBRARY_PATH="/usr/local/lib:$(brew --prefix)/lib"
make TARGET=agent TEST=1
```

What each env var does:
- `CMAKE_POLICY_VERSION_MINIMUM=3.5` — the macos-15 runner (and Homebrew on a fresh user box) ships cmake 4.x, which refuses to honor vendored externals declaring `cmake_minimum_required(VERSION 2.8)` (notably googletest). This var tells cmake to behave as if every project declared at least 3.5.
- `C_INCLUDE_PATH=$(brew --prefix)/include` — adds Homebrew's include dir to clang's system header search. `brew --prefix` resolves to `/opt/homebrew` on Apple Silicon and `/usr/local` on Intel, so the same line works on both archs.
- `LIBRARY_PATH=/usr/local/lib:$(brew --prefix)/lib` — `/usr/local/lib` for the cmocka you just installed there; `$(brew --prefix)/lib` for everything else brew installs (on Apple Silicon these are different directories; on Intel they're the same `/usr/local/lib` and the duplicate is harmless).

### 3. Run the tests
The test binaries are under `src/build/`. From `wazuh/src`:
```
export DYLD_LIBRARY_PATH="/usr/local/lib:$DYLD_LIBRARY_PATH"
cd build
ctest -V
```
`DYLD_LIBRARY_PATH` is the Apple equivalent of Linux's `LD_LIBRARY_PATH` — Apple's runtime linker needs to find cmocka's dylib at test execution time.

#### Running a specific test
Test binaries live under `src/build/<module>/`. For example:
```
cd src/build
export DYLD_LIBRARY_PATH="/usr/local/lib:$DYLD_LIBRARY_PATH"
./shared/test_url    # or wherever the binary you care about lives
```

## Appendix: Cleaning the environment before building a different target
Build artifacts produced by `make TARGET=…` are not interchangeable across targets. Three things go stale when you switch (e.g. agent → winagent or agent → server) and will cause confusing link errors or compiler-mismatch problems if you don't wipe them first:

Run these from `src/` before starting the per-target steps for the new target:
```
make clean        # build/, unit_tests/build*, generated headers, *.gcda/*.gcno, autotools distclean
make clean-deps   # external/* sources + tarballs (no TARGET needed — wipes the superset)
```

Then start the new target's per-target section from step 1 (fetch external dependencies).

