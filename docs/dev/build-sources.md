# Build from Sources

This guide describes how to build Wazuh components from source code.

## Prerequisites

Before building Wazuh from sources, ensure you have the required toolchain installed as described in the [Development Environment Setup](setup.md) guide.

## Build Server

To build the Wazuh server (manager) components, first install the dependencies, then compile:

```bash
make -C src TARGET=server deps
make -C src TARGET=server
```

### Build Options

You can customize the build with the following options:

```bash
make -C src TARGET=server DEBUG=1              # Build with debug symbols
make -C src TARGET=server TEST=1               # Build in testing mode
make -C src TARGET=server -j4                  # Parallel build with 4 jobs
make -C src TARGET=server INSTALLDIR=/custom   # Install to custom directory
```

## Build Agent for UNIX

To build the Wazuh agent for UNIX-like systems (Linux, macOS, BSD, etc.):

```bash
make -C src TARGET=agent deps
make -C src TARGET=agent
```

### Build Options

Similar to the server build, you can use:

```bash
make -C src TARGET=agent DEBUG=1               # Build with debug symbols
make -C src TARGET=agent TEST=1                # Build in testing mode
make -C src TARGET=agent -j4                   # Parallel build with 4 jobs
make -C src TARGET=agent INSTALLDIR=/custom    # Install to custom directory
```

## Build Agent for Windows

To build the Wazuh agent for Windows, you must first install the Windows build requirements (MinGW, Wine, CMocka) as described in the [setup guide](setup.md#windows-agent-build-requirements).

```bash
make -C src TARGET=winagent deps
make -C src TARGET=winagent
```

## Build Output

After a successful build, binaries are located in:

- **Server/Agent UNIX**: `src/` directory
- **Windows Agent**: `src/win32/` directory

## Clean Build

The build system provides several clean targets for different purposes:

```bash
make -C src clean                   # Clean all compiled code including external dependencies
make -C src clean-deps              # Clean external dependencies only
make -C src clean-internals         # Clean compiled code, but keep external dependencies
make -C src clean-windows           # Clean Windows resource files
```

**Clean target descriptions:**

- `clean` - Removes all build artifacts including external dependencies. Use this for a complete clean build.
- `clean-deps` - Removes only external dependencies (e.g., libraries downloaded during `make deps`).
- `clean-internals` - Removes compiled binaries and object files but preserves external dependencies. Useful for quick rebuilds.
- `clean-windows` - Removes Windows-specific compiled resource files.

## Troubleshooting

### Dependencies Not Found

If the build fails due to missing dependencies, ensure you've run the `deps` target first:

```bash
make -C src deps
```
