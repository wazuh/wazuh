# Development Environment Setup

This guide describes how to set up a development environment for Wazuh.

## Set up the toolchain

### Requirements

The recommended platform for development is **Ubuntu 24.04**.

The minimum toolchain requirements are:

- GNU C/C++ Compiler 13+ (CI and the package builders use GCC 14)
- GNU Make
- CMake 3.22.1+ (the engine refuses an older one, although the top-level project accepts 3.12.4)
- procps
- curl

Optional, for the agent only: `checkmodule` and `semodule_package`, which `src/Makefile` needs to build the
agent's SELinux policy. When either is missing the policy is skipped without an error; the manager build
never uses them.

For running the C unit tests (CMocka suites), CMocka is required, and the unit-test project refuses to
configure without `lcov`, `gcov` and `genhtml` (see [Test execution](test-execution.md)).

### Installation on Ubuntu 24.04

Install the required packages using apt:

```bash
apt install gcc g++ make cmake curl procps
apt install checkpolicy semodule-utils     # optional: agent SELinux policy
apt install libcmocka-dev lcov             # C unit tests
```

### Installation on Rocky Linux 9

Install the required packages and enable the GCC toolset:

```bash
dnf install make cmake gcc-toolset-13-gcc-c++ gcc-toolset-13-gcc procps
dnf install checkpolicy policycoreutils    # optional: agent SELinux policy
scl enable gcc-toolset-13 bash

# Install CMocka
dnf install dnf-plugins-core
dnf config-manager --enable crb
dnf install libcmocka-devel
```

### Windows Agent Build Requirements

To build the Windows agent, you need MinGW. A MinGW build of CMocka and Wine are only needed for the cross-compiled unit tests, not to build.

#### Installing MinGW and Wine on Ubuntu 24.04

```bash
apt install gcc-mingw-w64-i686 g++-mingw-w64-i686 wine32
```

#### Installing CMocka for MinGW

CMocka must be compiled from source for Windows cross-compilation:

```bash
git clone -b stable-1.1 https://git.cryptomilk.org/projects/cmocka.git
sed -Ei 's/(BUILD_SHARED_LIBS .+) ON/\1 OFF/' cmocka/DefineOptions.cmake
mkdir cmocka/build
cd cmocka/build
cmake -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc \
      -DCMAKE_C_LINK_EXECUTABLE=i686-w64-mingw32-ld \
      -DCMAKE_INSTALL_PREFIX=/usr/i686-w64-mingw32/ \
      -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_BUILD_TYPE=Release ..
make
make install
cd ../..
rm -r cmocka
```

## Set up IDE

We recommend using Visual Studio Code for Wazuh development.

### Recommended Extensions

Install the following VS Code extensions for optimal development experience:

- **C/C++** (ms-vscode.cpptools) - IntelliSense, debugging, and code browsing
- **C/C++ Extension Pack** (ms-vscode.cpptools-extension-pack) - Popular C++ extensions
- **GitLens** (eamodio.gitlens) - Enhanced Git capabilities and code history
- **CMake Tools** (ms-vscode.cmake-tools) - Extended CMake support
- **Makefile Tools** (ms-vscode.makefile-tools) - IntelliSense and build support for Makefiles
- **Remote - SSH** (ms-vscode-remote.remote-ssh) - Develop on remote machines via SSH
- **WSL** (ms-vscode-remote.remote-wsl) - Develop in Windows Subsystem for Linux (Windows only)

### Workspace Settings

The following workspace settings are recommended for consistency with Wazuh coding standards. Create or update `.vscode/settings.json`:

```json
{
    "files.autoSave": "afterDelay",
    "files.trimTrailingWhitespace": true,
    "files.insertFinalNewline": true,
    "files.trimFinalNewlines": true,
    "files.simpleDialog.enable": true,
    "editor.acceptSuggestionOnEnter": "off",
    "workbench.editor.enablePreview": false,
    "files.associations": {
        "wazuh-manager.conf": "xml",
        "ossec.conf": "xml",
        "agent.conf": "xml"
    },
    "terminal.integrated.allowChords": false,
    "terminal.integrated.scrollback": 100000,
    "editor.rulers": [80]
}
```

#### Key settings explained

- `files.trimTrailingWhitespace` - Removes trailing whitespace on save
- `files.insertFinalNewline` - Ensures files end with a newline
- `editor.rulers: [80]` - Shows a vertical line at 80 characters for line length guidance
- `terminal.integrated.scrollback: 100000` - Increases terminal history for long build outputs

### Build Tasks

Build tasks automate compilation from within VS Code. Create or update `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "build manager",
      "type": "shell",
      "command": "make",
      "args": ["TARGET=manager", "DEBUG=1", "-j4"],
      "options": {
        "cwd": "${workspaceFolder}/src"
      },
      "group": "build",
      "problemMatcher": ["$gcc"]
    },
    {
      "label": "build agent",
      "type": "shell",
      "command": "make",
      "args": ["TARGET=agent", "DEBUG=1", "-j4"],
      "options": {
        "cwd": "${workspaceFolder}/src"
      },
      "group": "build",
      "problemMatcher": ["$gcc"]
    },
    {
      "label": "build windows agent",
      "type": "shell",
      "command": "make",
      "args": ["TARGET=winagent", "-j4"],
      "options": {
        "cwd": "${workspaceFolder}/src"
      },
      "group": "build",
      "problemMatcher": ["$gcc"]
    }
  ]
}
```

**Running build tasks:**

- Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) and search for "Tasks: Run Task"
- Select the desired build task from the list
- Alternatively, press `Ctrl+Shift+B` to show all build tasks

**Task configuration notes:**

- `DEBUG=1` - Configures a `Debug` build (no optimization). Without it the build is `RelWithDebInfo`, which already carries symbols but is optimized. Like every Makefile flag it stays in the CMake cache: a later build without it is still `Debug` (see [Build from Sources](build-sources.md#build-options))
- `TARGET=manager` - The manager; `TARGET=server` is accepted as an alias and rewritten to `manager`, but `make server` (a goal, not a `TARGET`) stops with an error
- The three tasks share the single build tree, whose cache is `src/build/CMakeCache.txt`, and each target needs its own `make -C src deps TARGET=<target>` first; run `make -C src clean-internals` before switching `TARGET` so that no cached setting of the previous one carries over
- `-j4` - Enables parallel compilation with 4 jobs
- `problemMatcher: ["$gcc"]` - Parses compiler output to display errors in the Problems panel

### Debug Configurations

Debug configurations enable interactive debugging with GDB. Create or update `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug wazuh-manager-analysisd",
      "type": "cppdbg",
      "request": "launch",
      "program": "/var/wazuh-manager/bin/wazuh-manager-analysisd",
      "args": ["-f"],
      "stopAtEntry": false,
      "cwd": "${workspaceFolder}",
      "environment": [],
      "externalConsole": false,
      "MIMode": "gdb",
      "setupCommands": [
        {
          "description": "Enable pretty-printing for gdb",
          "text": "-enable-pretty-printing",
          "ignoreFailures": true
        }
      ],
      "preLaunchTask": "build manager",
      "miDebuggerPath": "/usr/bin/gdb"
    }
  ]
}
```

**Starting a debug session:**

1. Open the source file you want to debug
2. Set breakpoints by clicking to the left of line numbers
3. Press `F5` or go to Run - Start Debugging
4. Alternatively, open the Debug panel (`Ctrl+Shift+D`) and click the play button

**Debug configuration notes:**

- `program` - Path to the binary to debug
- `args` - Command-line arguments passed to the program
- `preLaunchTask` - Task to run before debugging (e.g., rebuild the binary)
- `stopAtEntry` - Set to `true` to pause at the program entry point
- Step-by-step debugging is reliable only on a `DEBUG=1` build; the default build is optimized

**Additional debug configurations:**

You can add more configurations for other Wazuh components:

```json
{
  "name": "Debug wazuh-manager-remoted",
  "type": "cppdbg",
  "request": "launch",
  "program": "/var/wazuh-manager/bin/wazuh-manager-remoted",
  "args": ["-f"],
  "preLaunchTask": "build manager",
  "MIMode": "gdb"
}
```

### Deployment After Building

The debug configurations above run the installed binaries, so a rebuilt binary has to be copied into the installation directory first. Build outputs land in `src/build/bin/` (daemons and CLIs) and `src/build/lib/` (shared libraries); the engine is built as `src/build/engine/wazuh-engine` and installed as `bin/wazuh-manager-analysisd`. You can automate the copy with an additional task:

```json
{
  "label": "deploy wazuh-manager-analysisd",
  "type": "shell",
  "command": "sudo",
  "args": ["cp", "build/engine/wazuh-engine", "/var/wazuh-manager/bin/wazuh-manager-analysisd"],
  "options": {
    "cwd": "${workspaceFolder}/src"
  },
  "dependsOn": ["build manager"]
}
```

Alternatively, link the `preLaunchTask` in your debug configuration to rebuild and deploy before each debug session.

When you copy a rebuilt daemon, copy the shared libraries of `src/build/lib/` into the installation's `lib/` too: a module library left from an older build is loaded by the new daemon at run time and can crash it.

## Troubleshooting

### Permission Denied When Debugging

If you encounter permission errors when debugging Wazuh binaries:

- Wazuh components often require root privileges
- Run VS Code as root: `sudo code --user-data-dir=/root/.vscode-root --no-sandbox`
- Or configure sudo to allow debugging without password prompts

### GDB Not Found

If GDB is not installed:

```bash
apt-get install gdb  # Ubuntu/Debian
yum install gdb      # Rocky Linux/RHEL
```

### Compilation Errors

Ensure all dependencies are installed and you're using the correct compiler version:

```bash
gcc --version  # Should be 13 or higher
```

### IntelliSense Not Working

If code completion isn't working:

1. Ensure the C/C++ extension is installed
2. Open the Command Palette (`Ctrl+Shift+P`)
3. Run "C/C++: Edit Configurations (JSON)"
4. Verify the `compilerPath` and `includePath` settings are correct
