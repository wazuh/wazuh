# file_helper — mockable filesystem and file-reading wrappers

Two static libraries that put the filesystem and file reading behind interfaces, so a module can be
unit-tested with GMock doubles instead of a real disk:

| CMake target | Namespace | Interfaces | Implementations |
|---|---|---|---|
| `FilesystemWrapper` | `file_system` | `IFileSystemWrapper` (thin `std::filesystem` and POSIX calls: `exists`, `is_directory`, `list_directory`, `rename`, `remove`, `open`, `flock`, …), `IFileSystemUtils` (`expand_absolute_path()`) | `FileSystemWrapper` (`filesystem_wrapper_unix.cpp` or `filesystem_wrapper_win.cpp`, chosen in `CMakeLists.txt`), `FileSystemUtils` |
| `FileIO` | `file_io` | `IFileIOWrapper` (thin `std::ifstream` calls), `IFileIOUtils` (`readLineByLine()`, `getFileContent()`, `getBinaryContent()`, `getRegularFileContent()`, `readRegularFileLineByLine()`) | `FileIOWrapper`, `FileIOUtils` |

What it is NOT: a file-watching or caching layer, and nothing in it logs. It is built for every
target (`src/CMakeLists.txt`), but its consumers are agent-side: `data_provider` (`sysinfo` and its
extended sources), `agent_info`, `sca`, `sync_protocol` and `utils/linuxInfoHelper.h`.

## Requirements

| # | Requirement | Where |
|---|---|---|
| RF-1 | `FileSystemUtils::expand_absolute_path()` expands `*` and `?` component by component and returns only paths that exist; a missing base directory or a file in its place matches nothing. A wildcard right under the root (`/x*`, `C:\x*`) lists the root. A wildcard with no separator before it (`*/a`, `dum*`) throws `std::runtime_error`. A matched name is never read as a pattern again, so entries named like `a*b` or `q?x` expand once. An entry whose `exists`/`is_directory`/`list_directory` raises a filesystem error (e.g. permission denied) is skipped and the other matches are still returned | `filesystem/src/filesystem_utils.cpp` |
| RF-2 | `FileIOUtils::getRegularFileContent()` and `readRegularFileLineByLine()` open the file first and check its type on the open descriptor, so the check applies to the file actually read. A named pipe is refused without blocking (`O_NONBLOCK` on open), anything that is not a regular file is `NotRegular`, and with `followSymlinks == false` a final symbolic link (on Windows, a junction or other name-redirecting reparse point) is `SymbolicLink`. Reading is in 64 KiB chunks, and lines split as `std::getline` splits them | `file_io/src/file_io_utils.cpp` |

## Design decisions

| # | Decision | Why |
|---|---|---|
| D1 | `expand_absolute_path()` returns only paths that exist, and a separator must precede the first wildcard | A literal path was returned unchecked, so `/a/*/missing` yielded one non-existent path per match, and `file/*` returned the file itself. The wildcard-at-position-0 branches could never run and are gone; the root case is handled by keeping the root separator. Expansion recurses on the unexpanded remainder with the expanded prefix carried apart, so a matched name holding `*` or `?` cannot loop; errors are caught inside the function rather than in `IFileSystemWrapper`, whose throwing `exists` other modules rely on. No caller uses the function yet, so its tests are its contract |

## Layout

| Path | Responsibility |
|---|---|
| `filesystem/include/` | `IFileSystemWrapper`, `IFileSystemUtils` and their implementations' headers |
| `filesystem/src/filesystem_wrapper{,_unix,_win}.cpp` | `FileSystemWrapper`: the portable calls, then the POSIX or Windows ones |
| `filesystem/src/filesystem_utils.cpp` | `FileSystemUtils::expand_absolute_path()` (RF-1) |
| `file_io/include/` | `IFileIOWrapper`, `IFileIOUtils` (with `RegularFileStatus`) and their implementations' headers |
| `file_io/src/file_io_wrapper.cpp`, `file_io/src/file_io_utils.cpp` | `FileIOWrapper`; `FileIOUtils` (RF-2) |
| `filesystem/tests/mocks/`, `file_io/tests/mocks/` | `mock_filesystem_wrapper.hpp`, `mock_filesystem_utils.hpp`, `mock_file_io_wrapper.hpp`, `mock_file_io_utils.hpp` |

## Consumer contract

- Link `FilesystemWrapper` and/or `FileIO`; each exports its own `include/` directory. Both are
  STATIC and position-independent, so they can go into a shared object.
- Depend on the interface, inject the implementation: `FileSystemUtils` and `FileIOUtils` take an
  optional `shared_ptr` to their wrapper and build the real one when it is null, so tests hand in a
  mock from `tests/mocks/`.
- Failure reporting differs per call: `readLineByLine()` throws `std::runtime_error("Could not open
  file")` when the file cannot be opened; `getFileContent()` and `getBinaryContent()` return an empty
  result instead; the two `Regular*` calls return a `RegularFileStatus` and never throw for an
  unreadable path (`readRegularFileLineByLine()` can return `OpenFailed` after lines were already passed
  to the callback, when the read fails part way).

## Tests

Both suites carry the ctest label `file_helper` and are built only in a `UNIT_TEST=ON` tree. CI:
`.github/workflows/5_testcomponent_shared_modules_file_helper-rtr.yml` (agent and Windows agent
targets).

| Test (ctest name) | Binary | Pins |
|---|---|---|
| `Filesystem` | `filesystem_unit_test` (`filesystem/tests/filesystem_utils_test.cpp`) | Wildcard expansion (`*`, `?`, prefix, suffix, under the root) over a mocked `IFileSystemWrapper`; a leading or relative wildcard throws; literal paths and expansions return only existing paths; a file in place of a directory matches nothing; entries named with `*`/`?` expand once; an entry that raises a filesystem error is skipped |
| `FileIO` | `file_io_unit_test` (`file_io/tests/file_io_utils_test.cpp`) | Over a mocked `IFileIOWrapper`: `readLineByLine()` passes each line to the callback and throws when the file cannot be opened; `getFileContent()`/`getBinaryContent()` return empty results on failure. On real files, the `Regular*` calls: a missing or unreadable path is `OpenFailed` (the unreadable case is skipped as root), a directory `NotRegular`, a named pipe is rejected without blocking, a symbolic link is followed or refused per `followSymlinks` (a dangling one is `OpenFailed` when followed), the line-by-line read stops when the callback asks, a line longer than a read chunk is kept whole, line endings are converted as in text mode, and an exception thrown while reading closes the file |
