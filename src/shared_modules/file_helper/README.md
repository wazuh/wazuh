# file_helper — mockable filesystem and file-reading wrappers

Two small static libraries that put the filesystem and file reading behind interfaces, so a module can
be unit-tested with GMock doubles instead of a real disk:

| Target | Namespace / class | Interface | Sources |
|---|---|---|---|
| `FilesystemWrapper` | `file_system::FileSystemWrapper` (thin forwarding to `std::filesystem` and POSIX `open`/`flock`/`close`), `file_system::FileSystemUtils` (wildcard expansion) | `IFileSystemWrapper`, `IFileSystemUtils` | `filesystem/src/` — `filesystem_wrapper_unix.cpp` or `filesystem_wrapper_win.cpp` by platform |
| `FileIO` | `file_io::FileIOWrapper` (stream primitives), `file_io::FileIOUtils` (whole-file and line reads) | `IFileIOWrapper`, `IFileIOUtils` | `file_io/src/` |

Both are `STATIC` with position-independent code, C++17 (`CMAKE_CXX_STANDARD 17` in `CMakeLists.txt`),
and export their `include/` directory publicly. `FilesystemWrapper` also reads `globHelper.h` from
[utils](../utils/README.md) through a `PRIVATE` include path (`filesystem/src/filesystem_utils.cpp`).

**Built by every target, used by the agent.** `src/CMakeLists.txt` adds this directory among the
"Common modules (all targets)", and adds both `include/` directories to the whole tree's include path, so
a manager build compiles both archives. On the manager nothing ships with them: `FileIO` is linked only
into `utils_utest` (`src/shared_modules/utils/tests/CMakeLists.txt`, for `linuxInfoHelper.h`) and
`FilesystemWrapper` into nothing. The consumers are agent-side: data_provider (`sysinfo`, the `users`
extended source and their tests), sync_protocol (`agent_sync_protocol`), SCA (`sca_impl`) and agent_info.

There is no operator page: nothing here is configured or observed at run time.

## Requirements

| # | Requirement | Where |
|---|---|---|
| RF-1 | Every operation a consumer needs from the filesystem — existence and type checks (`exists`, `is_directory`, `is_regular_file`, `is_socket`, `is_symlink`, `is_absolute`), `canonical`, `remove`/`remove_all`, `create_directories`, `rename`, `list_directory`, `temp_directory_path`, and the descriptor calls `open`/`flock`/`close` — is a virtual method of `IFileSystemWrapper` | `filesystem/include/ifilesystem_wrapper.hpp` |
| RF-2 | `FileSystemUtils::expand_absolute_path()` expands `*` and `?` component by component (recursing into each matching directory entry, matched with `Utils::patternMatch`) and appends to a `std::deque` only paths that exist: a path without a wildcard is appended only if it exists, and a base directory that is missing or is a file matches nothing. A wildcard in the component right under the root (`/x*`, `C:\x*`) lists the root. A path with a wildcard and no separator before it (one starting with a wildcard, or relative) throws `std::runtime_error` | `filesystem/src/filesystem_utils.cpp` |
| RF-3 | `FileIOUtils` reads a file line by line (`readLineByLine`, the callback can stop it), as text (`getFileContent`, empty on failure) or as bytes (`getBinaryContent`, empty on failure) | `file_io/include/ifile_io_utils.hpp`, `file_io/src/file_io_utils.cpp` |
| RF-4 | `getRegularFileContent()` and `readRegularFileLineByLine()` read a file **only if it is a regular file**: the type is checked on the opened descriptor or handle (so on the file actually read), opening never waits for a writer (a named pipe is rejected, not blocked on), and with `followSymlinks == false` a final symbolic link — on Windows also a junction or other name-redirecting reparse point — is refused. The outcome is a `RegularFileStatus` (`Read`, `NotRegular`, `OpenFailed`, `SymbolicLink`) | `file_io/include/ifile_io_utils.hpp`, `file_io/src/file_io_utils.cpp` |
| RF-5 | `readRegularFileLineByLine()` reads in chunks, so memory does not grow with the file; lines are split as `std::getline` splits them; `OpenFailed` can follow lines already delivered when a read fails part way | `file_io/include/ifile_io_utils.hpp` |
| RF-6 | Every concrete class takes its lower layer as an optional `shared_ptr` (`FileSystemUtils(IFileSystemWrapper)`, `FileIOUtils(IFileIOWrapper)`; `nullptr` builds the real one), and GMock doubles of all four interfaces ship in `filesystem/tests/mocks/` and `file_io/tests/mocks/` for consumers' tests | `filesystem/include/filesystem_utils.hpp`, `file_io/include/file_io_utils.hpp` |
| RNF-1 | Builds for Linux, macOS and Windows (`filesystem_wrapper_win.cpp`; the `_WIN32` branch of `file_io_utils.cpp`) | `CMakeLists.txt` |

## Design decisions

| # | Decision | Why |
|---|---|---|
| D1 | Open once, then check the type on the open file, with `O_NONBLOCK` (plus `O_NOFOLLOW` when links are not followed) on POSIX | SCA file and directory rules used to check the type of a path and then reopen it with `std::ifstream`: a named pipe in a scanned directory made the open wait for a writer, stopping that scan and every later one, and the checks were not made on the file actually read (commit that added `getRegularFileContent`) |
| D2 | A link found on open is its own status (`SymbolicLink`), and on Windows junctions and other name-redirecting reparse points count as links | On Windows the directory rules' earlier link check never saw links, so a link target's content was read; reporting the link on open gives the same result on every platform. Name-keeping reparse points (compressed or deduplicated files) are still read through their filter (commits that added and extended the status) |
| D3 | A chunked line reader and one shared reader that owns the descriptor or handle from the moment it is opened | Exact-line rules read and copied the whole file before matching, so memory grew with file size; streaming stops at the first match. Owning the descriptor means an exception while the content is stored or passed on no longer leaks it (commit that added `readRegularFileLineByLine`) |
| D4 | On Windows the "same file after reopening through the filter" check compares the 128-bit `FILE_ID_INFO`, falling back to the 64-bit index only when it is not the all-ones value | ReFS reports all-ones for files without a unique 64-bit identifier; `FILE_ID_INFO` exists from Windows 8, so only the declarations depend on the target version (same commit; comment at the top of `file_io/src/file_io_utils.cpp`) |
| D5 | `expand_absolute_path()` returns only paths that exist, and a pattern must start with a separator | A literal path used to be returned unchecked, so a fixed suffix after a wildcard (`/a/*/missing`) produced one non-existent path per match, and a file in place of a directory matched its whole path against the pattern (`file/*` returned the file). The branches meant for a wildcard at position 0 could never run (no separator precedes it, so it always threw) and are gone; the root case they described is handled by keeping the root separator in the base directory. No caller in the tree uses the function, so its tests are its contract (`filesystem/tests/filesystem_utils_test.cpp`) |

## Layout

| Path | Content |
|---|---|
| `CMakeLists.txt` | The two targets; the tests under `UNIT_TEST` |
| `filesystem/include/` | `ifilesystem_wrapper.hpp`, `ifilesystem_utils.hpp`, `filesystem_wrapper.hpp`, `filesystem_utils.hpp` |
| `filesystem/src/` | `filesystem_wrapper.cpp`, `filesystem_wrapper_unix.cpp`, `filesystem_wrapper_win.cpp`, `filesystem_utils.cpp` |
| `file_io/include/` | `ifile_io_wrapper.hpp`, `ifile_io_utils.hpp` (also `RegularFileStatus`), `file_io_wrapper.hpp`, `file_io_utils.hpp` |
| `file_io/src/` | `file_io_wrapper.cpp`, `file_io_utils.cpp` |
| `*/tests/` | The unit tests and the `mocks/` consumers include |

## Tests and CI

| Test (ctest name) | Binary | Pins |
|---|---|---|
| `Filesystem` | `filesystem_unit_test` (`filesystem/tests/filesystem_utils_test.cpp`) | Wildcard expansion (`*`, `?`, prefix, suffix, under the root) over a mocked `IFileSystemWrapper`; a leading or relative wildcard throws; literal paths and expansions return only existing paths; a file in place of a directory matches nothing |
| `FileIO` | `file_io_unit_test` (`file_io/tests/file_io_utils_test.cpp`) | The stream reads over a mocked `IFileIOWrapper`; on real files the regular-file contract — directories, missing files, symlinks followed or refused, dangling links, named pipes rejected without blocking, line splitting and chunk boundaries, text-mode line endings, the file closed when the callback throws. `UnreadableFileFailsToOpen` skips as root |

Both carry the ctest label `file_helper` and are registered whenever `UNIT_TEST` is on — a manager test
tree builds them too — but **only agent lanes run them**:

- `.github/workflows/5_testcomponent_shared_modules_file_helper-rtr.yml` runs
  `python build.py --readytoreview shared_modules/file_helper` for `agent` and `winagent` (tests, coverage,
  style). Coverage is skipped for `winagent` (`src/ci/run_check.py`), and the valgrind step runs only
  binaries whose name starts with the module name, so it finds none here and only warns.
- The lanes of its consumers re-run with it, since their `paths:` list this tree:
  `.github/workflows/5_testcomponent_sync_protocol-rtr.yml`, `.github/workflows/5_testcomponent_syscollector-rtr.yml`,
  `.github/workflows/5_testcomponent_sca-rtr.yml`, `.github/workflows/5_testcomponent_agent_info-rtr.yml`.
- `.github/workflows/5_testunit_shared_modules_utils.yml` (manager) lists `CMakeLists.txt`,
  `file_io/include/**` and `file_io/src/**` because `utils_utest` links `FileIO`; it does not run the
  `file_helper` label.

From `src/`, in a tree configured with `UNIT_TEST=ON` (see the `wazuh-testing` skill):

```bash
cmake --build build -j --target filesystem_unit_test file_io_unit_test
ctest --test-dir build -L file_helper --output-on-failure
```

## License

This directory is **not** in the SPDX scope of `.github/scripts/spdx_scope.py` (its dual-licensed
directories are `utils`, `manager_config`, `keystore`, `indexer_connector` and `common`), its sources carry
no licence header, and it has no `COPYING` of its own — the dual-licence notice of its neighbours does not cover it, and the SPDX lane does not check it.
