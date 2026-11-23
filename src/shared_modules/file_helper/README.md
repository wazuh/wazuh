# file_helper — mockable filesystem and file-reading wrappers

Static libraries that put the filesystem and file reading behind interfaces, so a module can be
unit-tested with GMock doubles instead of a real disk. This page documents `FileSystemUtils`
(`file_system` namespace, `IFileSystemUtils`), implemented in `filesystem/src/filesystem_utils.cpp`.

## Requirements

| # | Requirement | Where |
|---|---|---|
| RF-1 | `FileSystemUtils::expand_absolute_path()` expands `*` and `?` component by component and returns only paths that exist; a missing base directory or a file in its place matches nothing. A wildcard right under the root (`/x*`, `C:\x*`) lists the root. A wildcard with no separator before it (`*/a`, `dum*`) throws `std::runtime_error`. A matched name is never read as a pattern again, so entries named like `a*b` or `q?x` expand once. An entry whose `exists`/`is_directory`/`list_directory` raises a filesystem error (e.g. permission denied) is skipped and the other matches are still returned | `filesystem/src/filesystem_utils.cpp` |

## Design decisions

| # | Decision | Why |
|---|---|---|
| D1 | `expand_absolute_path()` returns only paths that exist, and a separator must precede the first wildcard | A literal path was returned unchecked, so `/a/*/missing` yielded one non-existent path per match, and `file/*` returned the file itself. The wildcard-at-position-0 branches could never run and are gone; the root case is handled by keeping the root separator. Expansion recurses on the unexpanded remainder with the expanded prefix carried apart, so a matched name holding `*` or `?` cannot loop; errors are caught inside the function rather than in `IFileSystemWrapper`, whose throwing `exists` other modules rely on. No caller uses the function yet, so its tests are its contract |

## Tests

| Test (ctest name) | Binary | Pins |
|---|---|---|
| `Filesystem` | `filesystem_unit_test` (`filesystem/tests/filesystem_utils_test.cpp`) | Wildcard expansion (`*`, `?`, prefix, suffix, under the root) over a mocked `IFileSystemWrapper`; a leading or relative wildcard throws; literal paths and expansions return only existing paths; a file in place of a directory matches nothing; entries named with `*`/`?` expand once; an entry that raises a filesystem error is skipped |
