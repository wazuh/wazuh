# External Dependencies

## Where they come from

The libraries Wazuh is built with are not in this repository. `make deps` downloads the ones of `EXTERNAL_RES` from the dependency set that `DEPS_VERSION` names in `src/Makefile`, `https://packages.wazuh.com/deps/<DEPS_VERSION>/`. For each library it first looks for the tarball built for the platform, `libraries/<os>/<arch>/<name>.tar.gz` (`libraries/windows/<name>.tar.gz` for the Windows agent), and takes the sources, `libraries/sources/<name>.tar.gz`, when the set has none for that platform or with `EXTERNAL_SRC_ONLY=yes`. The sources of the Python interpreter are named after `CPYTHON_ARCHIVE` where `src/Makefile` defines it, one tarball per architecture.

A set is uploaded by hand. Two files of this branch describe it, also written by hand:

- The table `Software and libraries used` of the `README.md` at the root of the repository.
- `src/external_dependencies.json`, the list the daily vulnerability scan of the dependencies reads, together with `framework/requirements.txt` for the Python packages.

## Update a dependency

A change of a library goes in a new set that keeps the rest of the current one.

1. Upload the tarballs of the new version to the new set: every source tarball `src/Makefile` downloads for the library, and the tarball of every platform that has one in the current set. A platform whose tarball is not replaced keeps building the old version.
2. Set `DEPS_VERSION` in `src/Makefile` to the new set.
3. In the same pull request, update the row of the library in the table of `README.md` and its entry in `src/external_dependencies.json` (`version`, `revision` and `purl`), and set `deps_version` of that file to the new set.
4. When the Python interpreter or its packages change, `framework/requirements.txt` must pin with `==` every package the `cpython` tarballs of the set carry.

## Add or remove a library

Add it to `EXTERNAL_RES`, to the table and to `src/external_dependencies.json`, or take it out of the three. The keys of an entry of the inventory:

| Key | Value |
|---|---|
| `name` | The name in `EXTERNAL_RES`. |
| `version` | The upstream release the sources match, as in the table. |
| `revision` | The exact upstream tag or commit. |
| `cpe` | The CPE of the library in the NVD dictionary, with `*` as its version, or `null` when NVD has none. |
| `purl` | Its package URL, ending in `@<revision>` or `@<version>`. |
| `license`, `author` | As in the table. |
| `homepage` | The URL of its row in the table. |
| `scan`, `reason` | `"scan": false` with a `reason`, for an entry with no CPE or that is not shipped. |
| `part_of` | Only for what comes inside another library and is not in `EXTERNAL_RES`: the name of that library. |

## What checks them

No workflow checks these files on the pull request. The weekly review of the dependencies compares the table and the inventory with each other, with `DEPS_VERSION` and `EXTERNAL_RES`, and with the version the source tarballs of the set state, and reports every difference until it is corrected.

A merge of this branch into a 5.x branch leaves `src/external_dependencies.json` out and keeps the 5.x version of this page: 5.x describes its dependencies in `packages/externals/dependencies.json`.
