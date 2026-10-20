# Container Images — integration tests

Integration tests for the `container_images` agent module, built on the same `wazuh_testing`
pytest framework used by `test_syscollector`, `test_sca` and `test_fim`. They drive a real
agent (`wazuh-modulesd`) with generated `ossec.conf` blocks and assert on the module's log
output and on its local SQLite database.

## How these tests stay non-flaky

The single most common source of flakiness in these suites is *time-based waiting* — sleeping a
fixed number of seconds and hoping a scan finished. These tests avoid that entirely:

- **Every wait is gated on a deterministic log line.** A `FileMonitor` watches `ossec.log` for a
  specific pattern (`Scan ended.`, `Module is disabled.`, `Inventory modified in …`, a config
  error, …) with a timeout. The assertion is "the line appeared", not "enough time passed". Each
  of those lines is emitted exactly once per event, so the wait is bounded and race-free.
- **The database is only read after the scan barrier.** The inventory tests read the SQLite
  tables only after the `Scan ended.` line for that scan has been observed, so they never race the
  writer.
- **The image-update test keys on the next event, not a duration.** It captures the state after
  the first `Scan ended.`, rebuilds the on-disk image, then waits for the *reference modification*
  log line — so the test passes as soon as the change is detected, regardless of the exact
  interval timing.
- **Each case is isolated.** `truncate_monitored_files` clears the log before/after every case;
  `daemons_handler` restarts the agent per case; and the image fixture the case asks for
  (`prepare_local_image`, `prepare_saved_archive`, `prepare_layered_image`,
  `prepare_whiteout_image`, `prepare_unsupported_image`, `prepare_rpm_sqlite_image`,
  `prepare_rpm_ndb_image`) builds a fresh input, points the configured `<archive>` reference at
  it, and removes it afterwards. No state leaks between cases.

## Layout

```text
test_container_images/
├── README.md                     # this file
├── conftest.py                   # OCI-layout build/update fixtures
├── test_configuration/           # parsing of the <container_images> block
│   ├── test_container_images_configuration.py
│   └── data/{configuration_templates,test_cases}/
└── test_inventory/               # scan -> store -> update detection
    ├── test_container_images_inventory.py
    └── data/{configuration_templates,test_cases}/
```

The log-line anchors and the DB query helper live in the framework package
`wazuh_testing/modules/modulesd/container_images/` (`patterns.py`, `db.py`), mirroring how
`test_syscollector` consumes `wazuh_testing/modules/modulesd/syscollector/patterns.py`. Those
two framework files are part of this change set and must be installed with `wazuh_testing`.

## Scenarios and expected results

### Suite: `test_configuration`

| # | Scenario | Configuration | Expected result |
|---|----------|---------------|-----------------|
| C1 | Module disabled | `enabled=no` | **PASS** when `Module is disabled.` is logged and no scan starts. |
| C2 | Default values | empty `<container_images>` block | **PASS** when the module logs `Module initialized.` (it came up on defaults). |
| C3a | Invalid `enabled` | `enabled=''` and `enabled=maybe` | **PASS** when `Invalid content for tag 'enabled'` is logged; the block is rejected. |
| C3b | Invalid `scan_on_start` | `scan_on_start=''` | **PASS** when `Invalid content for tag 'scan_on_start'` is logged. |
| C3c | Invalid `interval` | `interval=''` and `interval=1y` | **PASS** when `Invalid interval` is logged. |
| C3d | Empty `<archive>` reference | `<archive></archive>` | **PASS** when `Empty 'archive' reference` is logged. |

Failure of any of these means the parser accepted a value it should reject, or did not emit the
expected message (e.g. a wording change in the module that the pattern must be updated for).

### Suite: `test_inventory`

| # | Scenario | Input | Expected result |
|---|----------|-------|-----------------|
| I1 | Scan on start stores the inventory | `scan_on_start=yes`, one `<archive>` OCI layout with a dpkg database | **PASS** when `Scan ended.` is logged, the references table has ≥1 row, and `curl` and `tar` are stored with the versions the database holds. |
| I2 | Image update detected on next scan | `interval=5s`, one `<archive>` OCI layout | **PASS** when, after the image is rebuilt between scans, the next scan logs a reference *modification* and the stored `image_config_digest` changes. |
| I3 | Saved archive is inventoried | one `<archive>` saved image archive with an apk database | **PASS** when the reference is stored with type `archive` and its apk packages are stored. |
| I4 | The later layer wins | an image whose second layer upgrades a package | **PASS** when the upgraded package is stored once, with the version of the last layer, and the untouched package is still stored. |
| I5 | A deleted database contributes nothing | an image whose second layer deletes the dpkg database and adds an apk one | **PASS** when the package of the deleted database is absent and the apk package is stored. |
| I6 | Unsupported package format | an image whose only database is an RPM Berkeley DB one | **PASS** when the reference is stored, no package row exists, and the format is reported with a warning. |
| I7 | RPM sqlite database | an image whose only database is `var/lib/rpm/rpmdb.sqlite` | **PASS** when the reference is stored and the rpm packages are stored, with the epoch preserved on the version that carries one. |
| I8 | RPM ndb database | an image whose only database is `usr/lib/sysimage/rpm/Packages.db` | **PASS** when the reference is stored and the rpm packages are stored. |

Expected **failures** (i.e. what a regression would look like):

- I1 fails if a scan completes but nothing is persisted → storage/DBSync regression; it also fails
  if the references land but the packages do not → package extraction regression.
- I2 fails if the rebuilt image is not detected (no modification logged) or the stored digest is
  unchanged → change-detection regression. It also fails if the module emits a delete+create for
  the *reference* instead of a modify, which would mean the reference identity is no longer stable
  across rebuilds (the reference-keyed model would be broken).
- I3 fails if the saved archive is not read, or is stored under a reference type other than
  `archive` → input handling or reference-type regression.
- I4 and I5 fail if the layers are composed in the wrong order, or if the OverlayFS deletion
  markers are ignored → layer precedence regression.
- I6 fails if an unsupported format costs the reference instead of costing its packages, or if the
  empty inventory is silent → format-detection regression.
- I7 and I8 fail if the rpm database is not read, if the wrong database format is picked, or if the
  version loses its epoch → rpm extraction regression. I7 also fails if the write-ahead log mode a
  real `rpmdb.sqlite` carries is not handled, which shows up as zero packages.

## Requirements to run

- A **5.x agent installed** at `/var/ossec` whose `wazuh-modulesd` includes this module and the
  installed `libcontainer_images.so` (built from this branch). The suite configures `<archive>`
  references only, so no container engine and no registry access is needed.
- The `wazuh_testing` framework available on the Python path.
- Run as root (the framework manages the agent service and writes `ossec.conf`).

```bash
cd tests/integration
python -m pytest test_container_images -p no:cacheprovider -v
```

## What these tests prove today

The module reads the configured `<archive>` inputs, composes their layers and stores both the
image **references** and the **packages** those layers contain, so both suites exercise the real
path end to end: the parser and lifecycle logs in `test_configuration`, and discovery, package
extraction, storage and change detection in `test_inventory`.

Both supported inputs are covered (an OCI image layout directory and a saved image archive), as
are the layer precedence rules, the `dpkg` and `apk` formats, and a package format that is
recognized but not parsed yet. The inventory cases assert on `dbsync_container_image_packages` as
well as on the references table.

What these tests do **not** cover: RPM package inventory, remote registry references and the
container engine store, all of which are out of scope for this stage. The tar and gzip variants,
the malformed inputs and the field-level mapping are covered by the C++ unit tests, which drive
the reader and the database directly.

## Running in CI

Not integrated yet. Both test modules import from
`wazuh_testing.modules.modulesd.container_images`, and those three framework files
(`__init__.py`, `patterns.py`, `db.py`) still live in this directory rather than in the
framework package, so the suite only runs after they are copied into the installed
`wazuh_testing`. Landing them in the framework repository and registering the module in
`.github/test_modules_linux.json` is what makes these run on a pull request.
