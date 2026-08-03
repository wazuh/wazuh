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
  `daemons_handler` restarts the agent per case; `prepare_local_image` builds a fresh OCI layout
  and removes it afterwards. No state leaks between cases.

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
| C3d | Empty `<local>` reference | `<local></local>` | **PASS** when `Empty 'local' reference` is logged. |

Failure of any of these means the parser accepted a value it should reject, or did not emit the
expected message (e.g. a wording change in the module that the pattern must be updated for).

### Suite: `test_inventory`

| # | Scenario | Configuration | Expected result |
|---|----------|---------------|-----------------|
| I1 | Scan on start stores the inventory | `scan_on_start=yes`, one `<local>` OCI layout | **PASS** when `Scan ended.` is logged and the references table has ≥1 row. |
| I2 | Image update detected on next scan | `interval=5s`, one `<local>` OCI layout | **PASS** when, after the image is rebuilt between scans, the next scan logs a reference *modification* and the stored `image_config_digest` changes. |

Expected **failures** (i.e. what a regression would look like):

- I1 fails if a scan completes but nothing is persisted → storage/DBSync regression.
- I2 fails if the rebuilt image is not detected (no modification logged) or the stored digest is
  unchanged → change-detection regression. It also fails if the module emits a delete+create for
  the *reference* instead of a modify, which would mean the reference identity is no longer stable
  across rebuilds (the reference-keyed model would be broken).

## Requirements to run

- A **5.x agent installed** at `/var/ossec` whose `wazuh-modulesd` includes this module and the
  installed `libcontainer_images.so` (built from this branch).
- The `wazuh_testing` framework available on the Python path.
- Run as root (the framework manages the agent service and writes `ossec.conf`).

```bash
cd tests/integration
python -m pytest test_container_images -p no:cacheprovider -v
```

## Current-branch caveat (stub reader)

On this exploration branch the module's reader factory still returns the **stub reader**
(`StubImageReader`), because real OCI/local-image package extraction is deferred. With the stub:

- The **configuration** suite is fully valid — it exercises the real parser and lifecycle logs.
- The **inventory** suite's *control flow* (scan barrier, image-update detection via the
  reference-modification log line, digest change) is exactly what the productized test will assert,
  but the **rows** stored come from the stub fixture rather than from the configured `<local>` path.
  Once the local reader is wired (follow-up issue), the same tests validate the real path with no
  changes other than removing this caveat. The `prepare_local_image` fixture already writes a real
  OCI layout at the configured path so the test is ready for that switch.
