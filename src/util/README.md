# util — `verify-agent-conf` and `wazuh-manager-service-control`

Two standalone manager executables that share nothing but a directory:

- **`verify-agent-conf`** validates shared agent configurations (`agent.conf`) with the same readers
  the agent applies them with. The Server API runs it on every `PUT /groups/{group_id}/configuration`
  body; operators run it after editing a group's file by hand.
- **`wazuh-manager-service-control`** is the set-user-ID root helper that restarts or reloads the
  manager service on behalf of the unprivileged `wazuh-manager` user — `wm_control` in modulesd, or
  the Server API itself when modulesd is down.

Both are built only for the manager (`add_subdirectory(util)` sits in the `if(NOT IS_AGENT)` block of
[`src/CMakeLists.txt`](../CMakeLists.txt)), written to `src/build/bin`, and skipped entirely in a
`UNIT_TEST` tree ([`CMakeLists.txt`](CMakeLists.txt) returns early).

Three documentation layers cover them, each with its own job:

- **This README** — the developer's map: the [requirements catalog](#requirements),
  [design decisions](#design-decisions-d1d4), the [layout](#layout), the
  [contracts with the callers](#contracts-with-the-callers), the [invariants](#invariants) and the
  [test map](#tests).
- **The operator pages** — for the helper, [Control](../../docs/ref/modules/control/README.md) (its usage,
  who may run it, the action table, every refusal and where it is logged) and the control
  [architecture](../../docs/ref/modules/control/architecture.md) (the request path from the API through
  `wm_control`, and the helper's checks in order); for `verify-agent-conf`,
  [Centralized configuration](../../docs/ref/modules/agent-management/centralized-configuration.md)
  (options, exit codes, what the API answers for an invalid body). Nothing here restates them.
- **The callers** — `src/wazuh_modules/src/wm_control.c` and `framework/wazuh/core/cluster/utils.py`
  run the helper; `framework/wazuh/core/configuration.py` runs `verify-agent-conf`.

## Requirements

### Functional (RF)

| # | Requirement | Where it is answered |
|---|---|---|
| RF-1 | Validate one file (`-f`) or the `agent.conf` of every directory under the shared directory (no option), with the agent's readers: syscheck, rootcheck, localfile, `<agent>` and the modules | `verify_agent_conf()` calls `Test_Syscheck()`, `Test_Rootcheck()`, `Test_Localfile()`, `Test_Agent()` and `Test_WModule()` (`src/config/src/*-config.c`); `main()` walks `SHAREDCFG_DIR` |
| RF-2 | Exit `0` only when every file checked is valid; a directory without `agent.conf` counts as a failure | `error` in `main()` (`src/verify-agent-conf.c`) |
| RF-3 | Restart or reload the manager when asked by the `wazuh-manager` user or root, and nothing else: exactly one argument, `restart` or `reload` (`-h` prints the usage) | `valid_action()`, `authorized_caller()` (`manager_service_control/main.c`) |
| RF-4 | Refuse to act from an install another user could have altered: its own file (still setuid), the home, `bin/`, `bin/wazuh-manager-control`, `bin/.process_list` when present, and `/usr/bin/systemctl` under systemd must be root-owned and not group- or world-writable | `validate_path()`, `path_is_safe()` — D3 |
| RF-5 | Tell the caller the request was accepted, after every check and before acting | `notify_accepted()` writes `'1'` to descriptor 3 — D4 |
| RF-6 | Under systemd, refuse a restart or reload the next start would refuse, while the manager still runs | `run_check()` before `execute_systemctl()` — D2 |
| RF-7 | Without systemd, run `bin/wazuh-manager-control restart|reload` directly; under systemd, a `reload` waits up to 60 s for the unit to settle (`active` → check + `systemctl reload`, `inactive`/`failed` → the control script) | `systemd_running()`, `service_state()`, `parse_service_state()`, the loop in `main()` |

### Non-functional (RNF)

| # | Requirement | Where it is answered |
|---|---|---|
| RNF-1 | The helper executes nothing with the caller's environment, descriptors or identity: environment cleared to `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LANG=C`, umask `0077`, descriptors above 3 closed, then supplementary groups dropped and real, effective and saved uid and gid set to `0` (verified) before every `execv()` | `main()`, `close_inherited_descriptors()`, `become_root()` |
| RNF-2 | The helper trusts no caller-supplied path: the install directory is derived from `/proc/self/exe`, and the basename must be `wazuh-manager-service-control` | `resolve_install_paths()`, `derive_install_paths()` |
| RNF-3 | The helper depends only on libc; Linux only | its target links no library and is defined only when `CMAKE_SYSTEM_NAME` is `Linux` ([`CMakeLists.txt`](CMakeLists.txt)) |
| RNF-4 | Every decision the helper takes is a pure function a unit test can call | `valid_action`, `authorized_caller`, `path_is_safe`, `parse_service_state`, `derive_install_paths`, `check_passed` — [tests](#tests) |
| RNF-5 | `verify-agent-conf` runs as its caller (no privilege change) from the installation directory | `chdir()` to `w_homedir()` in `main()`; installed `root:wazuh-manager` `0750`, run by the API through `configuration.py` |

<a id="design-decisions-d1d4"></a>

## Design decisions (D1–D4)

| # | Decision | Why |
|---|---|---|
| D1 | **The helper lives in `src/util`**, beside `verify-agent-conf` | It was first added under a new `utils` directory next to this one, which collided with this directory; `src/util`'s `add_subdirectory` already sat in the server-only block, so the tool is built for the manager only (commit "refactor: move wazuh-manager-service-control into src/util") |
| D2 | **Under systemd the helper runs `wazuh-manager-control check` as root, and calls `systemctl` only when it exits `0`** | The unit's `ExecStop` stops every daemon before its `ExecStart` checks anything, so a configuration or credential the start would refuse must be refused while the manager still runs (comment on `run_check()`). Without systemd, `wazuh-manager-control restart|reload` runs those checks itself before stopping anything ([Control](../../docs/ref/modules/control/README.md)) |
| D3 | **`bin/.process_list` is part of the ownership check** | `wazuh-manager-control` sources that file (`enable debug` writes it) and the helper runs the control script as root ([control architecture](../../docs/ref/modules/control/architecture.md)) |
| D4 | **The acceptance byte is written only after every check, and the action only after the byte** | The caller decides its answer from it: `wm_control` answers `ok accepted` on `'1'` and `err Service control rejected action` on anything else or a timeout ([control architecture](../../docs/ref/modules/control/architecture.md)). The check of D2 runs after acceptance, so its refusal reaches the API caller only when the API ran the helper itself and waited ([Control](../../docs/ref/modules/control/README.md)) |

## Layout

| Path | Contents |
|---|---|
| `src/verify-agent-conf.c` | the whole of `verify-agent-conf`: options, the walk of the shared directory, `verify_agent_conf()` |
| `manager_service_control/main.c` | the whole of `wazuh-manager-service-control`; every function is `static` |
| `CMakeLists.txt` | both targets; `WAZUH_RUNTIME_USER="wazuh-manager"` for the helper |

`verify-agent-conf` links `config`, `wazuh_modulesd_lib` (for `Test_WModule()`), `wazuh` and `wazuhext`;
its log tag is the `#define ARGV0 "verify-agent-conf"` in the file itself, not a CMake `-DARGV0` like the
daemons'. Any option turns the directory walk off, so `-d` alone checks nothing and exits `0`.

## Contracts with the callers

| Contract | Helper side | Caller side |
|---|---|---|
| Status descriptor | `STATUS_FD 3` | `MANAGER_SERVICE_CONTROL_STATUS_FD` in `wm_control.c`; `SERVICE_CONTROL_STATUS_FD` in `cluster/utils.py` |
| Acceptance timeout | — | 5 s: `MANAGER_SERVICE_CONTROL_TIMEOUT_MS` (`wm_control.c`), `SERVICE_CONTROL_TIMEOUT` (`cluster/utils.py`); the API also waits `SERVICE_CONTROL_CHECK_TIMEOUT` (4 s) after acceptance for the check's verdict |
| Binary path | `PROGRAM_NAME`, enforced on `/proc/self/exe` | `MANAGER_SERVICE_CONTROL_BIN` (`wm_control.c`), `SERVICE_CONTROL_NAME` (`cluster/utils.py`) |
| Refusal text | `fail()`: `wazuh-manager-service-control: <reason>` on stderr, exit `1` | `cluster/utils.py` relays the output into errors `1904` and its log line; the operator pages quote the check refusal verbatim |
| Error lines of `verify-agent-conf` | `<date> verify-agent-conf: ERROR: (<code>): <message>` from the shared logger | `configuration.py` matches that shape with a regular expression to build the API's `1114` detail, else `1115` |

## Invariants

1. **The helper's name is load-bearing.** `derive_install_paths()` refuses any basename but
   `PROGRAM_NAME`, so a rename moves the define, the `${INSTALL}` line in `src/init/inst-functions.sh`,
   [manager_base.csv](../../.github/actions/check_files/manager_base.csv), the RPM `%attr` line in
   `packages/rpms/SPECS/wazuh-manager.spec`, the DEB `postinst` owner loop, both callers above, and the
   docs.
2. **The mode is `4750 root:wazuh-manager` in every copy** — the `${INSTALL}` line, the CSV, the RPM
   `%attr` and the DEB `postinst` loop; the CSV wins and its gate fails the package build on a drift. Without the setuid bit the helper refuses
   (`service control is not installed set-user-ID`).
3. **`WAZUH_RUNTIME_USER` is defined twice**: in [`CMakeLists.txt`](CMakeLists.txt) and in
   [`unit_tests/util/CMakeLists.txt`](../unit_tests/util/CMakeLists.txt), which compiles the same source.
4. **Nothing may run between the checks and `notify_accepted()` that can refuse**, and nothing after it may
   be skipped silently: past acceptance the only trace of a failure is the helper's stderr, which under
   modulesd is not the manager log.
5. **`verify-agent-conf`'s error format is parsed.** Changing the log tag, the `ERROR:` level word or the
   `(<code>):` prefix of a config reader's message breaks the API's `1114` detail; the framework test
   below pins the shapes it expects.

## Tests

| Suite | Covers |
|---|---|
| `unit_tests/util/test_manager_service_control.c` | compiles `manager_service_control/main.c` with `main` renamed and calls its predicates: `-h`, the action allowlist, the caller rule, the path policy, the service states, path derivation from the executable, the check verdict (a signal is no verdict) |
| `framework/wazuh/core/tests/test_configuration.py` | `verify-agent-conf` from the API's side, with `_run_verify_agent_conf` mocked (canned error output and the reason extracted from it), plus `_run_bounded` itself: the timeout answered as `1115` and the output cap |
| `framework/wazuh/core/cluster/tests/test_utils.py` | the API's run of the helper (acceptance, timeouts, exit codes) |

The cmocka suite runs in the manager leg of
[5_testunit_linux-win.yml](../../.github/workflows/5_testunit_linux-win.yml) (`src/util/**` and
`src/unit_tests/util/**` select no agent leg); the framework tests in
[5_testunit_framework.yml](../../.github/workflows/5_testunit_framework.yml). Nothing tests
`verify-agent-conf` itself, nor the helper's `main()` past `-h` — the identity change, the `execv()`s
and the systemd loop need a real setuid install — and no suite in
[test_modules_manager.json](../../.github/test_modules_manager.json) is selected by a change under
`src/util/`.
