# Wazuh configuration readers (`src/config`)

Static library `config` (`CMakeLists.txt`), linked by every daemon of the manager and the agent. It turns
configuration files into the structures each daemon consumes.

## Two formats, two entry points

| Consumer | File | Entry point | Format |
|---|---|---|---|
| Agent daemons (`-DCLIENT`) | `etc/ossec.conf`, `etc/shared/agent.conf` | `ReadConfig(modules, cfgfile, ...)` (`src/config.c`) | XML (`os_xml`) |
| Manager, on behalf of agents | `etc/shared/<group>/agent.conf` (`CAGENT_CONFIG`) | `ReadConfig()` | XML |
| Manager daemons | `etc/wazuh-manager.conf` | `w_mconf_load()` / `w_mconf_section()` (`src/mconf-config.c`, manager only) | strict XML validated against `etc/wazuh-manager.schema.json` |

`ReadConfig()` dispatches each XML top-level element to its reader (`Read_Syscheck`, `Read_Localfile`, `Read_Client`,
`Read_WModule`...). The manager's own sections (`global`, `remote`, `auth`, `wdb`, `indexer`, `vulnerability-detection`,
`task-manager`) have no XML reader anymore: an agent file that still carries one gets
`<section> configuration is only set in the manager.` and the block is ignored. `agent-upgrade` is the
mirror image and the only one: it is an **agent-only** section, so `Read_AgentUpgrade` is compiled for
the agent alone and a manager file carrying `<agent-upgrade>` gets
`agent-upgrade configuration is only set in the agent.` — a manager has no agent-upgrade module, and
configures the upgrades it serves under `task-manager`. Elements removed in 5.x are listed in
`OBSOLETE_ELEMENTS` (`src/config.c`) and are ignored with a warning; anything else unknown is still fatal.

`mconf-config.c` wraps `shared_modules/manager_config` (pugixml + JSON Schema): `w_mconf_load()` parses and validates
the XML, fills the schema defaults and keeps the effective document as cJSON; `w_mconf_section("remote")` returns one
section. The daemons hand that section to the JSON readers below. The engine (`wazuh-manager-analysisd`) does not link
this library: it reads the same file through `manager_config` and publishes the document to `libwazuhshared.so` with
`w_mconf_hook_set()` (`src/shared/src/mconf_hook.c`), which `w_mconf_section()` also honours.

## Manager sections (effective document → struct)

| Section | Reader | Output | Consumers |
|---|---|---|---|
| `global` | `Read_Global_JSON` (`src/global-config.c`) | `_Config` | remoted (also read by the task manager's disconnection sweep) |
| `remote` | `Read_Remote_JSON` (`src/remote-config.c`) | `remoted` | remoted (`legacy`, `https`, `agents`); the task manager reads `legacy.enabled` and `https.verification_mode` for its upgrade delivery gates |
| `auth` | `Read_Authd_JSON` (`src/authd-config.c`) | `authd_config_t` | authd, remoted's enrollment bridge |
| `wdb` | `Read_WazuhDB_JSON` (`src/wazuh_db-config.c`) | `wconfig` (`src/shared/src/wazuhdb_op.c`) | wazuh-db |
| `indexer` | `Read_Indexer_JSON` (`src/indexer-config.c`) | `indexer_config` (cJSON global) | modulesd (vulnerability scanner, inventory sync...) |
| `vulnerability-detection` | `Read_Vulnerability_Detection_JSON` (`src/wmodules-vulnerability-detection.c`) | `wmodule` with the section as cJSON | modulesd |
| `task-manager` | `wm_task_manager_read_json` (`src/wmodules-task-manager.c`) | `wm_task_manager` | modulesd |

`wm_task_manager_read_json()` also reads `global` and `remote` for itself, which is why those two rows
name more than one consumer: the disconnection sweep's interval and the gates that decide whether an
agent upgrade could be delivered are both other sections' values. It reads them there rather than in
`wm_task_manager_read()` because `wm_config()` initialises the default modules **before**
`w_mconf_load()`, so no effective document exists yet at that point.

The readers receive the **effective** section (defaults already applied by the schema), so they only repeat the checks the
schema cannot express: string lengths that must fit fixed C buffers, IP syntax, URL-prefix grammar, TLS 1.3 cipher names
(`w_remoted_validate_*`, `w_authd_validate_ciphers`). Types are native (`enabled: true`, `port: 1514`, durations as
strings such as `15m`) and the `getconfig` dumps return them the same way.

`remote-config.c`, `authd-config.c`, `global-config.c`, `wazuh_db-config.c`, `indexer-config.c`,
`wmodules-vulnerability-detection.c`, `wmodules-task-manager.c` and `mconf-config.c` are excluded from the agent build
(`CMakeLists.txt`); their headers stay shared because the structs they define are used by common code.
`wmodules-agent-upgrade.c` goes the other way and needs no CMake entry: it is guarded `#ifdef CLIENT` over its entirety,
so it compiles to nothing on a manager. It is **not** the `wmodules-aws.c` shape — those readers are agent-only at
runtime but dual-target at build, because a manager still parses their `<wodle>` out of a group's `agent.conf`
(`Read_WModule`'s `agent_cfg` branch). `<agent-upgrade>` is never read from `agent.conf` (`config.c` passes
`!(modules & CAGENT_CONFIG)`) and its module is not built for the manager at all, so `wmodules.h` does not even declare
the types this file uses there.

## Tests

* cmocka: `src/unit_tests/config/` (`test_config-elements.c`, `test_indexer.c`, `test_mconf-config.c`,
  `test_wmodules-config.c`...), `src/unit_tests/remoted/test_remote-config.c`,
  `src/unit_tests/os_auth/test_authd-config.c`, `src/unit_tests/wazuh_db/test_wazuh_db-config.c`.
* The loader itself: `src/shared_modules/manager_config/tests/`.

## Documentation

* Manager configuration reference: `docs/ref/configuration/manager/`.
* Agent configuration: [online documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html).
