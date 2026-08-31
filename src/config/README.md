# Wazuh configuration readers (`src/config`)

Static library `config` (`CMakeLists.txt`), linked by every daemon of the manager and the agent. It turns
configuration files into the structures each daemon consumes.

## Two formats, two entry points

| Consumer | File | Entry point | Format |
|---|---|---|---|
| Agent daemons (`-DCLIENT`) | `etc/ossec.conf`, `etc/shared/agent.conf` | `ReadConfig(modules, cfgfile, ...)` (`src/config.c`) | XML (`os_xml`) |
| Manager, on behalf of agents | `etc/shared/<group>/agent.conf` (`CAGENT_CONFIG`) | `ReadConfig()` | XML |
| Manager daemons | `etc/wazuh-manager.yml` | `w_mconf_load()` / `w_mconf_section()` (`src/mconf-config.c`, manager only) | YAML validated against `etc/wazuh-manager.schema.json` |

`ReadConfig()` dispatches each XML top-level element to its reader (`Read_Syscheck`, `Read_Localfile`, `Read_Client`,
`Read_WModule`...). The manager's own sections (`global`, `remote`, `auth`, `wdb`, `indexer`, `vulnerability-detection`,
`task-manager`) have no XML reader anymore: an agent file that still carries one gets
`<section> configuration is only set in the manager.` and the block is ignored. Elements removed in 5.x are listed in
`OBSOLETE_ELEMENTS` (`src/config.c`) and are ignored with a warning; anything else unknown is still fatal.

`mconf-config.c` wraps `shared_modules/manager_config` (yaml-cpp + JSON Schema): `w_mconf_load()` parses and validates
the YAML, fills the schema defaults and keeps the effective document as cJSON; `w_mconf_section("remote")` returns one
section. The daemons hand that section to the JSON readers below. The engine (`wazuh-manager-analysisd`) does not link
this library: it reads the same file through `manager_config` and publishes the document to `libwazuhshared.so` with
`w_mconf_hook_set()` (`src/shared/src/mconf_hook.c`), which `w_mconf_section()` also honours.

## Manager sections (YAML → struct)

| Section | Reader | Output | Consumers |
|---|---|---|---|
| `global` | `Read_Global_JSON` (`src/global-config.c`) | `_Config` | monitord |
| `remote` | `Read_Remote_JSON` (`src/remote-config.c`) | `remoted` | remoted (`legacy`, `https`, `agents`) |
| `auth` | `Read_Authd_JSON` (`src/authd-config.c`) | `authd_config_t` | authd, remoted's enrollment bridge |
| `wdb` | `Read_WazuhDB_JSON` (`src/wazuh_db-config.c`) | `wconfig` (`src/shared/src/wazuhdb_op.c`) | wazuh-db |
| `indexer` | `Read_Indexer_JSON` (`src/indexer-config.c`) | `indexer_config` (cJSON global) | modulesd (vulnerability scanner, inventory sync...) |
| `vulnerability-detection` | `Read_Vulnerability_Detection_JSON` (`src/wmodules-vulnerability-detection.c`) | `wmodule` with the section as cJSON | modulesd |
| `agent-upgrade` | `wm_agent_upgrade_read_json` (`src/wmodules-agent-upgrade.c`) | `wm_agent_upgrade` | modulesd |
| `task-manager` | `wm_task_manager_read_json` (`src/wmodules-task-manager.c`) | `wm_task_manager` | modulesd |

The readers receive the **effective** section (defaults already applied by the schema), so they only repeat the checks the
schema cannot express: string lengths that must fit fixed C buffers, IP syntax, URL-prefix grammar, TLS 1.3 cipher names
(`w_remoted_validate_*`, `w_authd_validate_ciphers`). Types are native (`enabled: true`, `port: 1514`, durations as
strings such as `15m`) and the `getconfig` dumps return them the same way.

`remote-config.c`, `authd-config.c`, `global-config.c`, `wazuh_db-config.c`, `indexer-config.c`,
`wmodules-vulnerability-detection.c`, `wmodules-task-manager.c` and `mconf-config.c` are excluded from the agent build
(`CMakeLists.txt`); their headers stay shared because the structs they define are used by common code.

## Tests

* cmocka: `src/unit_tests/config/` (`test_config-elements.c`, `test_indexer.c`, `test_mconf-config.c`,
  `test_wmodules-config.c`...), `src/unit_tests/remoted/test_remote-config.c`,
  `src/unit_tests/os_auth/test_authd-config.c`, `src/unit_tests/wazuh_db/test_wazuh_db-config.c`.
* The YAML layer itself: `src/shared_modules/manager_config/tests/`.

## Documentation

* Manager configuration reference: `docs/ref/configuration/manager/`.
* Agent configuration: [online documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html).
