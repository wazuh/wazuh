# manager_config — loader of the manager configuration (`etc/wazuh-manager.yml`)

Manager-only C++17 static library that turns `etc/wazuh-manager.yml` into the **effective configuration**
(parsed YAML, validated against the embedded JSON Schema, defaults filled, cross-field semantics checked)
and exposes it as canonical JSON to the C daemons (`manager_config_c.h`) and as a C++ class (`manager_config.hpp`).
It replaces the pseudo-XML `ReadConfig`/`os_xml` path and the four "bypass" readers of the manager
(`<logging>`, `<cluster>`, `<indexer>`, remoted's `<auth>` re-read). `agent.conf` and the agent stay on XML.

## Requirements

| # | Requirement | Where |
|---|---|---|
| RF-1 | One YAML 1.2 document with a mapping root; multi-document, anchors/aliases, explicit tags and non-mapping roots are rejected; an empty file is the empty mapping | `src/yamlToJson.cpp` |
| RF-2 | Validation against the embedded draft-04 schema; the first error is reported with its JSON pointer and keyword | `src/schemaValidate.cpp` |
| RF-3 | Defaults declared in the schema are filled into the effective document (a missing section = its defaults) | `src/defaults.cpp` |
| RF-4 | Uniform, fatal cross-field rules: certificate/key pairing, no `.`/`..` prefix segments, distinct listener ports, existence of certificate files (relative to the manager home) | `src/semantics.cpp` |
| RF-5 | `sectionJson()` / `documentJson()` canonical JSON (cJSON-parseable) | `src/manager_config.cpp` |
| RF-6 | Any path (`-c`) is honoured by every section of the process | `Document::load(path)` |
| RF-7 | Load once, read concurrently, no hot reload | immutable `Document` |
| RF-8 | C API without exceptions or C++ types across the boundary | `src/manager_config_c.cpp` |
| RNF-1 | C++17, STATIC, manager only, `yaml-cpp` + rapidjson PRIVATE | `CMakeLists.txt` |
| RNF-2 | Schema embedded at build time (`generated/embeddedSchema.hpp`); the same file is installed for Python | `CMakeLists.txt` |
| RNF-4 | Input limits: 1 MiB, depth 16 | `src/yamlToJson.hpp` |

## Design decisions

- **Schema as the single source of truth** (`schema/wazuh-manager.schema.json`): types, ranges, enums, defaults and
  descriptions of the 66 leaf options. Draft-04 because it is what rapidjson's validator implements and what the Python
  framework already uses (`jsonschema.Draft4Validator`). Definitions (`duration`, `size`, `port`…) are reused through
  `allOf: [{$ref}]` so a property can carry its own `default`/`description`.
- **YAML 1.2 core schema typing**, implemented by hand over yaml-cpp scalars: only `true`/`false` are booleans, so the
  legacy `yes`/`no` fail with `type`. Quoted scalars are always strings. PyYAML alone would follow YAML 1.1
  (`yes` → `True`); `tests/parity.py` shows the loader the Python side must use.
- **Strictness pass over the event stream** (`YAML::Parser` + `EventHandler`) before building nodes: yaml-cpp resolves
  aliases and drops tags silently in the Node API, so anchors/aliases/tags are detected at event level.
- **Validate the raw document, then fill defaults, then check semantics.** The effective document may therefore contain
  values the schema would reject on input (e.g. `indexer.hosts: []` when the section is absent): consumers decide whether
  an absent section is fatal (the engine does; modulesd does not).
- **Defaults algorithm** (mirrored in Python): for every property of an object schema missing in the document, insert its
  `default` when declared (property or resolved `$ref`), else an empty object when it is an object schema; recurse into
  object properties. Options without `default` (`verification_mode`, `ciphers`, `max_body_size`, `dual_stack`) stay absent:
  absence is meaningful ("module default / inferred").
- **Ports**: a disabled listener (`remote.legacy.enabled: false`, `auth.disabled: true`) does not reserve its port.
- **Files**: `LoadOptions::checkFiles` (default on) resolves relative paths against `LoadOptions::home`; unit tests turn it
  off or create the files under a temporary home.

## Layout

```
manager_config/
├── CMakeLists.txt                 # STATIC lib, schema embedding, tests under UNIT_TEST
├── schema/wazuh-manager.schema.json
├── include/manager_config/{manager_config.hpp, manager_config_c.h}
├── src/{yamlToJson,schemaValidate,defaults,semantics,manager_config,manager_config_c}.cpp
├── cli/manager-conf.cpp           # bin/wazuh-manager-conf (validate | get | dump)
└── tests/
    ├── unit/managerConfig_test.cpp   # target manager_config_utest
    ├── vectors/{valid,invalid}/*.yml + expected/*.json   # shared with parity.py
    ├── parity.py                     # jsonschema Draft4 must agree with the library on every vector
    └── cli/manager_conf_cli_test.sh  # ctest manager_config_cli: the CLI and the YAML generator (src/init/gen_wazuh.sh)
```

## Tests

```bash
cmake -S $WAZUH_REPO/src -B $WAZUH_REPO/src/build -DUNIT_TEST=ON
cmake --build $WAZUH_REPO/src/build -j --target manager_config_utest
$WAZUH_REPO/src/build/shared_modules/manager_config/tests/unit/manager_config_utest
$TMP_PY_VENV/bin/python3 tests/parity.py schema/wazuh-manager.schema.json tests/vectors
```

`ctest --test-dir $WAZUH_REPO/src/build -R manager_config` runs the three tests (`manager_config_utest`, `manager_config_parity`
— registered when the venv exists — and `manager_config_cli`, which also drives `src/init/gen_wazuh.sh` through a scratch mirror of the repository).

## CLI — `bin/wazuh-manager-conf`

```
wazuh-manager-conf [-f <file>] [-H <home>] [--skip-file-checks] validate | get <key.path> | dump
```

| Command | Output | Exit |
|---|---|---|
| `validate` | nothing on success; `(1244): Invalid configuration at '<json-pointer>': <reason>` on stderr otherwise | 0 / 1 |
| `get a.b.c` | the option of the **effective** document (defaults applied): strings unquoted, booleans `true`/`false`, numbers as is, objects and lists as compact JSON | 0; 2 when the key is not set (no value and no default) |
| `dump` | the whole effective document as pretty JSON | 0 / 1 |

`-f` defaults to `<home>/etc/wazuh-manager.yml`; `<home>` is `-H`, else `$WAZUH_MANAGER_HOME`, else the parent of the `bin/`
directory holding the binary (the same resolution as `w_homedir()`). A missing file is reported with `(1239)` (`NO_CONFIG`).
`--skip-file-checks` disables the existence check of the certificate/key files named in the document (the installer uses it:
the certificates are generated after the configuration). The CLI needs no daemon or socket; it links only `manager_config`.
Source: `cli/manager-conf.cpp` (C++17, `manager_config::Document` + `rapidjson::Pointer`), built in every mode so the
end-to-end test can run from the `UNIT_TEST` tree.

## Installed files

| Path (relative to `$WAZUH_HOME`) | Mode | Origin |
|---|---|---|
| `etc/wazuh-manager.yml` | 660 root:wazuh-manager | generated at installation by `WriteManagerYaml()` (`src/init/inst-functions.sh`), the YAML twin of `wazuh-manager.conf` with the same cluster key; `gen_wazuh.sh conf … [yaml_output]` writes it for the packages |
| `etc/wazuh-manager.schema.json` | 640 root:wazuh-manager | copy of `schema/wazuh-manager.schema.json`, refreshed on every install (product, not configuration); the Python framework validates against it |
| `bin/wazuh-manager-conf` | 750 root:wazuh-manager | this module's CLI |

Templates of the generated file: `etc/templates/config/generic/manager/*.yml.template` (one fragment per section; `remote` is
written from the `WAZUH_REMOTE_*` installation variables by `WriteRemoteYaml()`).

## Consumers

Today: `bin/wazuh-manager-conf` and the installer (validation of the generated file). Planned: remoted, authd, monitord,
wazuh-db and modulesd (`mconf_load` at startup, `mconf_section_json` per section), the engine (`manager_config::Document`),
`wazuh-server.sh` (`get`/`validate`) and, through the installed schema copy, the Python framework.
