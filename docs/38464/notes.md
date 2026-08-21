# Issue 38464: Rename the agent's `<server>` config block back to `<manager>` (`<agent><manager>`)

Labels: type/enhancement, module/agent
Branch: `enhancement/38464-rename-the-agent-s-server-config-block-back-to` (base `origin/5.0.0` @ `649266ca93`)
Worktree: `/Users/fabioc/ubuntu-data/wazuh-wt/enhancement-38464-rename-the-agent-s-server-config-block-back-to`

Rename the **inner** connection tag from `<server>` to `<manager>`, keeping the root as
`<agent>`. `<agent><server>` becomes invalid; the 4.x `<client><server>` address fallback
is untouched.

## Findings

Full trace of the tag on the `5.0.0` base.

### Parser — `src/config/src/client-config.c`

- `:37` `xml_agent_server = "server"` in `Read_Agent()`, compared at `:95` → dispatches `Read_Agent_Server()`. **This is the rename.**
- `:246` a *second* `xml_agent_server = "server"` inside `Read_Legacy_Client_Address()`, compared at `:259`. Reads `<client><server><address>` — **stays `"server"`**. Name is misleading (it is the client tag, not the agent one).
- `Read_Agent_Server()` `:347-461` carries no tag literal; it receives a pre-sliced node array.
- Log text with the literal tag name: `:293-294` (legacy fallback notice), `:435` ("Only one `<server>` block is supported"), `:458-459` (port default).
- `src/config/include/client-config.h:118-119,130,141-142` — doc comments only.
- `src/config/src/config.c:30,32,88,101` dispatches the **root** `agent`/`client` tags. Out of scope.

### Windows

- `src/win32/ui/common.c` XPath candidate arrays `:337-341` and `:465-467`: `xml_agentaddr` = `{ossec_config,agent,server,address}`, `xml_manageraddr` = `{ossec_config,client,manager,address}` (4.x legacy), `xml_serveraddr` = `{ossec_config,client,server,address}`. Write order self-reorders at `:495-508`.
- `src/win32/do_upgrade.ps1:342,344,348` — `get_conf_value "agent" "server" "address"`, literal passed as an argument. `get_conf_value()` itself (`:290-310`) is generic.
- `src/win32/InstallerScripts.vbs` — **not in the issue's scope list**. `:78` read regex `\s+<(server|manager)>...` already tolerates both; `:87-98` hardcodes writing `<server>`; `:240` profile-insert anchor `(</server>|</manager>)` already tolerates both. Comments at `:87-89` and `:234-238` state the opposite of the new rule.

### Install scripts

- `src/init/inst-functions.sh:399-408` `WriteAgent()` writes the block; the comment at `:399` only covers the root rename.
- `src/init/register_configure_agent.sh:149` deletes both `<manager>` and `<server>` blocks, then `:156-159` writes a fresh one. The delete happens *before* the write, so keeping both patterns is correct and desirable — the block only needs its written tag flipped.
- `src/init/tests/test_register_configure_agent.sh:96,98,113,125,127,144,146` — **not in the issue's scope list**; asserts on the literal `<server>` block.

### Not affected (verified, do not rename)

- `src/client-agent/src/config.c:167` already emits the JSON key `"manager"` for `getAgentConfig()`; decoupled from the XML tag.
- `remoted/`, `os_auth/`, `wazuh_modules/agent_upgrade/`: no node-name comparison on either word.
- Python (`framework/`, `api/`, `wodles/`): no hits. Manager-side config only.
- `<enrollment>` sub-tags `manager_address` / `server_ca_path` — a different tag.
- `config.c:25,29` "Server Config" comments = manager-side `<global>`/`<remote>`.
- `tests/integration/conftest.py:104,119` `"server"` = a host type in the topology.
- `src/shared/include/error_messages/error_messages.h:294` `AG_INV_INT` already says `<manager>`; the rename *fixes* that mismatch, no edit needed.

### Templates, tests, docs

- `etc/ossec-agent.conf:8-15` — the only shipped template carrying the block.
- `src/unit_tests/config/test_client-config_https.c` — 57 literal `<server>` occurrences. `test_manager_tag_is_rejected` (`:343`) asserts `<manager>` is invalid and **inverts** with this change; `:360` asserts the "Only one `<server>` block" warning text; `:597` mirrors the install template.
- `tests/integration/test_fim/conftest.py:116-127` — **not in the issue's scope list**; the tag is the dict key `{"server": {...}}` fed to the conf generator.
- `tests/integration/test_enrollment/test_options/data/{configuration_templates/config_server_address.yaml,test_cases/cases_server_address.yaml}`.
- `docs/ref/modules/client/configuration.md` — `### server` section `:21-77`, cross-refs `:145,245`, examples `:363-368,391-395,404,428-432`.
- `docs/guide/migration/upgrade-4x-to-5x.md:63-66` (the `<manager>`→`<server>` table row flips), `:95-119`, `:193,209,261`.

### Release timeline — `<agent><server>` never shipped

- Latest release tag is `v5.0.0-beta4` (2026-07-21, `e771576064`). Its shipped `etc/ossec-agent.conf` uses `<client><manager>`, and its parser accepted both `xml_client_manager = "manager"` and `xml_client_server = "server"`.
- `<agent><server>` arrived in `14221e3a07` (2026-08-06, "feat: rename `<client>` to `<agent>` for 5x fresh installation"). `git tag --contains 14221e3a07` is empty.
- So `<agent><server>` only exists on boxes built from `5.0.0`/`5.0.1`/`main`/`5.0.0-https` after 2026-08-06 — dev and QA, nothing in the field. The waived 5.x->5.x fallback has an empty population.

## Decisions

- Base is `origin/5.0.0`, not `main` and not `5.0.0-https`.
- `client-config.c:246` keeps `"server"` and gets renamed to `xml_client_server` for clarity.
- `win32/ui/common.c`: flip the existing `xml_agentaddr` to `{agent,manager}` rather than adding a fourth candidate — 5.x→5.x compat is explicitly not required, so `{agent,server}` is dropped, not demoted.
- `InstallerScripts.vbs`, `test_register_configure_agent.sh` and `test_fim/conftest.py` are in scope even though the issue does not list them.

## Open

- `{client,server-ip}` and `{client,server-hostname}` are still candidates in `get_ossec_server()` but are no longer parser-readable: `4.14.9` accepted `<client><server-ip>` / `<client><server-hostname>`, while 5.x only reads those two under `<agent>` (deprecated, `client-config.c:74-84`) and the narrowed `<client>` reader takes nothing but `<server><address>`. Same class as the deleted `xml_manageraddr`, but these are genuine 4.x shapes, so removing them is a separate call — own issue.
- `src/engine/tools/devContainer/e2e/agents/entrypoint.sh:15-27` is already stale against the current code (its comment claims 5.x uses `<manager>` while it seds a `<client>` block, and it never gates on `<agent>`). Broken independently of this rename — proposing to leave it out.

## Implemented

17 files, +149/-145. `bin/wzfmt --which` returns `none` for every C file touched.

- `client-config.c`: `xml_agent_server`/`"server"` -> `xml_agent_manager`/`"manager"` (`:37,95`); the second literal at `:246` kept as `"server"` and renamed `xml_client_server`; log and warn text updated at `:75,84,293,435,458`; doc comments at `:106,341,343`.
- `client-config.h`: two doc comments (`:118`, `:146`).
- `win32/ui/common.c`: `xml_agentaddr` -> `{ossec_config,agent,manager,address}` in both `get_ossec_server()` and `set_ossec_server()`; `{agent,server}` dropped, not demoted. `xml_manageraddr` (`{client,manager,address}`) deleted outright from both functions, along with its read block and its `xml_paths[]` entry.
- `win32/InstallerScripts.vbs`: the write path now emits `<manager>`; the read regex `:78` and the profile anchor `:239` keep their `server|manager` alternation so a pre-rename file is still matched.
- `win32/do_upgrade.ps1`: `get_conf_value "agent" "manager" "address"` and `... "port"`; the `"client" "server"` fallback is untouched.
- `init/inst-functions.sh`, `init/register_configure_agent.sh`: write `<manager>`. The sed in `add_adress_block()` still strips both tags — it runs before the write, so keeping `<server>` there is what lets a pre-rename 5.x file be re-registered.
- `etc/ossec-agent.conf`, `etc/templates/config/README.md`.
- `test_client-config_https.c`: 97 tags flipped; the 4 `parse_legacy_client()` XML inputs kept at `<server>`. `test_manager_tag_is_rejected` inverted to `test_server_tag_is_rejected` (asserts `(1230): Invalid element in the configuration: 'server'.`). Renamed `test_manager_address_and_explicit_port`, `test_second_manager_block_prevails_with_warning`, `test_agent_manager_address_and_port_are_parsed`, `test_agent_manager_port_defaults_to_1517`.
- `init/tests/test_register_configure_agent.sh`, `tests/integration/test_fim/conftest.py` (dict key), `config_server_address.yaml` (`- manager:`). The `SERVER_ADDRESS`/`server_address` names in `cases_server_address.yaml` are parameters, not the tag, and stay.
- `docs/ref/modules/client/configuration.md`: `### server` -> `### manager`, examples, and the `<client>` fallback paragraph.
- `docs/guide/migration/upgrade-4x-to-5x.md`: the `<manager>` -> `<server>` row reversed, plus a row for a half-renamed `<agent><server>`; before/after example, WPK address-lookup paragraph, and validation checklist.
- `CHANGELOG.md`: new Agent/Changed row. The `<client>` -> `<agent>` rename had no changelog entry at all before this.

### Missed by both the issue and the first trace

A repo-wide sweep for `<agent>` immediately followed by `<server>` (multiline, comments skipped) found five sites neither the issue's scope list nor the initial trace reported:

- `src/win32/ossec.conf:10-13` — the **Windows agent's shipped default config**. The trace only looked under `etc/`, so this template was invisible to it. Left alone, every Windows install would have shipped an `ossec.conf` the parser rejects.
- `src/unit_tests/config_files/test_config_report_{default,disabled,custom_interval}.conf` — fixtures read from disk by the `config_report` tests, so the tag never appears in the test `.c` file.
- `docs/ref/modules/client/README.md:62-67` — quick-configuration example.
- `src/config/src/config.c:104` — comment naming `<agent><server><address>` as the fallback target.

The lesson: a grep for the tag inside one file's own text misses fixtures loaded at runtime and templates outside the directory you expect. The adjacency sweep is what caught them.

### Install and upgrade matrix (verified against the code paths)

| Scenario | `ossec.conf` ends as | Parser result |
|---|---|---|
| Clean 4.x install | `<client><server><address>` (`4.14.9` template and its `WriteAgent()`) | n/a, parsed natively by 4.x |
| Clean 5.x install | `<agent><manager>` | `Read_Agent()` (`client-config.c:95`) |
| 4.x -> 5.x WPK | `<client><server><address>`, preserved | `Read_Legacy_Client_Address()`; port forced to `DEFAULT_HTTPS_REMOTE_PORT` |
| 5.x -> 5.x WPK | preserved, already `<manager>` | `Read_Agent()` |

The conf survives an upgrade on three counts: `upgrade.sh:16` shells out to `pkg_installer.sh` (dpkg/rpm); `install.sh:74-99` copies `${INSTALLDIR}/etc` aside and restores it; and the deb postinst gates registration on `[ -z "$2" ] || [ -f ${WAZUH_TMP_DIR}/create_conf ]`, where `create_conf` is only touched when the conf is *missing* (`preinst:117-119`). macOS is gated on `[ -z "${upgrade}" ]`. So `register_configure_agent.sh` never rewrites a preserved 4.x conf, and `add_adress_block` is additionally behind `[ -n "${WAZUH_MANAGER}" ]` (`:400`).

### `<client><manager>` has no population — deleted rather than supported

An earlier draft of these notes proposed teaching `Read_Legacy_Client_Address()` to accept `"manager"`, on the theory that beta4 left a stranded population. That was wrong, and the history says so:

- `4.6` through `4.14.9` carry no `xml_manageraddr` in `win32/ui/common.c` — only `{client,server-ip}`, `{client,server-hostname}`, `{client,server,address}`.
- `4.14.9`'s parser (`src/config/client-config.c` at that tag) has no `"manager"` literal at all: `xml_client_server = "server"`, `xml_client_ip = "server-ip"`, `xml_client_hostname = "server-hostname"`.
- `xml_manageraddr` was introduced on 2026-03-10 by `5a90e30535` ("fix(win32ui): persist manager ip for manager/server config"), during the 5.0 window when the inner tag was `<manager>` under a `<client>` root.

So `<client><manager>` was only ever written by 5.0 pre-releases (beta1..beta4) — precisely the population this issue waives. Reading it would re-add the 5.x -> 5.x compatibility the requirement says is not needed, so the candidate is deleted from both functions instead. The rule the UI now follows: every candidate must be one the agent parser also accepts.

### Regression found while walking that matrix, and fixed

`src/win32/InstallerScripts.vbs` rewrites only the **inner** block, never the root tag — its pattern is `\s+<(server|manager)>(.|\n)+?</\1>`, which matches wherever the block sits. On a Windows 4.x -> 5.x **MSI** upgrade with `WAZUH_MANAGER=` passed, the conf is preserved with a `<client>` root, so writing the new canonical `<manager>` produced `<client><manager>` — a shape `Read_Legacy_Client_Address()` does not match (it compares against `"server"` only, `:246`), leaving the agent with no manager address.

Fixed by choosing the inner tag from the root already in the file (`InstallerScripts.vbs:87-99`): `<manager>` when the file contains `<agent>`, `<server>` otherwise. A 4.x `ossec.conf` has no `<agent>` tag at all, so a plain `InStr` suffices; only a commented-out `<agent>` would fool it, which is marked with a `ponytail:` comment.

Not reachable on Linux/macOS: `register_configure_agent.sh` runs on fresh install only, where the root is already `<agent>`. `insert_into_agent_block` still anchors on `<(agent|client)>`, which is now defensive-only.

No automated coverage — there is no VBScript harness in this repo. Worth an explicit E2E case: Windows 4.14 agent, MSI upgrade to 5.0 with `WAZUH_MANAGER=` set, assert the resulting block is `<client><server>` and the agent connects.

### Cross-check against PR #38172 (the mirror `<client>` -> `<agent>` rename, issue #38103)

Walked all 27 files that PR touched. It found one thing my own sweeps did not:

- **`src/init/pkg_installer.sh:96-103`** — the Linux/macOS WPK pre-flight probe, exact twin of `do_upgrade.ps1`. `SERVER_ADDRESS=$(xml_value agent server address)` and `SERVER_PORT=$(xml_value agent server port)`, now `agent manager`. The `client server address` fallback is untouched. My earlier reading of `upgrade.sh` grepped for `ossec.conf`, found nothing, and wrongly concluded `pkg_installer.sh` came from the packaging repo — it lives here, and reads the conf through its own `xml_value()` helper (`:58`). Missing it would have aborted every Linux and macOS WPK upgrade with "No manager address found in the configuration."
- **Symbols follow the block.** That PR renamed `Read_Client*` to `Read_Agent*` alongside the tag, so `Read_Agent_Server` -> `Read_Agent_Manager` here (4 sites: declaration, call, definition, one test comment).

Line drawn at the data model: `agent_server`, `logr->server`, `server_count`, `Validate_Address(agent_server *)` keep their names. They describe the runtime struct, not the XML tag, and reach across agentd and the HTTPS bridge. The issue says the same of `SERVER_UNAV`/`SERVER_UP` — "naming only, not required to change".

Checked and correctly untouched: `docs/ref/configuration/agent/README.md:20` lists the **root** `<agent>` only; `docs/ref/modules/agent_upgrade/README.md`, `reload_agent.c`, `config.h`, `defs.h`, `verify-agent-conf.c`, `test_https_client_bridge.c`, and the `wm_agent_upgrade_agent` sources carry no inner-tag literal.

### CI (PR #38501) caught a third instance of the same blind spot

Four jobs failed, all in the modules that need a running agentd: `IT Linux - agentd`, `IT Linux - enrollment`, `IT Windows - agentd`, `IT Windows - enrollment`. Six integration templates still built the block as `- server:`:

- `test_enrollment/test_agent/data/configuration_templates/config_wazuh_enrollment.yaml`
- `test_agentd/test_state/data/configuration_templates/wazuh_conf.yaml`
- `test_agentd/test_state_config/data/configuration_templates/wazuh_conf.yaml`
- `test_agentd/test_reconnection/data/configuration_templates/wazuh_conf.yaml`
- `test_agentd/test_startup_hash_validation/data/configuration_templates/wazuh_conf.yaml`
- `test_execd/test_run_active_response/data/configuration_templates/config_run_active_response.yaml`

`test_execd` passed despite carrying the bad template, because its tests exercise `wazuh-execd` and do not need agentd to come up. `IT fim` passed only because `test_fim/conftest.py` had already been fixed — otherwise it would have failed the same way.

Note the enrollment templates also carry `<enrollment><manager_address>`, a different tag that must not move. The replacement was anchored on `^(\s*)- server:$` and asserted to hit exactly once per file.

**The blind spot, three times over.** Every miss in this issue was the tag appearing as *data* rather than as markup, so a grep for `<server>` could never see it:

| Form | Site | Found by |
|---|---|---|
| C XPath array element | `win32/ui/common.c` | the issue's own scope list |
| shell positional arg | `init/pkg_installer.sh` | cross-check against PR #38172 |
| YAML list key | 6 integration templates | CI |

The lesson for the next rename: sweep for the bare token in every serialization form — `<tag>`, `"tag"`, `'tag'`, `- tag:`, and as a bare argument — not just the markup.

### Traps hit

- Two legacy tests (`test_legacy_client_reads_nothing_but_the_address`, `test_legacy_client_takes_the_last_address`) pass their XML through a `const char *xml_str` variable rather than inline, so a call-site-scoped replacement missed them and flipped their input to `<manager>`. Reverted; every `parse_legacy_client()` input is verified back to `<server>`.
- Pre-existing lint, not introduced here: hard tabs in `upgrade-4x-to-5x.md` (`:101,109-112,143,147-149,153`), its in-page anchor at `:75`, and `CHANGELOG.md` consecutive blanks.
