# Rename the agent's connection block to `<agent><manager>`

## Description

This pull request keeps the root tag `<agent>` and takes the inner one back to `<manager>`, so the block reads `<agent><manager>`. `<agent><server>` becomes invalid.

The 4.x compatibility path is untouched: a configuration left behind by a 4.x agent is still read for `<client><server><address>`, with the port defaulted to `1517`.

No 5.x -> 5.x fallback is added, and none is needed. `<agent><server>` is in no release tag, `v5.0.0-beta4` (the newest tag) still shipped `<client><manager>`. It has no installed population.

Closes #38464

## Proposed Changes

**Parser**

`Read_Agent()` now dispatches on `"manager"` (`client-config.c:37,95`), and `Read_Agent_Server()` follows the block to `Read_Agent_Manager()`. The second `"server"` literal in the file stays exactly as it was: it lives in `Read_Legacy_Client_Address()` and reads the 4.x `<client><server><address>`, so it was renamed `xml_client_server` to stop it reading as an `<agent>` symbol. Log and warning text carrying the tag name moved with it, including the deprecation hints for `<server-ip>` and `<server-hostname>`.

The data model keeps its names. `agent_server`, `logr->server`, `server_count` and `Validate_Address(agent_server *)` describe the runtime struct rather than the XML tag and reach across agentd and the HTTPS bridge, so they are out of scope here, as the issue says of `SERVER_UNAV` / `SERVER_UP`.

**Everything that writes the block**

Both shipped templates (`etc/ossec-agent.conf`, `src/win32/ossec.conf`), the source installer (`inst-functions.sh`), the `WAZUH_MANAGER` rewrite used by the deb/rpm/macOS packages (`register_configure_agent.sh`), and the MSI custom action (`InstallerScripts.vbs`).

`add_adress_block()` still strips both `<manager>` and `<server>` before writing. That sed runs before the write, so keeping both patterns is what lets a pre-rename 5.x file be re-registered rather than accumulating two blocks.

**MSI upgrades pick the inner tag from the root already in the file**

`InstallerScripts.vbs` rewrites only the inner block and never the root — its pattern is `\s+<(server|manager)>(.|\n)+?</\1>`, which matches wherever the block sits. On a Windows 4.x -> 5.x MSI upgrade with `WAZUH_MANAGER=` passed, `ossec.conf` is preserved with a `<client>` root, so writing the new canonical `<manager>` would have produced `<client><manager>` — a shape `Read_Legacy_Client_Address()` does not match, leaving the agent with no manager address. The tag is now chosen from the root in the file: `<manager>` when it contains `<agent>`, `<server>` otherwise.

**WPK pre-flight, both platforms**

`pkg_installer.sh` (Linux/macOS) and `do_upgrade.ps1` (Windows) resolve the endpoint before installing anything and abort with `upgrade_result` = `2` if the manager is unreachable. Both now read `<agent><manager>` first and keep `<client><server><address>` as the 4.x fallback. Missing either one would abort every upgrade on that platform with "no manager address found in the configuration".

**Manage-Agent (`win32ui`)**

`get_ossec_server()` and `set_ossec_server()` keep an ordered list of candidate XPaths. The rule they now follow is that every candidate must be one the agent parser also accepts, otherwise the tray reports an address the agent cannot start with — and, worse, `set_ossec_server()` promotes whichever candidate already holds an address and writes the user's new value straight back into it.

`{agent,server}` was therefore replaced by `{agent,manager}` rather than demoted, and `{client,manager}` was deleted outright.

## Results and Evidence

### Artifacts Affected

- Agent executables: `wazuh-agentd` (configuration reader) and `win32ui.exe` (Manage-Agent).
- Default configuration files: `etc/ossec-agent.conf` and `src/win32/ossec.conf`.
- Packages: every agent package, through `inst-functions.sh`, `register_configure_agent.sh` and `InstallerScripts.vbs`.
- WPK contents: `pkg_installer.sh` and `do_upgrade.ps1` ship inside the WPK.

### Configuration Changes

- The agent connection block is `<agent><manager>`. `<agent><server>` is rejected with `(1230): Invalid element in the configuration: 'server'.`
- 4.x compatibility is unchanged: a `<client>` block is still read for `<server><address>` alone, with the port defaulted to `1517`. Renaming only the root tag is not enough — `<agent><server>` is invalid, so both tags move together.
- `<client><manager>` remains invalid, and is no longer read by Manage-Agent either.

### Documentation Updates

- `docs/guide/migration/upgrade-4x-to-5x.md`: the `<manager>` -> `<server>` row reversed, a new row for the half-renamed `<agent><server>` case, the before/after example, the WPK address-lookup paragraph and the validation checklist.
- `docs/ref/modules/client/configuration.md`: `### server` becomes `### manager`, plus the examples and the `<client>` fallback paragraph.
- `docs/ref/modules/client/README.md`: quick-configuration example.
- `etc/templates/config/README.md`: template example.

### Tests Introduced

No new test binaries. `src/unit_tests/config/test_client-config_https.c` was updated in place:

- `test_manager_tag_is_rejected` inverts into `test_server_tag_is_rejected`, asserting the parser now rejects `<server>` under `<agent>`.
- Four cases renamed to follow the tag: `test_manager_address_and_explicit_port`, `test_second_manager_block_prevails_with_warning`, `test_agent_manager_address_and_port_are_parsed`, `test_agent_manager_port_defaults_to_1517`.
- The `parse_legacy_client()` inputs deliberately keep `<server>`, since they exercise the 4.x `<client>` contract, which this change does not touch.

Seven integration templates build the block and now emit `- manager:`: `test_enrollment` (`config_server_address.yaml`, `config_wazuh_enrollment.yaml`), the four `test_agentd/*/wazuh_conf.yaml` (`test_state`, `test_state_config`, `test_reconnection`, `test_startup_hash_validation`) and `test_execd/test_run_active_response/config_run_active_response.yaml`, plus the `test_fim/conftest.py` dict key. The enrollment templates also carry `<enrollment><manager_address>`, a different tag that does not move.

`src/init/tests/test_register_configure_agent.sh` and the `test_config_report_*.conf` fixtures were updated to match. The MSI branch in `InstallerScripts.vbs` has no automated coverage; the repository has no VBScript test harness.

## Review Checklist

- [ ] Code changes reviewed
- [ ] Relevant evidence provided
- [ ] Tests cover the new functionality
- [ ] Configuration changes documented
- [ ] Developer documentation reflects the changes
- [ ] Meets requirements and/or definition of done
- [ ] No unresolved dependencies with other issues
