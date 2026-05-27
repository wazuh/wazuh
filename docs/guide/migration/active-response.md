# Active Response migration guide (4.x to 5.x)

Active Response (AR) is rebuilt in 5.x. The 4.x XML in `ossec.conf`, the agent-side `ar.conf`, rule-based matching, and the `PUT /active-response` API are all removed. 5.x replaces them with channels managed in the dashboard, an Alerting monitor that triggers them, a `wazuh-active-responses` data stream that records executions, and a manager-side poller that dispatches to agents over `wazuh-remoted`.

> **Manual migration only.** No converter, importer, or compatibility shim is provided. Every 4.x AR must be recreated as a 5.x channel; every custom script must be rewritten for the new JSON contract.

Complete the stack-wide upgrade (see the general [Migration guide (4.x to 5.x)](../../ref/migration-4x-5x.md)) before touching AR.

## Breaking changes at a glance

- `ossec.conf` `<command>` / `<active-response>` blocks are no longer parsed. `ar.conf` is removed from the agent.
- AR is created under **Explore → Active Responses**. Each channel carries `name`, `description`, `enabled`, `executable`, `extra_arguments`, `type` (`stateful` / `stateless`), `stateful_timeout` (default `180s`), `location` (`local` / `defined-agent` / `all`), `agent_id`.
- Matching (`<rules_id>` / `<level>` / `<rules_group>`) moves to the query of an Alerting monitor of type **Active Response**.
- `PUT /active-response` is removed with no replacement. Dispatch is document-driven: a monitor action writes into `wazuh-active-responses`; the manager polls every 60 s (batches of 100) and forwards via `wazuh-remoted`. Pre-5.0 agents are filtered out.
- Executions land as structured documents in the `wazuh-active-responses` data stream (backing index `.wazuh-active-responses-v5`, 3-day ISM retention via `stream-active-responses-policy`).
- The JSON delivered to scripts changed shape: `command` ∈ `enable` / `disable` (was `add` / `delete` / `continue`); alert fields use flat ECS paths (`source.ip`, `user.name`, …); AR metadata sits under `wazuh.active_response.*`.
- Default firewall scripts (`firewall-drop`, `firewalld-drop`, `pf`, `npf`, `ipfw`, `netsh`, `route-null`, `host-deny`) are folded into a single `block-ip` executable. `restart-wazuh` moves to the Control Module. `wazuh-slack` is removed.
- `<location>server</location>`, `<repeated_offenders>`, `<timeout_allowed>` have no direct equivalent.
- `<disabled>` is replaced by the channel `enabled` field plus a **Mute / Unmute** runtime toggle.

![Active Response pipeline — 4.x rule-engine driven vs 5.x channel + data stream + poller](../images/ar-pipeline-4x-vs-5x.png)

## Compatibility matrix

| Wazuh Version | AR configuration source | Dashboard Platform        | Manager / Indexer |
| ------------- | ----------------------- | ------------------------- | ----------------- |
| 4.x           | `ossec.conf` XML blocks | OpenSearch Dashboards 2.x | Wazuh 4.x         |
| 5.0.x         | Dashboard entity (UI)   | OpenSearch Dashboards 3.x | Wazuh 5.x         |

Mixed-version fleets may execute inconsistently — coordinate manager and agent upgrades.

---

## Pre-migration

Back up the 4.x AR state and inventory each entry before upgrading:

```bash
AR_BACKUP_DIR="/root/backup-ar-$(date +%Y%m%d)"
sudo mkdir -p "$AR_BACKUP_DIR"
sudo cp -a /var/ossec/etc/ossec.conf "$AR_BACKUP_DIR/"
sudo cp -a /var/ossec/active-response/bin/ "$AR_BACKUP_DIR/"
```

For each `<command>` and `<active-response>` block in `/var/ossec/etc/ossec.conf`, record the values you will need to recreate the AR as a 5.x channel:

- `<command>`: `<name>`, `<executable>`, `<extra_args>`, `<timeout_allowed>`.
- `<active-response>`: the linked command, `<location>`, `<agent_id>`, the matching condition (`<rules_id>` / `<rules_group>` / `<level>`), `<timeout>`, `<repeated_offenders>`, `<disabled>`.

Historical AR records are not migrated to the 5.x `wazuh-active-responses` data stream. In 4.x they live in two places:

- Alerts in your `wazuh-alerts-*` indices, filtered by `rule.groups: active_response`.
- Lines in `/var/ossec/logs/active-responses.log` on each agent.

If you need long-term records, export them from your 4.x indexer using your standard data-export procedure before upgrading.

---

## Field mapping (4.x XML → 5.x channel)

| 4.x XML                                                     | 5.x equivalent                      | Notes                                                                                               |
| ----------------------------------------------------------- | ----------------------------------- | --------------------------------------------------------------------------------------------------- |
| `<command><name>`                                           | _(no direct field)_                 | The channel replaces the named command. Pick a descriptive **Name**.                                |
| `<command><executable>`                                     | **Executable**                      | Discovery path preserved at `/var/ossec/active-response/bin/<executable>` on Unix agents.           |
| `<command><extra_args>`                                     | **Extra arguments**                 | Free-form string passed to the executable.                                                          |
| `<command><timeout_allowed>`                                | _(no replacement)_                  | Reversal is driven by `type = Stateful` + **Stateful timeout**.                                     |
| `<active-response><location>` = `local`                     | **Location** = `Local`              | Default.                                                                                            |
| `<active-response><location>` = `defined-agent`             | **Location** = `Defined agent`      | Reveals **Agent ID**.                                                                               |
| `<active-response><location>` = `all`                       | **Location** = `All`                | Pushes the action to every connected agent.                                                         |
| `<active-response><location>` = `server`                    | _(no replacement)_                  | Manager-side execution does not exist in 5.x. See [`Location = server`](#location--server-from-4x). |
| `<active-response><agent_id>`                               | **Agent ID**                        | Only when `Location = Defined agent`.                                                               |
| `<active-response><rules_id>` / `<level>` / `<rules_group>` | Alerting monitor query              | Matching moves to the monitor — see [Triggering model](#triggering-model).                          |
| `<active-response><timeout>`                                | **Stateful timeout**                | Same unit (seconds). Forces `Type = Stateful`. Default `180s`.                                      |
| `<active-response><repeated_offenders>`                     | _(no replacement)_                  | See [`<repeated_offenders>` is gone](#repeated_offenders-is-gone).                                  |
| `<active-response><disabled>`                               | `enabled` field + **Mute / Unmute** | `enabled` is the persistent flag; **Mute / Unmute** is the runtime toggle.                          |
| `ar.conf`                                                   | _(deleted)_                         | `wazuh-execd` reads the JSON message directly.                                                      |

## Triggering model

| Aspect              | 4.x                                                               | 5.x                                                                            |
| ------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Where matching runs | Manager rules engine                                              | Alerting monitor (indexer / dashboard plane)                                   |
| How to express it   | `<rules_id>` / `<level>` / `<rules_group>` in `<active-response>` | Monitor of type **Active Response** with a query against `wazuh-findings-v5-*` |
| What invokes the AR | The alert fires the AR directly                                    | The trigger's **Add active response** action invokes the channel               |
| Visibility          | Manager logs                                                      | Alerting evaluation + execution record in `wazuh-active-responses*`            |

Each 4.x `<active-response>` becomes two artifacts in 5.x: the AR channel (the **what**) and an Alerting monitor (the **when**). The monitor query encodes the matching condition that used to live in `<rules_id>` / `<level>` / `<rules_group>`; the monitor's trigger then carries an **Add active response** action pointing at the channel. End-to-end wiring is covered in [Migration steps](#migration-steps), steps 4 and 5 below.

> The monitor type **must** be `Active Response`. No other type exposes the **Add active response** action.

## Audit and visibility

| Surface               | 4.x                                                                                                       | 5.x                                                                                                                                                        |
| --------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Executions land in    | `/var/ossec/logs/active-responses.log` + events from the `active_response` rule group in `wazuh-alerts-*` | `wazuh-active-responses` data stream (`.wazuh-active-responses-v5` backing index). Agent log unchanged.                                                    |
| Structured fields     | Free text                                                                                                 | `wazuh.active_response.{name,type,executable,extra_arguments,stateful_timeout,location,agent_id}` + `event.doc_id` / `event.index`.                        |
| `@timestamp`          | Event time                                                                                                | Indexing time. For event-time correlation use the linked alert via `event.doc_id`.                                                                         |
| Default retention     | Alerts ILM policy                                                                                         | 3 days (`stream-active-responses-policy`, priority 100). Adjust the policy for longer retention.                                                           |
| Pivot to source alert | Manual                                                                                                    | Each execution record carries `event.doc_id` + `event.index`; switch Discover to that index and filter `_id == event.doc_id` to open the triggering alert. |

## API change

`PUT /active-response` is removed with no replacement endpoint. Integrations that previously fired AR via the API must now emit an alert document and let an Alerting Active Response monitor pick it up. The manager keeps a bookmark at `/var/wazuh-manager/queue/cluster/ar_bookmark.json`.

For general dashboard-plugin API namespace changes (`/api/status` → `/api/wazuh-core/status`, etc.) see [Migration guide — API changes](../../ref/migration-4x-5x.md#api-changes).

---

## JSON stdin contract

> Custom AR scripts from 4.x will break on 5.x without code changes.

The discovery path is unchanged on Unix agents (`/var/ossec/active-response/bin/<executable>`). What changed is the JSON shape and the command vocabulary.

**4.x:**

```json
{
  "version": 1,
  "origin": { "name": "node01", "module": "wazuh-analysisd" },
  "command": "add",
  "parameters": {
    "extra_args": [],
    "alert": {
      "rule": { "id": "5763", "level": 5 },
      "data": { "srcip": "192.168.1.100", "dstuser": "root" }
    },
    "program": "/var/ossec/active-response/bin/firewall-drop"
  }
}
```

**5.x:**

```json
{
  "wazuh": {
    "active_response": {
      "name": "block-ip",
      "executable": "block-ip",
      "location": "defined-agent",
      "agent_id": "001",
      "type": "stateless"
    },
    "agent": { "id": "001", "name": "test-agent" }
  },
  "source": { "ip": "192.168.1.100" },
  "user": { "name": "username" },
  "command": "enable"
}
```

Changes:

- `command` ∈ `enable` / `disable`. `disable` messages additionally carry `stateful_timeout` at the root.
- Alert fields are flat ECS 9.1 paths (`source.ip`, `source.port`, `user.name`). `parameters.alert.data.*` is gone.
- AR metadata under `wazuh.active_response.*`. `wazuh-execd` reads `.executable`, `.type`, `.stateful_timeout` before invoking the script.

### Migration recipe

For each custom script:

1. Re-map field reads to ECS paths (`parameters.alert.data.srcip` → `source.ip`, etc.).
2. Replace `case "$COMMAND" in add) ... delete) ... continue)` with `enable) ... disable)`. There is no `continue`.
3. Read AR metadata from `wazuh.active_response.*` instead of positional arguments.
4. Honor `wazuh.active_response.stateful_timeout` for stateful scripts.
5. Capture stdin in a wrapper (`tee /tmp/ar-input.json`) on a real dispatch to confirm the shape.

### Example diff

**4.x body:**

```bash
#!/bin/bash

# Log file
LOGFILE="/var/ossec/logs/active-responses.log"

logmsg(){
  local msg="$@"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - custom-ar-sh - $msg" >> "$LOGFILE"
}

# Read AR input
read INPUT_JSON

logmsg "$INPUT_JSON"

# Get command
command=$(echo  "$INPUT_JSON" | jq -r '.command')

# Get srcip from the alert
ar_srcip=$(echo  "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip')

logmsg "Command: $command"

if [ "$command" == "add" ]; then
  # Send control message
  printf '{"version":1,"origin":{"name":"custom-ar-sh","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'
  read RESPONSE
  response_command=$(echo $RESPONSE | jq -r .command)
  if [ ${response_command} != "continue" ]; then
    logmsg "Abort"
    exit 0;
  fi

  # Execute the main AR command
  logmsg "Execute AR"
elif [ "$command" == "delete" ]; then
  # Execute the revert/undone command
  logmsg "Revert AR"
else
  logmsg "Invalid command: $command"
fi

exit 0
```

**5.x body:**

```bash
#!/bin/bash

# Log file
LOGFILE="/var/ossec/logs/active-responses.log"

logmsg(){
  local msg="$@"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - custom-ar-sh - $msg" >> "$LOGFILE"
}

# Read AR input
read INPUT_JSON

logmsg "$INPUT_JSON"

# Get command
command=$(echo  "$INPUT_JSON" | jq -r '.command')

# Get srcip from the alert
ar_srcip=$(echo  "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip')

logmsg "Command: $command"

if [ "$command" == "enable" ]; then # 5.x MIGRATION: Changed from add to enable
  # Send control message
  printf '{"version":1,"origin":{"name":"custom-ar-sh","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'
  read RESPONSE
  response_command=$(echo $RESPONSE | jq -r .command)
  if [ ${response_command} != "continue" ]; then
    logmsg "Abort"
    exit 0;
  fi

  # Execute the main AR command
  logmsg "Execute AR"
elif [ "$command" == "disable" ]; then # 5.x MIGRATION: Changed from delete to disable
  # Execute the revert/undone command
  logmsg "Revert AR"
else
  logmsg "Invalid command: $command"
fi

exit 0
```

Ownership and permissions are unchanged:

```bash
sudo chown root:wazuh /var/ossec/active-response/bin/<script>
sudo chmod 750 /var/ossec/active-response/bin/<script>
```

The 4.x manager `<command>` / `<active-response>` registration is replaced by a channel created in **Explore → Active Responses** and an Alerting monitor with query `wazuh.rule.id: 5763` whose trigger's **Add active response** action points at the channel. `<repeated_offenders>` has no direct replacement — model escalation in the monitor query.

For the channel schema, see [`docs/dev/modules/active-responses.md`](../../dev/modules/active-responses.md).

---

## Default scripts

| 4.x script                                                                                   | 5.x replacement                                        | Notes                                                               |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------- |
| `firewall-drop`, `default-firewall-drop`, `firewalld-drop`, `pf`, `npf`, `ipfw`, `netsh.exe` | `block-ip`                                             | One cross-platform executable; backend selection is internal.       |
| `route-null`, `host-deny`                                                                    | `block-ip` (route / hosts.deny fallbacks)              | Used when no native firewall is available.                          |
| `ip-customblock`                                                                             | `block-ip` (or a custom script using the new contract) | Folded.                                                             |
| `disable-account`                                                                            | `disable-account`                                      | Retained. Rewrite only if wrapped by a custom JSON-parsing script.  |
| `restart-wazuh`                                                                              | _(removed from AR)_                                    | Agent restart belongs to the Control Module.                        |
| `wazuh-slack`                                                                                | _(removed)_                                            | Use **Explore → Notifications → Channels** for Slack notifications. |

For every migrated AR that referenced a consolidated script, set **Executable** to `block-ip` (or `disable-account`).

---

## Migration steps

1. **Finish the stack upgrade** ([Migration guide](../../ref/migration-4x-5x.md)) through dashboard startup. AR can only be validated once the manager and indexer are on 5.x.
2. **Remove legacy AR config** from `/var/ossec/etc/ossec.conf`: delete every `<command>` and `<active-response>` block.
3. **Rewrite custom scripts** following the [recipe above](#migration-recipe). Re-apply `root:wazuh` ownership and `750` permissions.
4. **Recreate each AR** under **Explore → Active Responses → Create active response**, using the [field mapping table](#field-mapping-4x-xml--5x-channel) and the [Default scripts](#default-scripts) translation.

   ![Side menu — Explore → Active Responses](../images/ar-explore-menu-entry.png)

   The creation form replaces the 4.x `<command>` / `<active-response>` XML blocks. Each row in the field-mapping table corresponds directly to a field in this form; conditional fields (**Stateful timeout**, **Agent ID**) only appear once **Type** or **Location** select the matching value.

   ![Create active response — Configurations panel](../images/ar-create-form-configurations.png)

5. **Wire each channel to a monitor** of type **Active Response**, encoding the 4.x match condition as the monitor query (e.g. `wazuh.rule.id: 5763`). The monitor type **must** be `Active Response` — no other type exposes the **Add active response** action.

   ![Monitor type — Active Response](../images/ar-monitor-type-active-response.png)

   In the trigger, the **Actions** section now exposes two separate buttons — **Add notification** (generic notifications) and **Add active response** (AR channels). Pick **Add active response** and select the channel created in the previous step.

   ![Trigger — Add active response action](../images/ar-trigger-action.png)

6. **Restart and smoke-test:**

   ```bash
   sudo systemctl restart wazuh-manager
   ```

   Generate the triggering event and open **Discover** with the `wazuh-active-responses*` index pattern. Within ~60 s an execution document appears; expand it to confirm `wazuh.active_response.{name,type,executable,location}` match the channel, and that `event.doc_id` / `event.index` point back to the source alert. For stateful AR, wait `stateful_timeout` seconds and verify the revert (a second log line in `/var/ossec/logs/active-responses.log` on the agent, plus restored connectivity for `block-ip`).

   ![Discover — Expanded active response document](../images/ar-discover-document-expanded.png)

## Post-migration validation

- Every 4.x `<active-response>` block has a matching entity in **Explore → Active Responses** with the values from the inventory.
- Custom scripts under `/var/ossec/active-response/bin/` use the 5.x JSON contract (no references to `parameters.alert.data.*` or `add` / `delete` / `continue`).
- `ossec.conf` contains no `<command>` or `<active-response>` blocks.
- The smoke test from [Migration steps](#migration-steps) (step 6) passes for at least one migrated AR.

---

## Troubleshooting

Items below are specific to the 4.x → 5.x migration. For symptoms that are not migration-specific, the general diagnostic flow is:

| Symptom                                         | Likely cause                                                      | Action                                                                 |
| ----------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------- |
| AR is not listed in the trigger selector        | The monitor is not _Active Response_, or the channel is muted     | Recreate the monitor as _Active Response_; unmute the channel          |
| No execution record appears in **Discover**     | Indexer notifications or alerting plugins missing                 | Ask your administrator to verify the plugin installation               |
| Record present but no effect on the agent       | Manager did not deliver the command, or the agent is disconnected | Check the manager service and the agent connection                     |
| A stateful AR does not revert after the timeout | Timeout too large, or the executable does not support reversal    | Confirm the timeout; ask your administrator to verify reversal support |

**AR entities not visible after upgrade.** Open **Dashboard Management → Index Patterns** and verify the `wazuh-active-responses*` pattern exists. If it is missing, ask your administrator to inspect the dashboard logs.

**Custom script silently does nothing.** The script still parses the 4.x JSON. `command` is now `enable`, not `add`; `parameters.alert.data.srcip` no longer exists (use `source.ip`). Re-apply the [recipe](#migration-recipe).

**AR fires but the agent never receives it.** Confirm the agent is on 5.0 or later (pre-5.0 agents are filtered out of dispatch). If the version is fine, inspect the manager logs for dispatch errors.

**Permission errors on custom scripts.** Re-apply:

```bash
sudo chown root:wazuh /var/ossec/active-response/bin/<script>
sudo chmod 750 /var/ossec/active-response/bin/<script>
```

### `<repeated_offenders>` is gone

`execd` keeps an in-memory dedup table but exposes no escalating-timeout knob. Substitutes:

- Count repeat occurrences in the monitor query and only fire the AR once a threshold is met.
- Use two AR channels with different **Stateful timeout** values and route via two monitors.
- Accept the loss where escalation was nice-to-have.

### `Location = server` from 4.x

Manager-side execution does not exist in 5.x. If the manager host runs a co-located Wazuh agent, use **Location** = `Defined agent` with that agent's ID. Otherwise install an agent on the manager host or relocate the action elsewhere.

---

## Rollback

AR cannot be rolled back independently — restore it as part of the full stack rollback ([Migration guide — Rollback](../../ref/migration-4x-5x.md#rollback-procedure)). 4.x and 5.x AR pipelines do not coexist: a 5.x manager does not parse the legacy XML, and a 5.x agent invokes scripts with the new JSON contract, so restoring 4.x config or scripts on a 5.x install does **not** recover 4.x behavior.

---

## Additional resources

- [Migration guide (4.x to 5.x)](https://github.com/wazuh/wazuh-dashboard-plugins/blob/main/docs/ref/migration-4x-5x.md)
- [Developer AR docs (channel schema)](https://github.com/wazuh/wazuh-dashboard-plugins/blob/main/docs/dev/modules/active-responses.md)
- [Wazuh 4.14 AR reference](https://documentation.wazuh.com/4.14/user-manual/capabilities/active-response/)
- [CHANGELOG](../../../CHANGELOG.md)
