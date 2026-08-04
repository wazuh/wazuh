# Remote Agent Upgrade Migration Guide (4.x to 5.x)

The remote agent upgrade mechanism is preserved in 5.x. The same `PUT /agents/upgrade` and `PUT /agents/upgrade_custom` API endpoints exist, and the `/var/wazuh-manager/bin/agent_upgrade` binary is still available as a command-line alternative that calls the same framework. WPK files themselves are unchanged. What did change is the delivery path: the manager no longer drives the WPK transfer from the API request path. Instead, it stores a `remote_upgrade` task in the Task Manager, and `remoted`'s own task-polling thread delivers it to agents confirmed below v5.0.0 by pushing the WPK over the agent's existing 1514 session (see [`remoted.legacy_task_polling_interval`](../../ref/modules/remoted/configuration.md)). Two breaking requirements must be met before any remote upgrade to 5.0.0+ can succeed:

1. **TCP-only agent connectivity on port 1514.** In Wazuh 5.x, the agent ignores the `<protocol>` configuration option and always connects to the manager over TCP, regardless of what it was set to in 4.x. The manager still accepts UDP, but no 5.x agent will initiate a UDP connection. The risk arises after an agent that was connecting over UDP is upgraded: it restarts in TCP mode, and if outbound TCP on port 1514 is blocked in the firewall, the agent cannot reconnect and appears as `disconnected`, not `active`. Firewall rules must be updated to allow outbound TCP on port 1514 from the agent to the manager **before** the agent is upgraded to 5.x, or the agent will be unreachable after the upgrade.
2. **Intermediate version requirement.** Direct remote upgrade to v5.0.0+ from agents older than v4.14.0 is blocked by the upgrade module and cannot be overridden with `--force`. Agents on v4.13.x or earlier must be upgraded to v4.14.x first.

---

## Breaking changes at a glance

| Area                                         | 4.x behavior                                                                                 | 5.x behavior                                                                                                                                                                                                                                                                       |
| -------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent-manager transport                      | TCP or UDP selectable via `<protocol>`                                                       | Agent always uses TCP; `<protocol>` is silently ignored by the agent (manager still accepts UDP)                                                                                                                                                                                   |
| Minimum agent version for 5.x remote upgrade | Not applicable (4.x managers only upgraded to 4.x)                                           | v4.14.0, older agents are rejected with `"Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first"`                                                                                                                                                             |
| `force` flag                                 | Bypasses same-version and version-exceeds-manager checks                                     | Same as before, but **cannot** bypass the intermediate version requirement                                                                                                                                                                                                         |
| WPK delivery to the agent                    | Manager pushes the WPK to the agent through Remoted (open/write/close/sha1/upgrade commands) | Manager stores a `remote_upgrade` task in the Task Manager. `remoted`'s own task-polling thread delivers it to agents confirmed below v5.0.0 by pushing the WPK over the agent's existing session, using the same open/write/close/sha1/upgrade commands as 4.x. |
| Upgrade result reporting                     | Agent reported success/failure back to the manager                                           | Fire-and-forget from the manager's perspective; the agent's ack (`upgrade_update_status`) is forwarded to the Engine's event pipeline like any other agent event. A manager-side push failure is only logged, not sent to the Engine. Upgrade progress is observable through the tasks table, the reported agent version, and the agent-side log |
| HTTPS `verification_mode` vs. upgrade target  | Not applicable (no HTTPS transport in 4.x)                                                    | Upgrading to v5.0.0+ while `remoted`'s `<remote><https><verification_mode>` is not `none` is rejected (repo-based path: unless `force_upgrade` is set; custom-WPK path: unconditionally)       |

---

## Pre-migration

### 1. Verify TCP connectivity on port 1514

Once an agent restarts as 5.x it will only try to connect to the manager over TCP on port 1514. To confirm TCP reachability, run this check from each agent host (or from a host in the same network segment as the agent):

```bash
# Linux / macOS
nc -zv <MANAGER_IP> 1514
```

```powershell
# Windows (PowerShell)
Test-NetConnection -ComputerName <MANAGER_IP> -Port 1514
```

If the connection is refused or times out, update the firewall rules on the agent host and any network devices between agent and manager before proceeding:

**Linux, iptables**

```bash
sudo iptables -A OUTPUT -p tcp --dport 1514 -d <MANAGER_IP> -j ACCEPT
```

**Linux, firewalld**

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="<MANAGER_IP>" port port="1514" protocol="tcp" accept'
sudo firewall-cmd --reload
```

**Windows, netsh (cmd as Administrator)**

```cmd
netsh advfirewall firewall add rule name="Wazuh agent outbound 1514" dir=out action=allow protocol=TCP remoteip=<MANAGER_IP> remoteport=1514
```

**macOS, pf**

```bash
# Add to /etc/pf.conf (or a file included from it)
pass out proto tcp from any to <MANAGER_IP> port 1514

# Reload the ruleset
sudo pfctl -f /etc/pf.conf
```

> [!NOTE]
> Port 1514 must allow **outbound TCP** from the agent to the manager. If agents sit behind NAT, ensure the return path from the manager is also open.

### 2. Check agent versions

Identify agents below v4.14.0, they require an intermediate upgrade before they can be remotely upgraded to 5.x.

Via API:

```bash
curl -k -X GET "https://localhost:55000/agents?pretty=true&select=id,name,version,status&limit=500" \
  -H "Authorization: Bearer $TOKEN"
```

Via binary:

```bash
/var/wazuh-manager/bin/agent_upgrade -l
```

```
ID    Name                                Version
002   agent20                             v4.13.1

Total outdated agents: 1
```

The `-l` flag lists all outdated agents with their current version. Agents on v4.14.x or later can be upgraded directly to 5.0 in a single step. Agents below v4.14.0 must go through the path described in [Two-step upgrade path (agents below v4.14.0)](#two-step-upgrade-path-agents-below-v4140).

### 3. Confirm manager has WPK repository access

The `agent_upgrade` module on the manager downloads the WPK from the Wazuh repository before sending it to the agent. If the manager does not have outbound access to the WPK repository, prepare a custom WPK and use the custom upgrade method instead, see [Custom WPK upgrade](#custom-wpk-upgrade).

---

## Remote upgrade workflow in 5.x - legacy agents

```
API request or agent_upgrade binary (target: an agent below v5.0.0)
    └─► Agent Upgrade module (queue/tasks/upgrade)
            ├─► validates version requirements and downloads/validates WPK
            └─► creates a remote_upgrade task in the Task Manager
                    └─► Task Manager stores the task in tasks.db
                            └─► remoted's own polling thread confirms the
                                    agent is still below v5.0.0 and pushes
                                    the WPK over the agent's existing 1514
                                    session (open/write/close/sha1/upgrade)
```

## Remote upgrade workflow in 5.x

```
API request or agent_upgrade binary
    └─► Agent Upgrade module (queue/tasks/upgrade)
            ├─► validates version requirements and downloads/validates WPK
            └─► creates a remote_upgrade task in the Task Manager
                    └─► Task Manager stores the task in tasks.db
                            └─► Agent picks up the task on its next poll to the manager
                                    └─► Agent downloads the WPK from the manager (HTTPS)
                                            └─► Agent validates SHA1 and executes the installer
```

The agent-facing task payload contains three fields:

| Field       | Purpose                                                                                 |
| ----------- | --------------------------------------------------------------------------------------- |
| `wpk_file`  | WPK filename the agent must download from the manager                                   |
| `wpk_sha1`  | SHA-1 the agent must reproduce before running the installer                             |
| `installer` | Installer script inside the WPK (`upgrade.sh` on Linux/macOS, `upgrade.bat` on Windows) |

For agents below v5.0.0, `remoted` streams the WPK bytes to the agent directly, the same way it always has (see [`remoted.legacy_task_polling_interval`](../../ref/modules/remoted/configuration.md)). Wire-level hiccups (a lost step acknowledgment, a disconnect mid-transfer) are retried up to 3 times before the manager gives up; failures a retry can't fix (a missing local WPK file, the agent's installer already ran and reported failure) are not retried. Either way, a push that ultimately fails is only logged on the manager, not sent to the Engine. Progress is observable through:

- The `delivery_time` column of the corresponding row in `tasks.db` — populated by the manager's own `get_pending_tasks` read (a side effect of the poller retrieving the task), not by anything agent-driven; it does not mean the agent has actually installed the WPK.
- The agent's own upgrade result, forwarded to the Engine's event pipeline like any other agent event (`upgrade_update_status`, one of "Upgrade was successful" / "Upgrade failed due missing dependency" / "Upgrade failed"). `remoted` replies to the agent with `clear_upgrade_result` within a few seconds of receiving a well-formed acknowledgment, regardless of whether it reports success or failure — this is what stops the agent's own retry loop (an agent resends the same acknowledgment on a growing backoff until it gets this reply back). The reply is handled by `remoted`'s own background poller rather than inline on receipt, so a burst of acknowledgments never competes with other agents' traffic for processing.
- The agent version reported by `GET /agents/<id>` once the upgrade completes and the agent reconnects.
- The agent-side upgrade log (`/var/ossec/logs/ossec.log`).

---

## Direct upgrade (agents on v4.14.x or later)

### Via API

**Step 1: Authenticate:**

```bash
TOKEN=$(curl -sk -u wazuh-wui:wazuh-wui -X POST \
  "https://<manager_ip>:55000/security/user/authenticate?raw=true")
```

**Step 2: Trigger the upgrade:**

```bash
curl -k -X PUT "https://localhost:55000/agents/upgrade?pretty=true&agents_list=001,002" \
  -H "Authorization: Bearer $TOKEN"
```

Optional query parameters:

| Parameter         | Type    | Default            | Description                                                                                                      |
| ----------------- | ------- | ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `wpk_repo`        | string  | Default repository | WPK repository base URL                                                                                          |
| `upgrade_version` | string  | Manager version    | Target version (e.g. `v5.0.0`)                                                                                   |
| `use_http`        | boolean | `false`            | Use HTTP instead of HTTPS to fetch WPK                                                                           |
| `force`           | boolean | `false`            | Bypass same-version and version-exceeds-manager checks; does **not** bypass the v4.14.0 intermediate requirement |
| `package_type`    | string  | auto-detected      | Package type override (`rpm`, `deb`)                                                                             |

Example response:

```json
{
   "data": {
      "affected_items": [
         {
            "agent": "002",
            "task_id": "7e4b1a2c-8f3d-46a1-9b0e-6d2f8c9a1234"
         }
      ],
      "total_affected_items": 1,
      "total_failed_items": 0,
      "failed_items": []
   },
   "message": "All upgrade tasks were created",
   "error": 0
}
```

If an agent below v4.14.0 is included, it appears in `failed_items`:

```json
{
   "data": {
      "affected_items": [],
      "total_affected_items": 0,
      "total_failed_items": 1,
      "failed_items": [
         {
            "error": {
               "code": 1822,
               "message": "Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first"
            },
            "id": ["002"]
         }
      ]
   },
   "message": "Some upgrade tasks were not created",
   "error": 1
}
```

### Via binary

The binary is fire-and-forget: it creates the upgrade task(s) and returns immediately, without waiting for or reporting the outcome:

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 002
```

To target a specific version:

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 002 -v v5.0.0
```

Available flags:

| Flag                | Description                                                                                                      |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `-a`/`--agents`     | One or more agent IDs to upgrade                                                                                 |
| `-v`/`--version`    | Target version; defaults to the manager version                                                                  |
| `-r`/`--repository` | WPK repository base URL                                                                                          |
| `-F`/`--force`      | Bypass same-version and version-exceeds-manager checks; does **not** bypass the v4.14.0 intermediate requirement |
| `--http`            | Use HTTP instead of HTTPS to fetch WPK                                                                           |
| `--package_type`    | Package type override (`deb`, `rpm`)                                                                             |
| `-s`/`--silent`     | Suppress output                                                                                                  |
| `-d`/`--debug`      | Debug mode                                                                                                       |

## Two-step upgrade path (agents below v4.14.0)

Agents on v4.13.x or earlier require an intermediate upgrade to v4.14.x before they can be upgraded to 5.0. The 5.x `agent_upgrade` module allows targeting a version below the manager version via the `-v`/`--version` parameter (or `upgrade_version` in the API).

### Step 1: Upgrade to v4.14.x

Via API:

```bash
curl -k -X PUT "https://localhost:55000/agents/upgrade?pretty=true&agents_list=002&upgrade_version=v4.14.5" \
  -H "Authorization: Bearer $TOKEN"
```

Via binary:

```bash
/var/wazuh-manager/bin/agent_upgrade -a 002 -v v4.14.5
```

```
/var/wazuh-manager/bin/agent_upgrade -a 002 -v v4.14.5

Upgrading...

Upgraded agents:
        Agent 002 upgraded: v4.13.1 -> v4.14.5
```

> [!NOTE]
> Using `--force` / `force=true` on step 1 is only needed if the agent reports a version equal to or higher than the target. It is not required for a normal version step-up.

### Step 2: Upgrade to v5.0.0

Via API:

```bash
curl -k -X PUT "https://localhost:55000/agents/upgrade?pretty=true&agents_list=002" \
  -H "Authorization: Bearer $TOKEN"
```

Via binary:

```bash
/var/wazuh-manager/bin/agent_upgrade -a 002
```

---

## Custom WPK upgrade

Use the custom upgrade method when the manager does not have access to the WPK repository or when a private WPK is required. The custom WPK file must be placed on the **manager**, be readable by the `wazuh-manager` user, and be accessible from all cluster nodes for clustered deployments before triggering the upgrade.

### Via API

```bash
curl -k -X PUT "https://localhost:55000/agents/upgrade_custom?pretty=true&agents_list=002&file_path=/var/wazuh-manager/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk&installer=upgrade.sh" -H "Authorization: Bearer $TOKEN"
```

### Via binary

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 -f /var/wazuh-manager/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk -x upgrade.sh
```

| Flag             | Description                                                                               |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `-f`/`--file`    | Path to the WPK file on the manager filesystem                                            |
| `-x`/`--execute` | Installer script inside the WPK (`upgrade.sh` for Linux/macOS, `upgrade.bat` for Windows) |

The `agent_upgrade` module still validates the intermediate version requirement for custom WPK files whose filename follows the canonical pattern `wazuh_agent_v<VERSION>_<rest>.wpk`. Files with non-standard names skip the manager-side version check and rely on the agent-side pre-install script to block an incompatible version.

---

## Validation checklist

After triggering the upgrade, confirm all conditions below are met before declaring the migration complete:

- Agent version reported in `GET /agents/<id>` matches `5.0.0`.
- Agent connection status is `active`.
- `ossec.log` on the agent contains no errors related to the upgrade (`grep -i "upgrade" /var/ossec/logs/ossec.log`).

---
