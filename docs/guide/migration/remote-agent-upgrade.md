# Remote Agent Upgrade Migration Guide (4.x to 5.x)

The remote agent upgrade mechanism is preserved in 5.x. The same `PUT /agents/upgrade` and `PUT /agents/upgrade_custom` API endpoints exist, and the `/var/wazuh-manager/bin/agent_upgrade` binary is also available as a command-line alternative that calls the same underlying framework. The WPK-based transfer flow is unchanged. Two breaking requirements must be met before any remote upgrade to 5.0.0+ can succeed:

1. **TCP-only agent connectivity on port 1514.** In Wazuh 5.x, the agent ignores the `<protocol>` configuration option and always connects to the manager over TCP, regardless of what it was set to in 4.x. The manager still accepts UDP, but no 5.x agent will initiate a UDP connection. The WPK transfer uses the agent's current 4.x communication channel while the upgrade is being delivered, which can still be UDP for agents that have not restarted into 5.x yet. The risk arises after an agent that was connecting over UDP is upgraded: it restarts in TCP mode, and if outbound TCP on port 1514 is blocked in the firewall, the agent cannot reconnect and appears as `disconnected`, not `active`. Firewall rules must be updated to allow outbound TCP on port 1514 from the agent to the manager **before** the agent is upgraded to 5.x, or the agent will be unreachable after the upgrade.
2. **Intermediate version requirement.** Direct remote upgrade to v5.0.0+ from agents older than v4.14.0 is blocked by the upgrade module and cannot be overridden with `--force`. Agents on v4.13.x or earlier must be upgraded to v4.14.x first.

---

## Breaking changes at a glance

| Area | 4.x behavior | 5.x behavior |
|------|-------------|-------------|
| Agent-manager transport | TCP or UDP selectable via `<protocol>` | Agent always uses TCP; `<protocol>` is silently ignored by the agent (manager still accepts UDP) |
| Minimum agent version for 5.x remote upgrade | Not applicable (4.x managers only upgraded to 4.x) | v4.14.0, older agents are rejected with `"Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first"` |
| `force` flag | Bypasses same-version and version-exceeds-manager checks | Same as before, but **cannot** bypass the intermediate version requirement |
| Upgrade result notification | Polling only via `GET /agents/upgrade_result` | Manager receives an asynchronous notification via router topic `upgrade_notifications`; result also available via polling |

---

## Pre-migration

### 1. Verify TCP connectivity on port 1514

The WPK transfer uses the same channel as regular agent-manager communication. The **manager** listens on port 1514; agents connect outbound to it. To confirm TCP reachability, run this check from each agent host (or from a host in the same network segment as the agent):

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

## Remote upgrade workflow in 5.x

```
API request or agent_upgrade binary
    └─► Agent Upgrade module (queue/tasks/upgrade)
            ├─► validates version requirements and downloads WPK
            └─► sends WPK commands to Remoted (queue/sockets/remote)
                    └─► Remoted delivers to agent over its current channel
                            └─► agent installs WPK and writes result
                                    └─► Remoted receives result
                                            └─► Router (upgrade_notifications topic)
                                                    └─► Agent Upgrade module updates task status
```

The six commands sent to the agent during WPK transfer are, in order:

| Command | Purpose |
|---------|---------|
| `lock_restart` | Prevent the agent from restarting while the transfer is in progress |
| `open wb <file>` | Open the WPK file for writing on the agent |
| `write <chunk>` | Send the WPK data in chunks (default 32 KB per chunk) |
| `close <file>` | Close and flush the file |
| `sha1 <file>` | Verify the SHA1 checksum of the received file |
| `upgrade <installer>` | Execute the installer (`upgrade.bat` on Windows, `upgrade.sh` elsewhere) |

All six commands travel over the agent-manager channel that is active before the agent restarts. For 4.x agents still configured over UDP, the transfer can use UDP; after the agent upgrades to 5.x, it reconnects only over TCP. If the active channel fails during the transfer, the upgrade module reports one of the following errors: `Send lock restart error`, `Send open file error`, `Send write file error`, `Send close file error`, `Send verify sha1 error`, or `Send upgrade command error`.

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

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wpk_repo` | string | Default repository | WPK repository base URL |
| `upgrade_version` | string | Manager version | Target version (e.g. `v5.0.0`) |
| `use_http` | boolean | `false` | Use HTTP instead of HTTPS to fetch WPK |
| `force` | boolean | `false` | Bypass same-version and version-exceeds-manager checks; does **not** bypass the v4.14.0 intermediate requirement |
| `package_type` | string | auto-detected | Package type override (`rpm`, `deb`) |

Example response:

```json
{
   "data": {
      "affected_items": [
         {
            "agent": "002",
            "task_id": 2
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

**Step 3: Monitor upgrade status:**

Poll the result for each agent:

```bash
curl -k -X GET "https://localhost:55000/agents/upgrade_result?pretty=true&agents_list=001,002" \
  -H "Authorization: Bearer $TOKEN"
```

Or query all pending tasks:

```bash
curl -k -X GET "https://localhost:55000/tasks/status?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

Expected `status` values during a successful upgrade: `In queue` → `Updating` → `Updated`.

### Via binary

The binary blocks until the upgrade completes and prints the result directly:

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 002
```

To target a specific version:

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 002 -v v5.0.0
```

Available flags:

| Flag | Description |
|------|-------------|
| `-a`/`--agents` | One or more agent IDs to upgrade |
| `-v`/`--version` | Target version; defaults to the manager version |
| `-r`/`--repository` | WPK repository base URL |
| `-F`/`--force` | Bypass same-version and version-exceeds-manager checks; does **not** bypass the v4.14.0 intermediate requirement |
| `--http` | Use HTTP instead of HTTPS to fetch WPK |
| `--package_type` | Package type override (`deb`, `rpm`) |
| `-s`/`--silent` | Suppress output |
| `-d`/`--debug` | Debug mode |

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

Use the custom upgrade method when the manager does not have access to the WPK repository or when a private WPK is required. The custom WPK file must be placed on the **manager** (accessible from all cluster nodes for clustered deployments) before triggering the upgrade.

### Via API

```bash
curl -k -X PUT "https://localhost:55000/agents/upgrade_custom?pretty=true&agents_list=002&file_path=/var/wazuh-manager/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk&installer=upgrade.sh" -H "Authorization: Bearer $TOKEN"
```

### Via binary

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 -f /var/wazuh-manager/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk -x upgrade.sh
```

| Flag | Description |
|------|-------------|
| `-f`/`--file` | Path to the WPK file on the manager filesystem |
| `-x`/`--execute` | Installer script inside the WPK (`upgrade.sh` for Linux/macOS, `upgrade.bat` for Windows) |

The `agent_upgrade` module still validates the intermediate version requirement for custom WPK files whose filename follows the canonical pattern `wazuh_agent_v<VERSION>_<rest>.wpk`. Files with non-standard names skip the manager-side version check and rely on the agent-side pre-install script to block an incompatible version.

---

## Validation checklist

After triggering the upgrade, confirm all conditions below are met before declaring the migration complete:

- `GET /agents/upgrade_result?agents_list=<id>` returns `"status": "Updated"` for every upgraded agent (or the binary exited with `Agent upgraded successfully`).
- Agent version reported in `GET /agents/<id>` matches `5.0.0`.
- Agent connection status is `active`.
- `ossec.log` on the agent contains no errors related to the upgrade (`grep -i "upgrade" /var/ossec/logs/ossec.log`).

---
