# Remote Agent Upgrade Migration Guide (4.x to 5.x)

The remote agent upgrade mechanism is preserved in 5.x. The same `PUT /agents/upgrade` and `PUT /agents/upgrade_custom` API endpoints exist, and the `/var/wazuh-manager/bin/agent_upgrade` binary is still available as a command-line alternative that calls the same framework. WPK files keep their format and are still installed by the agent's own upgrade module. What did change is the delivery path: the manager no longer drives the WPK transfer from the API request path. Instead, it stores a `remote_upgrade` task in the Task Manager, and `remoted`'s own task-polling thread delivers it to agents confirmed below v5.0.0 by pushing the WPK over the agent's existing legacy session on port 1514 (see [`remoted.legacy_task_polling_interval`](../../ref/modules/remoted/configuration.md#remotedlegacy_task_polling_interval)). The manager side is described end to end in [Agent upgrades](../../ref/modules/task_manager/agent-upgrades.md). Two breaking requirements must be met before any remote upgrade to 5.0.0+ can succeed:

1. **HTTPS connectivity on port 1517.** A 4.x agent reaches the manager over the legacy protocol on port 1514 (TCP or UDP); once upgraded to 5.x it talks HTTPS to the manager's agent listener, on port `1517` by default (`<remote><https><port>`). The 4.x `<client><server><port>` and `<protocol>` are not read any more: an upgraded agent keeps the manager address and connects to `<address>:1517/wazuh-manager`. The WPK installer checks that this endpoint answers **before** installing, and aborts the upgrade (`upgrade_result` `2`, the agent stays on 4.x) when it does not. Open outbound TCP `1517` from the agents to the manager before upgrading; port 1514 stays needed for as long as agents remain on 4.x, since that is where the WPK is pushed.
2. **Intermediate version requirement.** Direct remote upgrade to v5.0.0+ from agents older than v4.14.0 is rejected by the manager and cannot be overridden with `--force`. Agents on v4.13.x or earlier must be upgraded to v4.14.x first.

---

## Breaking changes at a glance

| Area                                         | 4.x behavior                                                                                 | 5.x behavior                                                                                                                                                                                                                                                                       |
| -------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent-manager transport                      | Legacy protocol on port 1514, TCP or UDP selectable via `<protocol>`                         | An upgraded agent talks HTTPS to port `1517` (`<address>:1517/wazuh-manager`). `<protocol>` and the 4.x `<client><server><port>` are not read; the WPK installer aborts when that endpoint does not answer. The manager keeps serving 4.x agents on 1514 while `<remote><legacy><enabled>` is `yes` (the installer writes `yes`) |
| Minimum agent version for 5.x remote upgrade | Not applicable (4.x managers only upgraded to 4.x)                                           | v4.14.0, older agents are rejected with `"Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first"`                                                                                                                                                             |
| `force` flag                                 | Bypasses same-version and version-exceeds-manager checks                                     | Same as before, but **cannot** bypass the intermediate version requirement                                                                                                                                                                                                         |
| WPK delivery to the agent                    | Manager pushes the WPK to the agent through Remoted (open/write/close/sha1/upgrade commands) | Manager stores a `remote_upgrade` task in the Task Manager. `remoted`'s own task-polling thread delivers it to agents confirmed below v5.0.0 by pushing the WPK over the agent's existing session, using the same open/write/close/sha1/upgrade commands as 4.x. |
| Upgrade result reporting                     | Agent reported success/failure back to the manager, which recorded it as the task's status   | No outcome is recorded: tasks stay `delivered` whether the push and the install succeed or not, and `tasks.db` has no `failed` status. A 4.x agent's result ack (`upgrade_update_status`) is logged by `remoted` (`WARNING` when the agent reports a failure), answered with `clear_upgrade_result`, and also passed to the Engine like any other agent event. A push failure the manager itself detects is retried and then logged by `remoted`. Follow progress through the reported agent version, the agent's log and `remoted`'s log — see [Delivery to agents below v5.0.0](#delivery-to-agents-below-v500) |
| HTTPS `verification_mode` vs. upgrade target  | Not applicable (no HTTPS transport in 4.x)                                                    | Upgrading to v5.0.0+ while `remoted`'s `<remote><https><verification_mode>` is not `none` is rejected (repo-based path: unless `force_upgrade` is set; custom-WPK path: unconditionally)       |
| Manager trust anchor on the agent            | Not applicable (no TLS between agent and manager in 4.x)                                     | An agent upgraded to 5.x has no enrollment token to take an anchor from, so `remoted` pushes the manager's CA over the same upgrade channel, to `var/incoming/root-ca.pem`, before issuing `upgrade`. Controlled by `<remote><legacy><ca_delivery>` (default `yes`); never fails the upgrade. See [Trust anchor delivery](#trust-anchor-delivery-to-legacy-agents) |
| Custom WPK location                          | `file_path` could be any absolute path on the manager; the manager pushed that file directly | `file_path` must resolve **inside** `/var/wazuh-manager/var/upgrade/` (symlinks followed). Anything else is rejected with `The WPK file does not exist`. The agent now fetches the file by name from that directory, so a path outside it named a file the delivery side would never find |
| When `<remote>` changes take effect for upgrades | Read per request                                                                          | Read once when `wazuh-manager-modulesd` starts. Changing `<remote><legacy>` or `<remote><https><verification_mode>` needs modulesd restarted as well as remoted, or upgrade requests keep applying the previous value |
| Manager-side upgrade configuration | `<agent-upgrade>` section, with `<enabled>` and `<wpk_repository>` | Moved into `<task-manager>` as `<upgrade_enabled>` and `<wpk_repository>`. **`<agent-upgrade>` is no longer a valid manager section and the schema rejects it** — a manager configuration still carrying one is refused with `Invalid configuration at '/agent-upgrade'` and the manager will not start. See [Configuration changes](#configuration-changes) below |
| Manager-side upgrade socket | `queue/tasks/upgrade`, served by the agent-upgrade module of `wazuh-modulesd` | Served on the Task Manager's `queue/sockets/task-http.sock` as `POST /v1/agents/upgrade` and `POST /v1/agents/upgrade-custom`. `queue/tasks/upgrade` no longer exists |

---

## Configuration changes

The manager side of agent upgrades now runs inside the Task Manager, so its two settings moved with
it. This is a **hard failure**, not a silent default: the manager configuration schema rejects an
`<agent-upgrade>` section outright, so a file carrying one has to be edited before the manager will
start.

Before (4.x):

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <wpk_repository>packages.wazuh.com/4.x/wpk/</wpk_repository>
</agent-upgrade>
```

After (5.x; both options are optional — `upgrade_enabled` defaults to `yes`, and with no
`wpk_repository` the repository is picked from the target version, `packages.wazuh.com/5.x/wpk/` for
a 5.x target):

```xml
<task-manager>
  <upgrade_enabled>yes</upgrade_enabled>
  <wpk_repository>packages.wazuh.com/5.x/wpk/</wpk_repository>
</task-manager>
```

`<agent-upgrade>` still exists **on an agent**, where it controls what that agent accepts — whether
it can be upgraded remotely, and how it verifies the WPK signature. Only the manager's half moved;
see the [Agent Upgrade configuration reference](../../ref/modules/agent_upgrade/configuration.md).

The resolved values are reported under the Task Manager in `getconfig`, as
`task-manager.agent_upgrade`, rather than under an `agent-upgrade` module of their own. Every option
and the internal options of the upgrade path are in the
[Task Manager configuration reference](../../ref/modules/task_manager/configuration.md#agent-upgrades).

---

## Pre-migration

### 1. Verify HTTPS connectivity on port 1517

Once an agent restarts as 5.x it connects to the manager over HTTPS on port 1517 (the manager's
`<remote><https><port>`), and the WPK installer refuses to upgrade an agent that cannot reach it. To
confirm reachability, run this check from each agent host (or from a host in the same network segment
as the agent):

```bash
# Linux / macOS
nc -zv <MANAGER_IP> 1517
```

```powershell
# Windows (PowerShell)
Test-NetConnection -ComputerName <MANAGER_IP> -Port 1517
```

If the connection is refused or times out, update the firewall rules on the agent host and any network devices between agent and manager before proceeding:

**Linux, iptables**

```bash
sudo iptables -A OUTPUT -p tcp --dport 1517 -d <MANAGER_IP> -j ACCEPT
```

**Linux, firewalld**

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="<MANAGER_IP>" port port="1517" protocol="tcp" accept'
sudo firewall-cmd --reload
```

**Windows, netsh (cmd as Administrator)**

```cmd
netsh advfirewall firewall add rule name="Wazuh agent outbound 1517" dir=out action=allow protocol=TCP remoteip=<MANAGER_IP> remoteport=1517
```

**macOS, pf**

```bash
# Add to /etc/pf.conf (or a file included from it)
pass out proto tcp from any to <MANAGER_IP> port 1517

# Reload the ruleset
sudo pfctl -f /etc/pf.conf
```

> [!NOTE]
> Port 1517 must allow **outbound TCP** from the agent to the manager, and the manager's own
> firewall must accept it. Keep 1514 open as well until every agent runs 5.x: the WPK is pushed to
> 4.x agents over their legacy session. See
> [Agent-manager protocol from 4.x to 5.x](agent-manager-protocol.md) for the full port list.

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

The manager downloads the WPK from the Wazuh repository before making it available to the agent. If the manager does not have outbound access to the WPK repository, prepare a custom WPK and use the custom upgrade method instead, see [Custom WPK upgrade](#custom-wpk-upgrade).

### 4. Confirm the `openssl` command on Linux agents

The Linux upgrade script validates the [CA the manager delivers](#trust-anchor-delivery-to-legacy-agents) with the `openssl` command-line tool. The agent package does not depend on it, and some supported images ship only the library (`openssl-libs`) or keep a custom build outside root's `PATH`. Without it the upgrade still succeeds, but the agent comes up verifying nothing (see [When the CA cannot be validated on the agent](#when-the-ca-cannot-be-validated-on-the-agent)).

The script runs with the `PATH` of the agent's own daemons, which on some distributions is shorter than a root login shell's (on CentOS 7, for example, it has no `/root/bin`). Check each Linux agent with that `PATH` before upgrading, and install the distribution's `openssl` package where this prints nothing:

```bash
sudo env -i PATH="$(sudo tr '\0' '\n' < /proc/$(pgrep -xo wazuh-execd)/environ | sed -n 's/^PATH=//p')" sh -c 'command -v openssl'
```

macOS ships `openssl` (LibreSSL) and Windows agents validate the CA with .NET, so neither needs anything extra.

---

## Remote upgrade workflow in 5.x - legacy agents

```
API request or agent_upgrade binary (target: an agent below v5.0.0)
    └─► Task Manager, upgrade routes (queue/sockets/task-http.sock)
            ├─► validates each agent's version and platform
            ├─► downloads and verifies the WPK -- once per distinct
            │       package, however many agents were requested
            └─► stores one remote_upgrade task per agent in tasks.db,
                    in a single transaction
                            └─► remoted's own polling thread confirms the
                                    agent is still below v5.0.0 and pushes
                                    the WPK over the agent's existing 1514
                                    session (open/write/close/sha1/upgrade)
```

## Remote upgrade workflow in 5.x - 5.x agents

```
API request or agent_upgrade binary
    └─► Task Manager, upgrade routes (queue/sockets/task-http.sock)
            ├─► validates each agent's version and platform
            ├─► downloads and verifies the WPK -- once per distinct
            │       package, however many agents were requested
            └─► stores one remote_upgrade task per agent in tasks.db,
                    in a single transaction
                            └─► Agent picks up the task on its next poll to the manager
                                    └─► Agent downloads the WPK from the manager (HTTPS)
                                            └─► Agent validates SHA1 and executes the installer
```

The agent-facing task payload contains four fields:

| Field         | Purpose                                                                                 |
| ------------- | --------------------------------------------------------------------------------------- |
| `wpk_file`    | WPK filename the agent must download from the manager                                   |
| `wpk_sha1`    | SHA-1 the agent must reproduce before running the installer                             |
| `installer`   | Installer script inside the WPK (`upgrade.sh` on Linux/macOS, `upgrade.bat` on Windows) |
| `wpk_version` | Version the WPK installs. Consulted only by the legacy delivery path, to decide whether to send the manager's CA (see [Trust anchor delivery](#trust-anchor-delivery-to-legacy-agents)). Empty on the custom-WPK path, where the file name is not authoritative about what it installs |

### Delivery to agents below v5.0.0

For agents below v5.0.0, `remoted` pushes the WPK bytes to the agent itself, with the same
`open`/`write`/`close`/`sha1`/`upgrade` commands as 4.x (see
[`remoted.legacy_task_polling_interval`](../../ref/modules/remoted/configuration.md#remotedlegacy_task_polling_interval)):

- **A rejection** (the agent answered, but not with success) is retried up to 5 times within the same
  poll cycle.
- **No response at all** is not retried in that cycle: the task goes to an in-memory retry list (at
  most 100 entries, each kept for up to an hour) that later cycles pick up, so one unresponsive agent
  does not hold up the others.
- **Failures a retry cannot fix** (a missing local WPK file, an installer that already ran and
  reported failure) are not retried.

Retried attempts are logged at `debug` level except the last, which is a `warning`; a task that runs
out of attempts or ages out of the retry list is logged and dropped. Its row in `tasks.db` stays
`delivered` either way: the manager records no outcome.

An agent that is still on 4.x after the attempt (a step to 4.14.x, or a 5.x install that failed)
reports its result over the legacy session as `upgrade_update_status`. `remoted` logs it (`INFO` on
success, `WARNING` on a failure the agent reports), replies with `clear_upgrade_result` — which stops
the agent from resending it — and passes the message on to the Engine like any other agent event.
Replies are sent from the delivery thread, one per agent however often it resends, each waiting at
most 10 seconds for the agent's answer, without delaying the next poll cycle. If an agent does not
answer the reply, its acks are not answered again for 5 minutes. The agent keeps resending on its own
backoff, so a resend that is not answered (including when more than 1024 agents are waiting for a
reply at once) is answered on a later one. An agent that comes up as 5.x reports its result once, as a stateless `upgrade_result` event (see
[Agent Upgrade](../../ref/modules/agent_upgrade/README.md#flow)).

Progress is observable through:

- The agent version reported by `GET /agents?agents_list=<id>&select=id,version,status` once the
  upgrade completes and the agent reconnects.
- `remoted`'s log (`legacy_task_delivery:` lines) for push failures and the agent's reported result.
- The agent-side logs (`/var/ossec/logs/ossec.log`, and `/var/ossec/logs/upgrade.log` for the
  installer).

---

## Trust anchor delivery to legacy agents

A 5.x agent verifies the manager's HTTPS listener against a CA it received in its enrollment token.
An agent that reaches 5.x by *upgrade* never sees one: it already holds a `client.keys` identity
from its original enrolment, so it does not enrol again, and re-enrolling would cost its identity
continuity. Without an anchor, that agent cannot verify the manager it is about to start talking
to over HTTPS.

The manager closes that gap over the upgrade channel itself. Between verifying the WPK's SHA-1 and
issuing the `upgrade` command, `remoted` pushes its own CA certificate to the agent with a second
`open`/`write`/`close`/`sha1` cycle, landing it at `var/incoming/root-ca.pem` (`incoming\root-ca.pem`
on Windows). The agent's installer reads it from there.

The security property is worth stating plainly: the 4.x channel is encrypted and integrity-protected
with the agent's own key from `client.keys`, so an attacker without that key cannot inject a message
the agent will accept. The symmetric-key channel is what bootstraps the asymmetric anchor — there is
no unauthenticated moment and no trust-on-first-use window.

Details that matter in practice:

- **`var/incoming/`, not `var/upgrade/`.** The `com` file-transfer commands are jailed to
  `var/incoming/`, and the `upgrade` command clears `var/upgrade/` before unpacking the WPK into it
  — a CA staged there would be deleted by the very command meant to consume it.
- **The file is named `root-ca.pem`**, the same name it has on the manager and the same name the
  agent's installer already looks for as its drop-in. Nothing renames it anywhere along the path,
  so a hand-staged anchor and a delivered one produce identical layouts.
- **5.x targets only.** An agent being stepped up to an intermediate 4.14.x release receives no CA.
- **No 4.x agent change is required.** This uses only `com` behaviour already shipped in 4.x,
  verified against v4.14.0 — the oldest version from which a direct upgrade to 5.0 is permitted.
- **The WPK signature chain is untouched.** The CA is a separate file, never inside the signed
  package, and is still verified against `wpk_root.pem` exactly as before.
- **Both upgrade paths behave identically**, repository and custom WPK, from master and worker
  nodes alike.

### When the CA cannot be delivered

The upgrade always proceeds. A failure is logged as its own step — never as a generic upgrade
failure — at `error` when the manager refuses to send (see below) and at `warning` when the transfer
itself did not complete. An agent off the air is worse than an agent without an anchor.

The manager refuses to send the CA, and logs an actionable error, when:

- the configured `remote.https.ca_certificate` is missing, unreadable, or is not a complete PEM
  certificate; or
- that CA does not sign the certificate the manager's own HTTPS listener serves. An agent that
  pinned such an anchor would fail every connection afterwards, which is worse than sending nothing.

Delivery status is visible in the manager log only. As with WPK delivery itself, `tasks.db` records
no per-task outcome — see the "Upgrade result reporting" row in [Breaking changes at a
glance](#breaking-changes-at-a-glance).

### When the CA cannot be validated on the agent

On Linux the upgrade script checks the delivered CA with the `openssl` command, and then checks that
it verifies the manager's certificate at the address the agent dials, before installing it as the
agent's anchor. If it does not verify the manager (the CA was rotated, the address is not in the
certificate, or something else answered on that port), the upgrade aborts with `upgrade_result` `2`,
the CA is kept in `var/incoming`, and the agent keeps running its current version, so neither a stale
CA nor an impostor on the network can take the agent off the air or leave it unverified. Fix the
manager certificate and retry, or, on a 5.x agent, install the anchor with `--certs-only` (below).
The check runs only where the agent will verify against the anchor: it is skipped with the agent's
own `<certificate_authorities>` and under `none` or `certificate`. When it is skipped, or when `curl`
cannot run it (missing, or no TLS 1.3 support, as on macOS), the CA is installed on its own validation. When `openssl` is not found, the script leaves the CA in
`var/incoming/root-ca.pem`, installs no anchor, and the upgrade still reports success. If an anchor
is already present, the delivered copy is discarded instead. The upgraded agent runs with
`verification_mode` resolved to `none`:

- `upgrade.log` says `cannot be validated: openssl was not found on this host` and how to recover.
- `ossec.log` logs `(4126)` on every start until an anchor is installed, next to the generic
  `TLS verification is DISABLED (verification_mode=none).` warning.
- Later remote upgrades of that agent abort at the installer's certificate trust check
  (`upgrade_result` `2`) unless the OS trust store already verifies the manager's certificate: a
  5.x agent with no anchor is not given the pass a 4.x one gets. The agent keeps running on its
  current version.

To recover an agent already upgraded this way, install the anchor with an enrollment token. The
agent keeps its id and `client.keys`, and the step needs no `openssl` command:

1. On the master, mint a token for the address the agent already connects to. `--no-credential`
   is enough, since the token is only used to fetch and pin the CA:
   ```bash
   sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <manager address> --no-credential --ttl 1h > token
   ```
2. Copy the token to the agent and install the anchor with the agent stopped:
   ```bash
   sudo systemctl stop wazuh-agent
   sudo /var/ossec/bin/wazuh-agent-auth --token-file token --certs-only
   sudo systemctl start wazuh-agent
   ```
3. Confirm that `/var/ossec/etc/certs/root-ca.pem` exists and that `ossec.log` no longer logs
   `(4126)`. `--certs-only` also removes `/var/ossec/var/incoming/root-ca.pem`, so a later upgrade
   cannot install that copy over the anchor.

Do not copy the file from `var/incoming` into place by hand or re-run the upgrade to pick it up. A
hand-copied anchor does not get the ownership and marker `--certs-only` writes (see the
[client module reference](../../ref/modules/client/README.md)). Once the agent runs 5.x the manager
no longer delivers its CA, so installing `openssl` afterwards changes nothing for that agent; install
it on the agents still waiting to be upgraded.

### Certificate requirements

The manager cannot check that its certificate covers the address a given agent dials — behind NAT, a
load balancer, or in a cluster it does not know that address. Certificates are also not synchronized
between cluster nodes, and the CA sent is the one configured on whichever node holds the agent's
session. Two requirements are therefore yours to meet before upgrading a fleet:

1. Every node's agent-facing certificate is issued by the CA being distributed.
2. That certificate carries every address agents actually dial among its subjectAltName entries —
   the cluster VIP, each node's own address, and any NAT address.

`remoted` warns at start-up if its certificate carries no usable SAN at all (no DNS or IP entry
beyond loopback and the host's own name), but it cannot detect a SAN list that is merely missing the
right address.

### Disabling it

Set `<remote><legacy><ca_delivery>no</ca_delivery></remote>` when a corporate PKI or a
configuration-management tool distributes the anchor by its own means. With it off, the upgrade push
is byte-for-byte what it was before this feature existed. Unlike `<remote><legacy><enabled>` and
`<remote><https><verification_mode>`, this option is read by `remoted` alone, so changing it does not
also require restarting `wazuh-manager-modulesd`.

---

## Direct upgrade (agents on v4.14.x or later)

### Via API

**Step 1: Authenticate:**

```bash
TOKEN=$(curl -sk -u <user>:<password> -X POST \
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
         "001",
         "002"
      ],
      "total_affected_items": 2,
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
               "code": 1819,
               "message": "Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first"
            },
            "id": ["002"]
         }
      ]
   },
   "message": "No upgrade task was created",
   "error": 1
}
```

### Via binary

The binary is fire-and-forget in 5.x: it creates the upgrade task(s) and returns immediately, without
waiting for or reporting the outcome (4.x waited and printed each agent's result):

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 002
```

To target a specific version:

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 002 -v v5.0.0
```

```text
Upgrade tasks created for 2 agent(s).
Note: Agents will execute upgrades autonomously. Use agent logs to track progress.
```

Agents that cannot be upgraded are listed first, as `Agent <ID> upgrade failed. Status: <error>`.
`-F`/`--force` skips the same-version and version-above-manager checks but, like `force` in the API,
not the v4.14.0 intermediate requirement. Every flag is listed in the
[`agent_upgrade` reference](../../ref/modules/agent_upgrade/README.md#agent_upgrade).

## Two-step upgrade path (agents below v4.14.0)

Agents on v4.13.x or earlier require an intermediate upgrade to v4.14.x before they can be upgraded to 5.0. The 5.x manager accepts a target below its own version, given with `-v`/`--version` (or `upgrade_version` in the API).

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

Wait until the agent reports `v4.14.5` (`GET /agents?agents_list=002&select=id,version,status`)
before running step 2.

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

Use the custom upgrade method when the manager does not have access to the WPK repository or when a private WPK is required.

The custom WPK file must be placed **inside `/var/wazuh-manager/var/upgrade/` on the manager**, be readable by the `wazuh-manager` user, and — in a clustered deployment — exist in that directory on **every** node before triggering the upgrade.

> **Changed in 5.x.** `file_path` used to accept any absolute path, because the manager pushed that file to the agent itself. The agent now fetches the WPK by *name* from the upgrade directory, so a path anywhere else names a file the delivery side would never find. Such a path is now rejected outright with `The WPK file does not exist`, rather than producing a task that fails later. Symlinks are resolved before the check, so a link inside the directory pointing outside it is rejected too.

### Via API

```bash
curl -k -X PUT "https://localhost:55000/agents/upgrade_custom?pretty=true&agents_list=002&file_path=/var/wazuh-manager/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk&installer=upgrade.sh" -H "Authorization: Bearer $TOKEN"
```

### Via binary

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 -f wazuh_agent_v5.0.0_linux_x86_64.wpk -x upgrade.sh
```

`-f` takes the bare file name or a path inside `/var/wazuh-manager/var/upgrade/`; the CLI exits with
an error before creating any task when the file is not there. `-x` names the installer inside the WPK
(`upgrade.sh` for Linux/macOS, `upgrade.bat` for Windows). See the
[`agent_upgrade` reference](../../ref/modules/agent_upgrade/README.md#agent_upgrade).

The manager still enforces the intermediate version requirement for custom WPK files whose name
carries a `_v<VERSION>_` token, as in `wazuh_agent_v<VERSION>_<rest>.wpk`. Files without one skip the
manager-side version check and rely on the agent-side pre-install script to block an incompatible
version. See [Version constraints](../../ref/modules/task_manager/agent-upgrades.md#version-constraints).

---

## Validation checklist

After triggering the upgrade, confirm all conditions below are met before declaring the migration complete:

- Agent version reported in `GET /agents?agents_list=<id>&select=id,version,status` is the target (for example `v5.0.0`).
- Agent connection status is `active`.
- `ossec.log` on the agent contains no errors related to the upgrade (`grep -i "upgrade" /var/ossec/logs/ossec.log`).
- The manager log records the CA step for each upgraded agent, and no warning or error against it
  (`grep "legacy_task_delivery.*CA" /var/wazuh-manager/logs/wazuh-manager.log`). An agent whose CA delivery
  failed is still upgraded and connected, but verifies nothing — worth catching before the migration
  is declared complete.
- On each Linux or macOS agent, the trust anchor is in place (`sudo ls -l /var/ossec/etc/certs/root-ca.pem`)
  and `ossec.log` has no `(4126)`. A delivered CA the agent could not validate leaves the agent
  upgraded and connected but unverified, and the manager log does not show it. See
  [When the CA cannot be validated on the agent](#when-the-ca-cannot-be-validated-on-the-agent).

---
