# Agent upgrades

Remote agent upgrades are served by the Task Manager, on two routes of its own socket. This page is
the manager side end to end: what a request does, which agents it accepts, and what it leaves behind
for the agent to pick up.

The agent's half — verifying the WPK's signature and running the installer — belongs to the
[Agent Upgrade module](../agent_upgrade/README.md), which exists only on an agent.

**Configuration:** [`<task-manager>`](configuration.md#agent-upgrades)

---

## What a request does

```
API / agent_upgrade CLI
        │  POST /v1/agents/upgrade  (or /v1/agents/upgrade-custom)
        ▼
queue/sockets/task-http.sock ──► parse, then hand the batch to a worker  ──► answer immediately
                                            │
                        ┌───────────────────┴───────────────────┐
                        │  PER AGENT                            │
                        │  read its row, check platform,        │
                        │  version and delivery gates,          │
                        │  work out which WPK it needs          │
                        └───────────────────┬───────────────────┘
                                            │
                        ┌───────────────────┴───────────────────┐
                        │  PER DISTINCT WPK, not per agent      │
                        │  fetch `versions` once, download once,│
                        │  stage, SHA-1-verify, rename into     │
                        │  var/upgrade/                         │
                        └───────────────────┬───────────────────┘
                                            │
                        ┌───────────────────┴───────────────────┐
                        │  ONE transaction for the whole batch  │
                        │  task_type:   remote_upgrade          │
                        │  agent_id:    <id>                    │
                        │  create_time: <request timestamp>     │
                        │  payload:                             │
                        │    wpk_file:  <bare WPK filename>     │
                        │    wpk_sha1:  <hex digest>            │
                        │    installer: upgrade.sh|.bat         │
                        └───────────────────────────────────────┘
```

**Only the first stage is per agent, and that is the point.** Agents that resolve to the same package
share one repository-index fetch and one download, and every surviving agent's task row is written in
a single database transaction. A 500-agent request against one platform costs one index fetch, one
download and one transaction — not 500 of each.

**The response is a per-agent envelope**, so one agent failing its version check does not affect the
rest of the request.

Requests are answered from a pool of batch workers rather than inline: a cold batch may need a
repository fetch and a 100 MB download before the first task exists, and the same socket is serving
every agent's task polling at the same time. If that pool's queue is full the request is refused with
per-agent error 4 (*Task manager communication error*), which the Server API answers by halving the
chunk and retrying.

Task IDs are derived deterministically from `agent_id`, `task_type` and the request timestamp
forwarded by the API, so the same request reaching several cluster nodes produces the same
`task_id` and does not schedule the upgrade twice.

---

## Version constraints

| Condition | Behavior |
| --- | --- |
| Agent below `v3.0.0` | Rejected — minimum supported version |
| Upgrade target ≥ `v5.0.0` and current agent version < `v4.14.0` | Rejected with `Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first` |
| Target version ≤ current agent version | Rejected unless `force_upgrade` is set |
| Target version > manager version | Rejected unless `force_upgrade` is set |
| Upgrade target ≥ `v5.0.0` and `remoted`'s `remote.https.verification_mode` is not `none` | Rejected. The repository path allows `force_upgrade` to override, with a logged warning; the custom-WPK path has no `force` parameter and so cannot be overridden |
| Agent below `v5.0.0` and `remote.legacy.enabled` false | Rejected — there would be no way to deliver the task |

---

## The WPK file

A WPK is a signed, compressed archive holding the agent binaries and an installer script
(`upgrade.sh` on Linux/macOS, `upgrade.bat` on Windows) for one platform and version. Each is
published alongside a SHA-1 checksum used to validate it end to end.

The repository URL defaults to `packages.wazuh.com/<major>.x/wpk/`, derived from the target version,
and is overridden with [`<wpk_repository>`](configuration.md#agent-upgrades).

**Downloads are staged, verified, then renamed into place**, so a partially written file is never
visible at the path agents fetch from.

**Peer verification is never disabled.** The SHA-1 a WPK is checked against comes from the
repository's own index over the same connection, so an unverified channel would let a man in the
middle supply a matching pair and the integrity check would confirm his work rather than ours. A host
with no CA bundle has every download refused, and is told so once at start-up.

### Custom WPK files

`file_path` must resolve **inside `var/upgrade/`** — symlinks are followed before the check, and
anything landing elsewhere is rejected with *The WPK file does not exist*. The task payload carries
only the file's **basename**, and both delivery paths join that name to `var/upgrade/`, so a path
anywhere else would name a file the agent could never fetch.

**In a cluster the file must exist on every manager node**, inside each node's `var/upgrade/`. The
node that receives the API request creates the task, but the agent may connect to a different node to
download the WPK.

---

## After the task is stored

The manager does **not** push WPK data to the agent, and does not connect to Remoted from the request
path. Delivery depends on the agent's version:

- **5.x agents** pull the task from `POST /control` on their next poll, fetch the WPK with
  `POST /download` over the same HTTPS interface, and hand the file to their local upgrade module.
- **Agents below v5.0.0** are served by `remoted`'s own task-polling thread, which pushes the WPK
  over the agent's existing session. See
  [`remoted.legacy_task_polling_interval`](../remoted/configuration.md).

A 4.x agent installs the WPK with its own 4.x upgrade module, which is why a 5.0.0 WPK still has to
be consumable by 4.x code: the WPK's `upgrade.sh` / `upgrade.bat` and `pkg_installer.sh` run under
the agent being replaced.

**No outcome comes back.** An agent task is stored and handed out; the manager never learns what came
of it. Progress is observable through the agent's reported version, the agent's own log, and
`remoted`'s log for the legacy path.

---

## Interface

| Socket | Direction | Purpose |
| --- | --- | --- |
| `queue/sockets/task-http.sock` | Inbound | `POST /v1/agents/upgrade` and `POST /v1/agents/upgrade-custom` from the Server API |

Outbound, the only traffic is HTTPS to the WPK repository.

**Both routes always answer `200`**, including for a body that could not be parsed. The per-agent
envelope carries every verdict, and the Server API turns each entry into an exception code by adding
1810; a non-2xx would make that client raise before it ever read the entries, replacing a precise
per-agent reason with a generic transport error. The route shapes are in
[the HTTP interface](README.md#agent-upgrades).

---

## Key source files

Under `src/wazuh_modules/task_manager/src/upgrade/`.

| File | Purpose |
| --- | --- |
| `upgradeApi.{hpp,cpp}` | The two routes. Parses, hands the batch to the pool, answers later through the retained responder |
| `upgradeService.{hpp,cpp}` | Bounded worker pool. Its shutdown answers every parked request rather than dropping it |
| `upgradeOrchestrator.{hpp,cpp}` | The three phases: resolve per agent, materialise per WPK, persist in one transaction |
| `versionPolicy.{hpp,cpp}` | The version gates, including the un-forceable `v4.14.0` rule |
| `platform.{hpp,cpp}` | Platform tables, package family and architecture naming |
| `repoLayout.{hpp,cpp}` | The six published repository URL shapes and the two version epochs that select them |
| `deliveryGate.{hpp,cpp}` | The `remote.legacy.enabled` and `verification_mode` checks |
| `wpkCache.{hpp,cpp}` | One download per file, stage-then-rename, digest memo |
| `versionsCache.{hpp,cpp}` | One `versions` fetch per repository path, TTL-cached |
| `httpWpkRepository.{hpp,cpp}` | The outbound HTTPS client, with peer verification that cannot be turned off |

---

## See Also

- [Task Manager Configuration](configuration.md#agent-upgrades) — options, monitoring, troubleshooting
- [Task Manager Module](README.md) — the surrounding module
- [Agent Upgrade module](../agent_upgrade/README.md) — the agent's half: signature verification and the installer
