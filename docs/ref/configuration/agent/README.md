# Agent Configuration

Configuration reference for Wazuh agent components.

## Configuration Files

| File | Location (Linux/Unix) | Location (Windows) | Description |
|------|----------------------|-------------------|-------------|
| `ossec.conf` | `/var/ossec/etc/` | `C:\Program Files (x86)\ossec-agent\` | Main XML configuration |
| `internal_options.conf` | `/var/ossec/etc/` | `C:\Program Files (x86)\ossec-agent\` | Internal tuning parameters |
| `local_internal_options.conf` | `/var/ossec/etc/` | `C:\Program Files (x86)\ossec-agent\` | User overrides |

## Configuration Sections

| Module | XML Section | Internal Options |
|--------|-------------|------------------|
| [Active Response](../../modules/active-response/configuration.md) | `<active-response>` | `execd.*` |
| [Agent Info](../../modules/agent_info/configuration.md) | `<agent-info>` | `agent_info.*` |
| [Agent Upgrade](../../modules/agent_upgrade/configuration.md) | `<agent-upgrade>` | - |
| [Client](../../modules/client/configuration.md) | `<agent>` (the 4.x `<client>` block is still read for `<server><address>` and `<enrollment>`), `<anti_tampering>` | `agent.*`, `monitord.*` (log rotation), `windows.*` (Windows only) |
| [Command](../../modules/command/configuration.md) | `<wodle name="command">` | `wazuh_command.*` |
| [Logcollector](../../modules/logcollector/configuration.md) | `<localfile>`, `<socket>` | `logcollector.*` |
| [Logging](../../modules/logging/configuration.md) | `<logging>` | - |
| [Rootcheck](../../modules/rootcheck/configuration.md) | `<rootcheck>` | `rootcheck.*` |
| [SCA](../../modules/sca/configuration.md) | `<sca>` | `sca.*` |
| [Syscollector](../../modules/syscollector/configuration.md) | `<wodle name="syscollector">` | - |
| [FIM](../../modules/fim/configuration.md) | `<syscheck>` | `syscheck.*` |

**Note:** every module of `wazuh-modulesd` shares the `wazuh_modules.*` options documented in
[Common Internal Options](#common-internal-options); which modules each one affects is listed there.

### Cloud & Integration Modules

| Module | XML Section | Internal Options |
|--------|-------------|------------------|
| AWS ([CloudTrail](../../modules/integrations/aws-cloudtrail.md), [CloudWatch Logs](../../modules/integrations/aws-cloudwatch-logs.md), [Security Hub](../../modules/integrations/aws-security-hub.md), [Security Lake](../../modules/integrations/amazon-security-lake.md)) | `<wodle name="aws-s3">` | - |
| [Azure](../../modules/integrations/azure.md) | `<wodle name="azure-logs">` | - |
| [Docker](../../modules/integrations/docker.md) | `<wodle name="docker-listener">` | - |
| [GCP](../../modules/integrations/gcp.md) | `<gcp-pubsub>`, `<gcp-bucket>` | - |
| [GitHub](../../modules/integrations/github.md) | `<github>` | - |
| [MS Graph](../../modules/integrations/microsoft-graph.md) | `<ms-graph>` | - |
| [Office 365](../../modules/integrations/office365.md) | `<office365>` | - |

The integrations run on the agent only: the manager reads no integration section, and an integration
block in `wazuh-manager.conf` is rejected as an unknown option (`(1244)`).

---

## Common Internal Options

These internal options apply to the modules of `wazuh-modulesd`, or to every daemon. The shipped
`/var/ossec/etc/internal_options.conf` carries their defaults; set overrides in
`/var/ossec/etc/local_internal_options.conf`, which is read first. A value outside the range stops the
daemon at start with `(2302): Invalid definition for <name>: '<value>'.`

| Option | Default | Range | Effect |
|---|---|---|---|
| `wazuh_modules.debug` | `0` | `0`-`2` | Debug level of `wazuh-modulesd` (the `-d` flag overrides it) |
| `wazuh_modules.rlimit_nofile` | `8192` | `8192`-`1048576` | Soft file descriptor limit of `wazuh-modulesd`, see [File descriptor limits](#file-descriptor-limits) |
| `wazuh_modules.max_eps` | `100` | `1`-`1000` | Events per second sent by Command, AWS, MS Graph and Agent Upgrade |
| `wazuh_modules.task_nice` | `10` | `-20`-`19` | Nice value of the external programs modules launch (Command, AWS, Azure, GCP, SCA policy commands, the Agent Upgrade installer) |
| `wazuh_modules.kill_timeout` | `10` | `0`-`3600` | Seconds a module's child process (the programs above, the Docker listener) gets to exit at shutdown before it is killed |
| `wazuh.thread_stack_size` | `8192` | `2048`-`65536` | Stack size, in KiB, of the threads the daemons start through the shared thread helper |

`wazuh_modules.rlimit_nofile` cannot go below `8192`: a lower value is rejected at start with
`Invalid definition` and modulesd does not run. See [File descriptor limits](#file-descriptor-limits)
for how the value interacts with the limit the agent is started with.

---

## File descriptor limits

Two limits apply to every daemon, and they have different owners:

1. **The hard limit** is set by whatever starts the agent: `LimitNOFILE=65536` in
   `wazuh-agent.service`, the shell that runs the SysV init script, or `ulimits.nofile` in a
   container. The daemons never change it. Raising it needs `CAP_SYS_RESOURCE`, which containers drop
   by default, so it is set where the process is started, not from inside. The SysV init scripts only
   raise the soft limit to `65536` (to the hard limit when that is lower, with a warning on stderr).
2. **The soft limit** is the one the kernel enforces (`EMFILE`, "too many open files"). At start,
   each daemon raises its own soft limit to the value of its internal option, never above the hard
   limit it inherited and never below what it already had:

| Option | Default | Range |
|---|---|---|
| `wazuh_modules.rlimit_nofile` | `8192` | `8192`-`1048576` |
| `logcollector.rlimit_nofile` | `1100` | `1024`-`1048576` |

`wazuh-agentd`, `wazuh-syscheckd` and `wazuh-execd` have no option and keep the limits they inherit.

When the hard limit is below the option, the daemon runs with the hard limit and logs a warning
naming both values, for example
`File descriptor limit is 4096, below the 8192 requested by 'wazuh_modules.rlimit_nofile'. Raise the limit the process is started with (LimitNOFILE, ulimit -n, container ulimits) to go higher.`
For `wazuh_modules.rlimit_nofile` the line is emitted twice per start, because `wazuh-control start`
runs `wazuh-modulesd -t` first and modulesd raises its limit before that check;
`wazuh-logcollector` raises its limit only after its `-t` exit, so it logs the line once. An option
above the hard limit never fails and never logs an error.

To go higher than the ceiling the unit declares, use a systemd drop-in rather than editing the
unit, which a package upgrade replaces:

```ini
# /etc/systemd/system/wazuh-agent.service.d/nofile.conf
[Service]
LimitNOFILE=131072
```

For a SysV start, raise the limit with `ulimit -n` before the init script, and in a container set
`ulimits.nofile`.

Note for agents upgraded from a release before the unit declared `LimitNOFILE`: hosts whose systemd
granted a higher hard limit (512K on EL8+, Fedora, Debian 10+ and Ubuntu 20.04+) now start with
`65536`. That is far above what any agent daemon requests by default, but an installation that
raised `wazuh_modules.rlimit_nofile` or `logcollector.rlimit_nofile` above `65536` is capped at the
new ceiling and logs the warning above. The drop-in restores the previous headroom.

---

For comprehensive module documentation including architecture and implementation details, see [Modules Reference](../../modules/README.md).
