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
| [Agent Info](../../modules/agent_info/configuration.md) | `<agent-info>` | - |
| [Agent Upgrade](../../modules/agent_upgrade/configuration.md) | `<agent-upgrade>` | - |
| [Client](../../modules/client/configuration.md) | `<agent>`, `<anti_tampering>` | `agent.*`, `windows.*` (Windows only) |
| [Command](../../modules/command/configuration.md) | `<wodle name="command">` | `wazuh_command.*` |
| [Logcollector](../../modules/logcollector/configuration.md) | `<localfile>`, `<socket>` | `logcollector.*` |
| [Logging](../../modules/logging/configuration.md) | `<logging>` | - |
| [Rootcheck](../../modules/rootcheck/configuration.md) | `<rootcheck>` | `rootcheck.*` |
| [SCA](../../modules/sca/configuration.md) | `<sca>` | `sca.*` |
| [Syscollector](../../modules/syscollector/configuration.md) | `<wodle name="syscollector">` | - |
| [FIM](../../modules/fim/configuration.md) | `<syscheck>` | `syscheck.*` |

**Note:** All wodle-based modules (Command, Syscollector, AWS, Azure, Docker) also use common `wazuh_modules.*` options documented in [Common Internal Options](#common-internal-options).

### Cloud & Integration Modules

| Module | XML Section | Internal Options |
|--------|-------------|------------------|
| [AWS](../../modules/integrations/index.html) | `<wodle name="aws-s3">` | - |
| [Azure](../../modules/integrations/index.html) | `<wodle name="azure-logs">` | - |
| [Docker](../../modules/integrations/index.html) | `<wodle name="docker-listener">` | - |
| [GCP](../../modules/integrations/index.html) | `<gcp-pubsub>`, `<gcp-bucket>` | - |
| [GitHub](../../modules/integrations/index.html) | `<github>` | - |
| [MS Graph](../../modules/integrations/index.html) | `<ms-graph>` | - |
| [Office 365](../../modules/integrations/index.html) | `<office365>` | - |

---

## Common Internal Options

These internal options apply to all Wazuh modules (wodles) on the agent. Configure them in `/var/ossec/etc/local_internal_options.conf`:

```ini
# Debug level for all wazuh modules (0-2, default: 0)
wazuh_modules.debug=0

# Maximum events per second for all modules (default: 100)
wazuh_modules.max_eps=100

# Process priority/nice value for module threads (-20 to 19, default: 10)
wazuh_modules.task_nice=10

# Timeout in seconds for killing unresponsive modules (default: 10)
wazuh_modules.kill_timeout=10

# Maximum file descriptors for module processes (8192-1048576, default: 8192)
wazuh_modules.rlimit_nofile=8192
```

`wazuh_modules.rlimit_nofile` cannot go below `8192`: a lower value is rejected at start with
`Invalid definition` and modulesd does not run. See [File descriptor limits](#file-descriptor-limits)
for how the value interacts with the limit the agent is started with.

**Used by modules:** Command, Syscollector, and other wodle-based modules on the agent.

---

## File descriptor limits

Two limits apply to every daemon, and they have different owners:

1. **The hard limit** is set by whatever starts the agent: `LimitNOFILE=65536` in
   `wazuh-agent.service`, the SysV init scripts, or `ulimits.nofile` in a container. The daemons
   never change it. Raising it needs `CAP_SYS_RESOURCE`, which containers drop by default, so it
   is set where the process is started, not from inside.
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
`File descriptor limit is 4096, below the 8192 requested by 'wazuh_modules.rlimit_nofile'`. The
line is emitted twice per start, because `wazuh-control start` validates the configuration first
and each daemon raises its limit before that validation. An option above the hard limit never
fails and never logs an error.

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

For comprehensive module documentation including architecture and implementation details, see [Modules Reference](../../modules/index.html).
