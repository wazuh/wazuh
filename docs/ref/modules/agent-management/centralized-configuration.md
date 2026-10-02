# Centralized Configuration for Agents

## Introduction

The Wazuh manager can push configuration to its agents through an `agent.conf` file per
[group](agent-groups.md). Policies are defined once on the manager and every agent in the group picks
them up.

An agent reads its local `ossec.conf` first and the received `agent.conf` after it, so a setting given
in both takes the `agent.conf` value; a repeatable block (a `<localfile>`, a `<directories>` entry)
is added to the local ones.

## How it works

1. The administrator edits `/var/wazuh-manager/etc/shared/<GROUP_NAME>/agent.conf` (directly, or with
   `PUT /groups/<GROUP_NAME>/configuration`).
2. `wazuh-manager-remoted` re-reads the shared directory every
   [`remoted.shared_reload`](../remoted/configuration.md#remotedshared_reload) seconds (10 by
   default) and, when a file changed, rebuilds the group's `merged.mg`.
3. On its next `POST /control` poll the agent learns that its configuration hash changed and
   downloads the new `merged.mg` with `POST /download`.
4. The agent unpacks it into its shared directory (`etc/shared/agent.conf` and the group's other
   files), validates it, and — with `<agent><auto_restart>` enabled, the default — reloads to apply it.

No manager restart is needed.

## File location

```text
/var/wazuh-manager/etc/shared/<GROUP_NAME>/agent.conf
```

The default group is `default`; an agent enrolled without a group belongs to it.

## Configuration format

`agent.conf` uses the same XML elements as `ossec.conf`, wrapped in one or more `<agent_config>`
blocks instead of `<ossec_config>`.

### Basic example

```xml
<agent_config>
  <localfile>
    <location>/var/log/myapp.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <syscheck>
    <directories check_all="yes">/etc,/usr/bin</directories>
  </syscheck>
</agent_config>
```

### Targeting agents

An `<agent_config>` block can carry one or more attributes; it applies only to an agent that matches
all of them. Each value is a pattern matched with `OS_Match2()` (a substring match, `|` separates
alternatives).

| Attribute | Matched against |
|-----------|-----------------|
| `os` | The agent's system description (`uname`), for example `Linux` or `Windows` |
| `name` | The agent's name |
| `profile` | The agent's `<agent><config-profile>` in its local `ossec.conf` |

`overwrite` is accepted and ignored; any other attribute is logged as an error and ignored.

```xml
<agent_config os="Linux">
  <localfile>
    <location>/var/log/auth.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>

<agent_config os="Windows">
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>

<agent_config name="web-server-01">
  <localfile>
    <location>/var/log/nginx/access.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>

<agent_config profile="database-servers">
  <localfile>
    <location>/var/log/mysql/error.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>
```

## Supported configuration sections

The agent's daemons read these sections from `agent.conf` (`read_main_elements()` in
`src/config/src/config.c`):

| Section | Read by |
|---------|---------|
| `<localfile>`, `<socket>` | Log collection |
| `<syscheck>` | File integrity monitoring |
| `<rootcheck>` | Rootkit detection |
| `<sca>` | Security configuration assessment |
| `<wodle>` | Wazuh modules configured as a wodle |
| `<agent-info>` | Agent info module |
| `<gcp-pubsub>`, `<gcp-bucket>` | Google Cloud modules |
| `<github>`, `<office365>`, `<ms-graph>` | Cloud log collection modules |
| `<agent>` | Only its `<batch>` child; any other child is an error |

Sections that are read only from the agent's local `ossec.conf`:

- `<active-response>`: the agent's execd reads its `<disabled>` flag only from the local file, so an
  `<active-response>` block in `agent.conf` is accepted and ignored.
- `<agent-upgrade>`: ignored in `agent.conf`.
- `<logging>`: ignored in `agent.conf`.

A manager-only section is skipped with the warning `<section> configuration is only set in the
manager.`

## Verifying the configuration

On the manager, `verify-agent-conf` checks the syntax and the `<syscheck>`, `<rootcheck>`,
`<localfile>`, `<agent>` and module sections of every group's `agent.conf`:

```bash
/var/wazuh-manager/bin/verify-agent-conf
```

```text
verify-agent-conf: Verifying [etc/shared/default/agent.conf]
verify-agent-conf: OK
```

| Option | Effect |
|--------|--------|
| *(none)* | Check `agent.conf` in every directory under `etc/shared/`; a directory without one is reported as `File not found` |
| `-f <file>` | Check only that file |
| `-d` | Debug output. Any option turns the scan of `etc/shared/` off, so use it with `-f` |
| `-V` | Print the version |
| `-h` | Print the help and exit `1` |

It exits `0` when every file is valid and `1` otherwise. Errors are printed on standard error; an XML
syntax error names the line (`(1226): Error reading XML file '<file>': <error> (line <n>).`). The
`os`, `name` and `profile` filters are not evaluated here: every block is checked.

On the agent, a received configuration that fails validation is not applied: the agent logs
`Downloaded configuration failed validation; not reloading.` and reports
`wazuh: Invalid remote configuration: '<section>'.` to the manager as an event.

## Applying changes

Changes are picked up within `remoted.shared_reload` seconds plus the agent's polling interval. To
confirm an agent applied them, check the agent's log for `Agent is reloading due to shared
configuration changes.`

With `<agent><auto_restart>no</auto_restart>` the files are stored but not applied until the agent
restarts; the agent logs `Agent must restart to apply the new shared configuration; auto_restart is
disabled.` An agent whose `agent.remote_conf` internal option is `0` ignores `agent.conf` altogether.

## Precedence rules

`agent.conf` wins over the local `ossec.conf` (see [Introduction](#introduction)). If an agent belongs to multiple groups, the configurations from all groups are merged. Groups are merged in the order they were assigned to the agent, and in case of conflicts between groups, the configuration from the group assigned last takes precedence. See [Configuration merge order](agent-groups.md#configuration-merge-order).
