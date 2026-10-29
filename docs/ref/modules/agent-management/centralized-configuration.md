# Centralized Configuration for Agents

## Introduction

The Wazuh manager can push configuration to its agents through an `agent.conf` file per
[group](agent-groups.md). Policies are defined once on the manager and every agent in the group picks
them up.

An agent reads its local `ossec.conf` first and the received `agent.conf` after it, so a setting given
in both takes the `agent.conf` value; a repeatable block (a `<localfile>`, a `<directories>` entry)
is added to the local ones.

## How it works

1. The administrator edits `/etc/wazuh-manager/shared/<GROUP_NAME>/agent.conf` (directly, or with
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
/etc/wazuh-manager/shared/<GROUP_NAME>/agent.conf
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

`overwrite` is accepted and ignored. Any other attribute is refused on the manager: `verify-agent-conf`
prints `(1233): Invalid attribute '<name>' in the configuration: '<file>'.` and exits non-zero, and
`PUT /groups/{group_id}/configuration` answers `400` with error `1114` naming the attribute, so the file is
not stored. An agent that still receives such a block (a file placed in `/etc/wazuh-manager/shared/<group>/`
by hand) logs the same error and does not treat the unknown attribute as a filter: it applies the block as
if the attribute were absent (with no other attribute, on every agent of the group).

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
| `<agent>` (or its 4.x spelling `<client>`) | Only its `<batch>` child (`<force_reconnect_interval>` is warned about and ignored); any other child is an error |

Sections that are read only from the agent's local `ossec.conf`:

- `<active-response>`: the agent's execd reads the whole block (`<disabled>`,
  `<repeated_offenders>`, `<allowlist>`) only from the local file, so an `<active-response>` block in
  `agent.conf` is accepted and ignored.
- `<agent-upgrade>`: ignored in `agent.conf`.
- `<anti_tampering>` (Unix agents): read from the local file only; ignored in `agent.conf`. Windows
  agents do not know the section, so there it makes the file invalid.
- `<logging>`: ignored in `agent.conf`.
- `<cluster>`: ignored. `<client_buffer>` (4.x event buffering, replaced by `<agent><batch>`) is ignored
  with the info line `'client_buffer' is no longer used and will be ignored.`

A manager-only section (`global`, `remote`, `auth`, `wdb`, `indexer`, `vulnerability-detection`,
`vulnerability-detector`, `task-manager`) is skipped with the warning `<section> configuration is only set in the manager.` A
section removed in 5.0 (`labels`, `command`, `integration`, …) is skipped with
`(1223): '<section>' is no longer supported and will be ignored. <reason>` Any other unknown section is
an error that makes the whole file invalid.

## Verifying the configuration

On the manager, `verify-agent-conf` checks the syntax and the `<syscheck>`, `<rootcheck>`,
`<localfile>`, `<agent>` and module sections of every group's `agent.conf`:

```bash
/var/wazuh-manager/bin/verify-agent-conf
```

```text
verify-agent-conf: Verifying [/etc/wazuh-manager/shared/default/agent.conf]
verify-agent-conf: OK
```

| Option | Effect |
|--------|--------|
| *(none)* | Check `agent.conf` in every directory under `/etc/wazuh-manager/shared/`; a directory without one is reported as `File not found` and counts as a failure |
| `-f <file>` | Check only that file. A relative path is resolved against `/var/wazuh-manager`, so give an absolute one |
| `-d` | Debug output. Any option turns the scan of `/etc/wazuh-manager/shared/` off, so use it with `-f` |
| `-V` | Print the version |
| `-h` | Print the help and exit `1` |

It exits `0` when every file is valid and `1` otherwise. Errors are printed on standard error; an XML
syntax error names the line (`(1226): Error reading XML file '<file>': <error> (line <n>).`). The
`os`, `name` and `profile` filters are not evaluated here: every block is checked.

`PUT /groups/<GROUP_NAME>/configuration` runs the same check (`verify-agent-conf -f`) on the body
before it replaces `agent.conf`, and refuses an invalid one with error `1113` (not well-formed XML) or
`1114` (invalid configuration), or `1115` when `verify-agent-conf` fails without an error line the
API can parse, without touching the file. A document type declaration (`<!DOCTYPE …>`, and with it any
entity definition) is not allowed in the body: it is refused with `1113` too, as `not well-formed (invalid
token)`, and the line and column in that message count from the API's own wrapper around the body, not
from the body itself. The `1114` detail is the reason `verify-agent-conf` gives
(for an unknown section, `Invalid element in the configuration: '<section>'.`) and names the file as
`<GROUP_NAME>/agent.conf`. A leading XML declaration (`<?xml version="1.0"?>`) in the body is accepted and
dropped, so the file written has none. On disk it is the other way round: `verify-agent-conf` refuses an `agent.conf` that starts with an XML
declaration, with error `1226`, so do not add one when editing the file by hand. An `agent.conf` edited directly on disk is
not checked by the manager: `wazuh-manager-remoted` distributes it as it is, so run
`verify-agent-conf` after editing.

On the agent, a received configuration that fails validation is not applied: the agent restores its
previous shared files, keeps running with its current configuration, reports
`wazuh: Invalid remote configuration: '<section>'.` to the manager as an event, and logs the warning
`The shared configuration the manager provides (hash=<hash>) is invalid; the agent keeps its current
configuration until the manager provides a valid one.` (while the agent is still starting and its
modules wait for the manager's configuration, the warning ends `the modules stay on hold until the
manager provides a valid one.` instead; either is repeated every 10 minutes while the manager
keeps offering that configuration; it is not downloaded again until it changes).

## Applying changes

Changes are picked up within `remoted.shared_reload` seconds plus the agent's polling interval. To
confirm an agent applied them, check the agent's log for `Agent is reloading due to shared
configuration changes.`

With `<agent><auto_restart>no</auto_restart>` the files are stored but not applied until the agent
restarts; the agent logs `Agent must restart to apply the new shared configuration; auto_restart is
disabled.` An agent whose `agent.remote_conf` internal option is `0` ignores `agent.conf` altogether.

## Precedence rules

`agent.conf` wins over the local `ossec.conf` (see [Introduction](#introduction)). For an agent in
several groups, how their `agent.conf` files are combined is described in
[Configuration merge order](agent-groups.md#configuration-merge-order).
