# Centralized Configuration for Agents

## Introduction

The Wazuh manager can push configuration settings to registered agents using the `agent.conf` file. This centralized approach simplifies managing large deployments by allowing administrators to define monitoring policies once on the manager and distribute them automatically to agents based on group membership.

Configuration values defined in `agent.conf` take precedence over the local `ossec.conf` on each agent. This ensures consistent policy enforcement across all managed endpoints.

## How it works

1. The administrator creates or edits the `agent.conf` file on the Wazuh manager.
2. The file is placed in the appropriate group's shared directory on the manager.
3. When agents connect (or reconnect), the manager distributes the updated configuration.
4. The agent merges the received `agent.conf` settings with its local `ossec.conf`, with `agent.conf` values taking precedence.

## File location

On the Wazuh manager, the centralized configuration files are located in the shared directory for each group:

```
/var/wazuh-manager/etc/shared/<GROUP_NAME>/agent.conf
```

The default group is named `default`. All agents belong to the `default` group unless explicitly assigned to another group.

## Configuration format

The `agent.conf` file uses the same XML syntax as `ossec.conf`. Wrap the configuration inside `<agent_config>` tags.

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

### Targeting specific agents by OS

Use the `os` attribute to apply settings only to agents running a specific operating system:

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
```

### Targeting specific agents by name

Use the `name` attribute to apply settings to a specific agent:

```xml
<agent_config name="web-server-01">
  <localfile>
    <location>/var/log/nginx/access.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>
```

### Targeting specific agents by profile

Use the `profile` attribute to target agents that have a matching profile defined in their local `ossec.conf`:

```xml
<agent_config profile="database-servers">
  <localfile>
    <location>/var/log/mysql/error.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>
```

## Supported configuration sections

The following configuration sections can be distributed via `agent.conf`:

| Section | Description |
|---------|-------------|
| `<localfile>` | Log collection settings |
| `<syscheck>` | File integrity monitoring settings |
| `<rootcheck>` | Rootkit detection settings |
| `<sca>` | Security configuration assessment policies |
| `<wodle>` | Wazuh module (wodle) settings |
| `<active-response>` | Active response configuration |

## Verifying the configuration

After editing `agent.conf`, verify the configuration syntax on the manager:

```bash
/var/wazuh-manager/bin/verify-agent-conf
```

If the configuration is valid, the output confirms success. If there are syntax errors, they are reported with line numbers.

## Applying changes

After editing `agent.conf`, restart the Wazuh manager so the new configuration is distributed to agents:

```bash
systemctl restart wazuh-manager
```

Agents receive the updated configuration automatically on their next connection to the manager.

## Precedence rules

When the same setting is defined in multiple places, the following precedence applies (highest to lowest):

1. `agent.conf` (centralized configuration from the manager)
2. `ossec.conf` (local configuration on the agent)

If an agent belongs to multiple groups, the configurations from all groups are merged. In case of conflicts between groups, the configuration from the group with the lowest alphabetical order takes precedence.
