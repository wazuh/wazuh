# GitHub Integration

## Introduction

The Wazuh GitHub module retrieves audit log events from GitHub organizations using the GitHub Audit Log API. This enables monitoring of organization activity, including repository management, team changes, member access, and other administrative actions.

It is an agent module, built into the agent's `wazuh-modulesd` and available on Linux, macOS and Windows agents (see [Integrations](README.md)). It periodically queries `https://api.github.com/orgs/<org>/audit-log` for each configured organization and sends each audit event to the manager with `integration` set to `github` and the event under `github`.

## Prerequisites

- A GitHub organization with admin access.
- A personal access token with the `admin:org` scope (specifically `read:audit_log`).

## GitHub setup

### Generate a personal access token

1. Go to **GitHub** > **Settings** > **Developer settings** > **Personal access tokens**.
2. Generate a new token with the following scope:
   - `admin:org` > `read:audit_log`
3. Copy the generated token.

## Configuration

Configure the GitHub module in the agent's `ossec.conf`, inside `<ossec_config>`:

```xml
<github>
  <enabled>yes</enabled>
  <only_future_events>yes</only_future_events>
  <interval>1m</interval>
  <time_delay>30s</time_delay>
  <curl_max_size>1M</curl_max_size>
  <api_auth>
    <org_name>my-organization</org_name>
    <api_token>ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</api_token>
  </api_auth>
  <api_parameters>
    <event_type>all</event_type>
  </api_parameters>
</github>
```

### Configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `enabled` | No | `yes` | Enables or disables the module. |
| `only_future_events` | No | `yes` | `yes`: when the module starts, events older than the start are not collected. `no`: collection resumes from the last event collected before the agent stopped (the module keeps that position across restarts). |
| `interval` | No | `1m` | Time between API queries: a number with an optional unit `s`, `m`, `h`, `d` or `w` (seconds when none). |
| `time_delay` | No | `30s` | Each query only asks for events older than this delay, to allow for GitHub API propagation. Same units as `interval`. |
| `curl_max_size` | No | `1M` | Maximum size of an HTTP response: a number with an optional unit `B`, `K`, `M` or `G` (bytes when none). Minimum `1K`. |
| `api_auth` | Yes | — | Authentication configuration section. At least one is required; several can be defined for several organizations. |
| `org_name` | Yes | — | GitHub organization name. Cannot be empty. |
| `api_token` | Yes | — | GitHub personal access token with `read:audit_log` permission. Cannot be empty. |
| `api_parameters` | No | — | Section for API query parameters. |
| `event_type` | No | `all` | Type of audit events to retrieve. Options: `all`, `git`, `web`; any other value makes the configuration fail to load. |

Any other element makes the configuration fail to load.

### Event types

| Event type | Description |
|-----------|-------------|
| `all` | All audit log events (default). |
| `git` | Git-related events (clone, push, pull). |
| `web` | Web interface and API events (repository creation, team management, member access). |

### Monitoring multiple organizations

```xml
<github>
  <enabled>yes</enabled>
  <interval>1m</interval>
  <api_auth>
    <org_name>organization-one</org_name>
    <api_token>ghp_token_for_org_one</api_token>
  </api_auth>
  <api_auth>
    <org_name>organization-two</org_name>
    <api_token>ghp_token_for_org_two</api_token>
  </api_auth>
  <api_parameters>
    <event_type>web</event_type>
  </api_parameters>
</github>
```

## Verify the integration

Restart the agent and look for the module's lines (tag `wazuh-modulesd:github`):

```bash
systemctl restart wazuh-agent
grep "github" /var/ossec/logs/ossec.log
```

`Module GitHub started.` is logged at start; the first query runs one `interval` later. Request failures are logged under the same tag, and `Github organization '<org>' and event type '<type>', connected successfully.` is logged when an organization that was failing answers again.
