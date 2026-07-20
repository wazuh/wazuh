# GitHub Integration

## Introduction

The Wazuh GitHub module retrieves audit log events from GitHub organizations using the GitHub Audit Log API. This enables monitoring of organization activity, including repository management, team changes, member access, and other administrative actions.

The module runs on the Wazuh agent and periodically queries the GitHub API for new audit events. Events are processed by the Wazuh rule engine to generate alerts for suspicious activity such as unauthorized repository access, permission changes, and authentication events.

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

Configure the GitHub module in the Wazuh agent `ossec.conf` file:

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
| `only_future_events` | No | `yes` | Only retrieve events generated after the module starts. |
| `interval` | No | `1m` | Time interval between API queries. |
| `time_delay` | No | `30s` | Delay before retrieving events to allow GitHub API propagation. |
| `curl_max_size` | No | `1M` | Maximum size of the HTTP response body. |
| `api_auth` | Yes | — | Authentication configuration section. Multiple `api_auth` blocks can be defined for multiple organizations. |
| `org_name` | Yes | — | GitHub organization name. |
| `api_token` | Yes | — | GitHub personal access token with `read:audit_log` permission. |
| `api_parameters` | No | — | Section for API query parameters. |
| `event_type` | No | `all` | Type of audit events to retrieve. Options: `all`, `git`, `web`. |

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

Restart the Wazuh agent after applying the configuration:

```bash
systemctl restart wazuh-agent
```

Check the module logs:

```bash
grep "github" /var/ossec/logs/ossec.log
```

GitHub audit events generate alerts with the `github` data field populated.
