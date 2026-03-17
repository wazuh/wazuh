# Microsoft Graph Security API

## Introduction

The Wazuh Microsoft Graph module retrieves security alerts and events from the Microsoft Graph Security API. This provides access to security data from multiple Microsoft security products, including Microsoft Defender for Endpoint, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Azure AD Identity Protection.

The module runs on the Wazuh agent and periodically queries the Microsoft Graph Security API for new alerts and events. It supports multiple API resources and relationships for comprehensive security monitoring.

## Prerequisites

- A Microsoft 365 or Azure AD tenant with admin access.
- An Azure AD application registered with Microsoft Graph Security API permissions.
- The application's tenant ID, client ID, and client secret.

## Azure AD application setup

1. In the Azure portal, navigate to **Azure Active Directory** > **App registrations**.
2. Register a new application.
3. Under **API permissions**, add the following Microsoft Graph permissions (Application type):
   - `SecurityEvents.Read.All` – Read security events
   - `SecurityAlert.Read.All` – Read security alerts
   - Additional permissions depending on the resources you want to monitor
4. Grant admin consent for the permissions.
5. Under **Certificates & secrets**, create a new client secret.

## Configuration

Configure the Microsoft Graph module in the Wazuh agent `ossec.conf` file:

```xml
  <ms-graph>
    <enabled>yes</enabled>
    <only_future_events>yes</only_future_events>
    <run_on_start>yes</run_on_start>
    <interval>5m</interval>
    <version>v1.0</version>
    <curl_max_size>1M</curl_max_size>
    <api_auth>
      <client_id>YOUR_CLIENT_ID</client_id>
      <tenant_id>YOUR_TENANT_ID</tenant_id>
      <secret_value>YOUR_CLIENT_SECRET</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
  </ms-graph>
```

### Configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `enabled` | No | `yes` | Enables or disables the module. |
| `only_future_events` | No | `yes` | Only retrieve events generated after the module starts. |
| `run_on_start` | No | `yes` | Query the API immediately when the module starts. |
| `interval` | No | `5m` | Time interval between API queries. |
| `version` | No | `v1.0` | Microsoft Graph API version. Options: `v1.0`, `beta`. |
| `curl_max_size` | No | `1M` | Maximum size of the HTTP response body. |
| `page_size` | No | `50` | Number of results per API page. |
| `time_delay` | No | `30s` | Delay before retrieving events to allow API propagation. |
| `api_auth` | Yes | — | Authentication configuration section. |
| `client_id` | Yes | — | Azure AD application (client) ID. |
| `tenant_id` | Yes | — | Azure AD tenant ID. |
| `secret_value` | Yes | — | Azure AD application client secret. |
| `api_type` | No | `global` | API endpoint type. Options: `global`, `gcc-high`, `dod`. |
| `resource` | Yes | — | Defines a Microsoft Graph resource to monitor. Multiple `resource` blocks are supported. |
| `name` | Yes | — | The resource name (for example, `security`, `identityProtection`). |
| `relationship` | Yes | — | The relationship to query within the resource (for example, `alerts_v2`, `incidents`). |

### API types

| API type | Login endpoint | Graph endpoint | Description |
|----------|---------------|----------------|-------------|
| `global` | `login.microsoftonline.com` | `graph.microsoft.com` | Global Microsoft cloud. |
| `gcc-high` | `login.microsoftonline.us` | `graph.microsoft.us` | US Government GCC High cloud. |
| `dod` | `login.microsoftonline.us` | `dod-graph.microsoft.us` | US Department of Defense cloud. |

### Common resources and relationships

| Resource | Relationship | Description |
|----------|-------------|-------------|
| `security` | `alerts_v2` | Security alerts from Microsoft security products. |
| `security` | `incidents` | Security incidents that correlate related alerts. |

### Monitoring multiple resources

```xml
<ms-graph>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <api_auth>
    <client_id>YOUR_CLIENT_ID</client_id>
    <tenant_id>YOUR_TENANT_ID</tenant_id>
    <secret_value>YOUR_CLIENT_SECRET</secret_value>
  </api_auth>
  <resource>
    <name>security</name>
    <relationship>alerts_v2</relationship>
    <relationship>incidents</relationship>
  </resource>
</ms-graph>
```

## Verify the integration

Restart the Wazuh agent after applying the configuration:

```bash
systemctl restart wazuh-agent
```

Check the module logs:

```bash
grep "ms-graph" /var/ossec/logs/ossec.log
```

Microsoft Graph security events generate alerts with the `ms-graph` data field populated.
