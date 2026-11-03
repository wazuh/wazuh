# Microsoft Graph Security API

## Introduction

The Microsoft Graph module (`<ms-graph>`) retrieves records from Microsoft Graph API resources, such as the security alerts and incidents of the Microsoft security products (`security`), Identity Protection risk detections (`identityProtection`) or Intune audit events and device inventory (`deviceManagement`).

It is an agent module, built into the agent's `wazuh-modulesd` and available on Linux, macOS and Windows agents (see [Integrations](README.md)). On each run it queries `https://<graph endpoint>/<version>/<resource>/<relationship>` for every configured relationship of every tenant, page by page, and sends each record to the manager with `integration` set to `ms-graph` and the record under `ms-graph` (with `resource` and `relationship` fields added).

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

Configure the Microsoft Graph module in the agent's `ossec.conf`, inside `<ossec_config>`:

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
| `only_future_events` | No | `yes` | `yes`: when the module starts, events older than the start are not collected. `no`: collection resumes from the last position saved before the agent stopped. |
| `run_on_start` | No | `yes` | Query the API as soon as the module starts instead of waiting for the first `interval`. |
| `interval` | No | `1d` | Time between runs. See [Scheduling](README.md#scheduling) for units and the `day`/`wday`/`time` alternatives. |
| `version` | No | `v1.0` | Microsoft Graph API version. Options: `v1.0`, `beta`. |
| `curl_max_size` | No | `1M` | Maximum size of an HTTP response: a number with an optional unit `B`, `K`, `M` or `G` (bytes when none). Minimum `1K`. |
| `page_size` | No | `50` | Number of results requested per page (`$top`). Minimum `1`. |
| `time_delay` | No | `30s` | Each query only asks for records older than this delay, to allow for API propagation. A number with an optional unit `s`, `m`, `h`, `d` or `w`. |
| `api_auth` | Yes | — | Authentication configuration section. At least one is required; several can be defined, one per tenant. |
| `client_id` | Yes | — | Application (client) ID. |
| `tenant_id` | Yes | — | Tenant ID. |
| `secret_value` | Yes | — | Application client secret. |
| `api_type` | Yes | — | API endpoint type. Options: `global`, `gcc-high`, `dod` (see [API types](#api-types)). There is no default: an `api_auth` without it makes the configuration fail to load. |
| `resource` | Yes | — | Defines a Microsoft Graph resource to monitor. At least one is required; several are supported. |
| `name` | Yes | — | The resource name (for example, `security`, `identityProtection`). |
| `relationship` | Yes | — | The relationship to query within the resource (for example, `alerts_v2`, `incidents`). At least one per resource; several may be given. |

Any other element makes the configuration fail to load.

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
| `identityProtection` | `riskDetections`, `servicePrincipalRiskDetections` | Identity Protection risk detections. |
| `deviceManagement` | `auditEvents` | Intune audit events. |
| `deviceManagement` | any other, for example `managedDevices`, `detectedApps` | Read as an inventory: every run sends the full list (each record with a `scan_id`), not only new records. For `detectedApps`, each app carries the `managedDevices` it is installed on. |

### Monitoring multiple resources

```xml
<ms-graph>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <api_auth>
    <client_id>YOUR_CLIENT_ID</client_id>
    <tenant_id>YOUR_TENANT_ID</tenant_id>
    <secret_value>YOUR_CLIENT_SECRET</secret_value>
    <api_type>global</api_type>
  </api_auth>
  <resource>
    <name>security</name>
    <relationship>alerts_v2</relationship>
    <relationship>incidents</relationship>
  </resource>
</ms-graph>
```

## Verify the integration

Restart the agent and look for the module's lines (tag `wazuh-modulesd:ms-graph`):

```bash
systemctl restart wazuh-agent
grep "ms-graph" /var/ossec/logs/ossec.log
```

`Started module.` is logged at start and `Scanning tenant '<tenant_id>'` on every run; request failures are logged under the same tag.
