# Office 365 Integration

## Introduction

The Wazuh Office 365 module retrieves audit logs from the Microsoft Office 365 Management Activity API. This enables monitoring of user and administrator activity across Office 365 services, including Exchange Online, SharePoint Online, Azure Active Directory, and Microsoft Teams.

It is an agent module, built into the agent's `wazuh-modulesd` and available on Linux, macOS and Windows agents (see [Integrations](README.md)). It periodically lists and downloads the new content blobs of each configured subscription, for each tenant, and sends each audit record to the manager with `integration` set to `office365` and the record under `office365` (with a `Subscription` field naming the content type).

## Prerequisites

- A Microsoft 365 tenant with admin access.
- An Azure AD application registered with the required API permissions.
- The application's tenant ID, client ID, and client secret.

## Azure AD application setup

1. In the Azure portal, navigate to **Azure Active Directory** > **App registrations**.
2. Register a new application.
3. Under **API permissions**, add the following permissions:
   - **Office 365 Management APIs** > **ActivityFeed.Read** (Application permission)
   - **Office 365 Management APIs** > **ActivityFeed.ReadDlp** (Application permission, if DLP events are needed)
4. Grant admin consent for the permissions.
5. Under **Certificates & secrets**, create a new client secret and note the value.
6. Note the **Application (client) ID** and **Directory (tenant) ID** from the application overview.

## Configuration

Configure the Office 365 module in the agent's `ossec.conf`, inside `<ossec_config>`:

```xml
<office365>
  <enabled>yes</enabled>
  <only_future_events>yes</only_future_events>
  <interval>1m</interval>
  <curl_max_size>1M</curl_max_size>
  <api_auth>
    <tenant_id>YOUR_TENANT_ID</tenant_id>
    <client_id>YOUR_CLIENT_ID</client_id>
    <client_secret_path>/var/ossec/etc/office365_secret</client_secret_path>
  </api_auth>
  <subscriptions>
    <subscription>Audit.AzureActiveDirectory</subscription>
    <subscription>Audit.Exchange</subscription>
    <subscription>Audit.SharePoint</subscription>
    <subscription>Audit.General</subscription>
  </subscriptions>
</office365>
```

### Configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `enabled` | No | `yes` | Enables or disables the module. |
| `only_future_events` | No | `yes` | `yes`: when the module starts, events older than the start are not collected. `no`: collection resumes from the last position saved before the agent stopped. |
| `interval` | No | `1m` | Time between API queries: a number with an optional unit `s`, `m`, `h`, `d` or `w` (seconds when none). At most `1d`. |
| `curl_max_size` | No | `1M` | Maximum size of an HTTP response: a number with an optional unit `B`, `K`, `M` or `G` (bytes when none). Minimum `1K`. |
| `api_auth` | Yes | — | Authentication configuration section. At least one is required; several can be defined for multi-tenant setups. |
| `tenant_id` | Yes | — | Azure AD tenant ID. |
| `client_id` | Yes | — | Azure AD application (client) ID. |
| `client_secret_path` | Yes (or `client_secret`) | — | Path to a file containing the client secret. The file must exist when the configuration is loaded, otherwise the configuration fails to load. Cannot be set together with `client_secret`. |
| `client_secret` | Yes (or `client_secret_path`) | — | The client secret value directly (use `client_secret_path` for better security). Cannot be set together with `client_secret_path`. |
| `api_type` | No | `commercial` | API endpoint type. Options: `commercial`, `gcc`, `gcc-high` (see [GCC and GCC High environments](#gcc-and-gcc-high-environments)); any other value makes the configuration fail to load. |
| `subscriptions` | Yes | — | Section defining which content subscriptions to monitor. |
| `subscription` | Yes | — | A content type name, passed to the API as is. Cannot be empty. |

Any other element makes the configuration fail to load.

### Available subscriptions

| Subscription name | Description |
|-------------------|-------------|
| `Audit.AzureActiveDirectory` | Azure Active Directory audit events |
| `Audit.Exchange` | Exchange Online audit events |
| `Audit.SharePoint` | SharePoint Online and OneDrive for Business audit events |
| `Audit.General` | General audit events (including Microsoft Teams) |
| `DLP.All` | Data Loss Prevention events (requires additional permissions) |

### GCC and GCC High environments

For US Government Cloud environments, set the `api_type` option. It selects the endpoints the module uses:

| `api_type` | Login endpoint | Management API endpoint |
|------------|----------------|-------------------------|
| `commercial` | `login.microsoftonline.com` | `manage.office.com` |
| `gcc` | `login.microsoftonline.com` | `manage-gcc.office.com` |
| `gcc-high` | `login.microsoftonline.us` | `manage.office365.us` |


```xml
<api_auth>
  <tenant_id>YOUR_TENANT_ID</tenant_id>
  <client_id>YOUR_CLIENT_ID</client_id>
  <client_secret_path>/var/ossec/etc/office365_secret</client_secret_path>
  <api_type>gcc-high</api_type>
</api_auth>
```

## Verify the integration

Restart the agent and look for the module's lines (tag `wazuh-modulesd:office365`):

```bash
systemctl restart wazuh-agent
grep "office365" /var/ossec/logs/ossec.log
```

`Module Office365 started.` is logged at start. Request failures are logged under the same tag, and `Office365 tenant '<tenant_id>', connected successfully.` is logged when a tenant that was failing answers again.
