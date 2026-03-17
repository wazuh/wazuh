# Office 365 Integration

## Introduction

The Wazuh Office 365 module retrieves audit logs from the Microsoft Office 365 Management Activity API. This enables monitoring of user and administrator activity across Office 365 services, including Exchange Online, SharePoint Online, Azure Active Directory, and Microsoft Teams.

The module runs on the Wazuh agent and periodically queries the Office 365 API for new audit events. Events are processed by the Wazuh rule engine to generate alerts for suspicious activity such as unauthorized access, mail forwarding rule changes, and privilege escalation.

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

Configure the Office 365 module in the Wazuh agent `ossec.conf` file:

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
| `only_future_events` | No | `yes` | Only retrieve events generated after the module starts. |
| `interval` | No | `1m` | Time interval between API queries. |
| `curl_max_size` | No | `1M` | Maximum size of the HTTP response body (in bytes or with suffix `K`, `M`). |
| `api_auth` | Yes | — | Authentication configuration section. Multiple `api_auth` blocks can be defined for multi-tenant setups. |
| `tenant_id` | Yes | — | Azure AD tenant ID. |
| `client_id` | Yes | — | Azure AD application (client) ID. |
| `client_secret_path` | Yes | — | Path to a file containing the client secret. |
| `client_secret` | No | — | The client secret value directly (use `client_secret_path` for better security). |
| `api_type` | No | `commercial` | API endpoint type. Options: `commercial`, `gcc`, `gcc-high`. |
| `subscriptions` | Yes | — | Section defining which content subscriptions to monitor. |
| `subscription` | Yes | — | Individual subscription name. |

### Available subscriptions

| Subscription name | Description |
|-------------------|-------------|
| `Audit.AzureActiveDirectory` | Azure Active Directory audit events |
| `Audit.Exchange` | Exchange Online audit events |
| `Audit.SharePoint` | SharePoint Online and OneDrive for Business audit events |
| `Audit.General` | General audit events (including Microsoft Teams) |
| `DLP.All` | Data Loss Prevention events (requires additional permissions) |

### GCC and GCC High environments

For US Government Cloud environments, set the `api_type` option:

```xml
<api_auth>
  <tenant_id>YOUR_TENANT_ID</tenant_id>
  <client_id>YOUR_CLIENT_ID</client_id>
  <client_secret_path>/var/ossec/etc/office365_secret</client_secret_path>
  <api_type>gcc-high</api_type>
</api_auth>
```

## Verify the integration

Restart the Wazuh agent after applying the configuration:

```bash
systemctl restart wazuh-agent
```

Check the module logs:

```bash
grep "office365" /var/ossec/logs/ossec.log
```

Office 365 audit events generate alerts with the `office365` data field populated.
