# Azure Integration

## Introduction

The Wazuh Azure module retrieves logs from Microsoft Azure services and forwards them for analysis. The module supports three data sources:

- **Log Analytics**: Queries Azure Log Analytics workspaces using Kusto Query Language (KQL).
- **Microsoft Graph**: Retrieves directory and security data from the Microsoft Graph API.
- **Azure Storage**: Reads logs from Azure Blob Storage containers.

The module runs as a Wazuh wodle on the Wazuh agent. It invokes the `wodles/azure/azure-logs` Python script to connect to Azure services.

## Prerequisites

- An Azure subscription with the required services enabled.
- An Azure AD application registered with appropriate API permissions.
- Python 3 and the required Azure Python libraries installed on the Wazuh agent.

## Configuration

The Azure module is configured inside the `<ossec_config>` block of the Wazuh agent configuration file (`ossec.conf`).

### Log Analytics configuration

```xml
  <wodle name="azure-logs">
    <disabled>no</disabled>
    <run_on_start>yes</run_on_start>
    <interval>1h</interval>
    <log_analytics>
      <auth_path>/var/ossec/etc/azure_auth.json</auth_path>
      <tenantdomain>my-tenant.onmicrosoft.com</tenantdomain>
      <request>
        <tag>azure-activity</tag>
        <query>AzureActivity | where Level != "Informational"</query>
        <workspace>workspace-id-here</workspace>
        <time_offset>1h</time_offset>
      </request>
    </log_analytics>
  </wodle>
```

### Microsoft Graph configuration

```xml
  <wodle name="azure-logs">
    <disabled>no</disabled>
    <run_on_start>yes</run_on_start>
    <interval>1h</interval>
    <graph>
      <auth_path>/var/ossec/etc/azure_auth.json</auth_path>
      <tenantdomain>my-tenant.onmicrosoft.com</tenantdomain>
      <request>
        <tag>azure-graph</tag>
        <query>auditLogs/signIns</query>
        <time_offset>1h</time_offset>
      </request>
    </graph>
  </wodle>
```

### Azure Storage configuration

```xml
  <wodle name="azure-logs">
    <disabled>no</disabled>
    <run_on_start>yes</run_on_start>
    <interval>1h</interval>
    <storage>
      <auth_path>/var/ossec/etc/azure_storage_auth.json</auth_path>
      <tag>azure-storage</tag>
      <container name="insights-logs-networksecuritygroupflowevent">
        <blobs>.json</blobs>
        <content_type>json</content_type>
        <time_offset>1h</time_offset>
      </container>
    </storage>
  </wodle>
```

### Configuration options

#### General options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `disabled` | No | `no` | Disables the Azure module when set to `yes`. |
| `run_on_start` | No | `yes` | Process logs immediately when the module starts. |
| `interval` | No | `1h` | Time interval between Azure API queries. |
| `timeout` | No | `3600` | Maximum execution time in seconds for each run. |

#### Log Analytics and Graph API options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `application_id` | No | — | Azure AD application ID (deprecated; use `auth_path`). |
| `application_key` | No | — | Azure AD application key (deprecated; use `auth_path`). |
| `auth_path` | No | — | Path to a JSON file containing authentication credentials. |
| `tenantdomain` | Yes | — | Azure AD tenant domain (for example, `contoso.onmicrosoft.com`). |
| `request` | Yes | — | Defines a query request. Multiple `request` blocks are supported. |
| `tag` | No | — | Custom tag added to generated alerts for identification. |
| `query` | Yes | — | KQL query (Log Analytics) or Graph API resource path. |
| `workspace` | Yes (Log Analytics) | — | Log Analytics workspace ID. |
| `time_offset` | No | — | Time range for the query (for example, `1h`, `1d`). |
| `timeout` | No | `3600` | Maximum execution time in seconds for the request. |

#### Storage options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `account_name` | No | — | Azure storage account name (deprecated; use `auth_path`). |
| `account_key` | No | — | Azure storage account key (deprecated; use `auth_path`). |
| `auth_path` | No | — | Path to a JSON file containing storage authentication credentials. |
| `tag` | No | — | Custom tag added to generated alerts for identification. |
| `container` | Yes | — | Defines a blob container to monitor. Use `name` attribute for the container name. |
| `blobs` | No | — | Blob name filter (for example, `.json` to match JSON files). |
| `content_type` | No | — | Expected blob content type (for example, `json`, `text`). |
| `path` | No | — | Blob prefix filter. |
| `time_offset` | No | — | Time range for blob selection (for example, `1h`, `1d`). |
| `timeout` | No | `3600` | Maximum execution time in seconds for the container scan. |

## Azure AD application setup

### Register an application

1. In the Azure portal, navigate to **Azure Active Directory** > **App registrations**.
2. Register a new application.
3. Under **API permissions**, add permissions based on the data sources you need:
   - **Log Analytics**: `Log Analytics API` > `Data.Read`
   - **Graph API**: `Microsoft Graph` > `AuditLog.Read.All`, `Directory.Read.All`
4. Grant admin consent for the permissions.
5. Create a client secret under **Certificates & secrets**.

### Authentication file format

Create a JSON authentication file with the following structure:

For Log Analytics and Graph API:
```json
{
  "application_id": "YOUR_APPLICATION_ID",
  "application_key": "YOUR_CLIENT_SECRET",
  "tenant_id": "YOUR_TENANT_ID"
}
```

For Storage:
```json
{
  "account_name": "YOUR_STORAGE_ACCOUNT_NAME",
  "account_key": "YOUR_STORAGE_ACCOUNT_KEY"
}
```

## Verify the integration

Restart the Wazuh agent after applying the configuration:

```bash
systemctl restart wazuh-agent
```

Check the module logs:

```bash
grep "azure" /var/ossec/logs/ossec.log
```

Azure events generate alerts with the `azure` data field populated.
