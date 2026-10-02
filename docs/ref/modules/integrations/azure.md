# Azure Integration

## Introduction

The Azure module (`<wodle name="azure-logs">`) collects logs from three Microsoft sources:

- **Log Analytics** (`<log_analytics>`): runs Kusto (KQL) queries against Log Analytics workspaces.
- **Microsoft Graph** (`<graph>`): reads Microsoft Graph `v1.0` resources such as the Entra ID
  (Azure AD) audit and sign-in logs.
- **Azure Storage** (`<storage>`): reads blobs from Azure Blob Storage containers.

It is an agent module, configured in the agent's `ossec.conf`, and is not available on Windows agents
(see [Integrations](README.md)). On each run the agent's `wazuh-modulesd` invokes the
`wodles/azure/azure-logs` Python script once per request or container, and the script sends every
row, Graph record or blob event to the manager. To collect Microsoft Graph security resources with
paging and per-resource state, see also the [Microsoft Graph](microsoft-graph.md) module.

## Prerequisites

- An Azure subscription with the required services enabled.
- For Log Analytics and Graph: an application registered in Microsoft Entra ID (Azure AD) with a
  client secret and the API permissions of the data you query.
- For Storage: the storage account name and an access key.
- The Python packages the script imports — `azure-storage-blob`, `requests`, `SQLAlchemy`,
  `python-dateutil` and `pytz` — installed for the agent host's `python3`.

## Configuration

The blocks go inside `<ossec_config>` in the agent's `ossec.conf`. One `azure-logs` block may hold
several `<log_analytics>`, `<graph>` and `<storage>` blocks. An element not listed below directly
under `<wodle name="azure-logs">` makes the configuration fail to load; inside a `<log_analytics>`,
`<graph>`, `<storage>`, `<request>` or `<container>` it makes that block be logged as an error and
skipped.

### Log Analytics configuration

```xml
<wodle name="azure-logs">
  <disabled>no</disabled>
  <run_on_start>yes</run_on_start>
  <interval>1h</interval>
  <log_analytics>
    <auth_path>/var/ossec/etc/azure_auth</auth_path>
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
    <auth_path>/var/ossec/etc/azure_auth</auth_path>
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
    <auth_path>/var/ossec/etc/azure_storage_auth</auth_path>
    <tag>azure-storage</tag>
    <container name="insights-logs-networksecuritygroupflowevent">
      <blobs>.json</blobs>
      <content_type>json_file</content_type>
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
| `run_on_start` | No | `yes` | Run as soon as the module starts instead of waiting for the first `interval`. |
| `interval` | No | `1d` | Time between runs. See [Scheduling](README.md#scheduling) for units and the `day`/`wday`/`time` alternatives. |
| `timeout` | No | none | Maximum run time of each script invocation, in seconds, for every request and container that does not set its own. Without it the module waits for the script to finish. |

#### Log Analytics and Graph options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `auth_path` | Yes | — | Path to the [authentication file](#authentication-files) with `application_id` and `application_key`. |
| `tenantdomain` | Yes | — | Tenant domain (for example, `contoso.onmicrosoft.com`). |
| `request` | Yes | — | A query to run. Several may be given. |
| `tag` | No | random | Added to each event (`log_analytics_tag` or `azure_aad_tag`). Without it a random `request_<n>` is used and an info message is logged. |
| `query` | Yes | — | KQL query (Log Analytics) or Graph resource path relative to `https://graph.microsoft.com/v1.0/` (Graph). |
| `workspace` | Yes (Log Analytics) | — | Log Analytics workspace ID. Ignored, with an info message, in `<graph>`. |
| `time_offset` | No | — | How far back each run reads: a number followed by `m`, `h` or `d`. Events already processed are not read again. Without it, each run continues from the newest event already processed. |
| `timeout` | No | general `timeout` | Maximum run time of this request, in seconds. |

A `<log_analytics>` or `<graph>` block without `auth_path`, `tenantdomain` or a valid `request`, and
a `request` without `query` (or without `workspace` in Log Analytics), are not fatal: they are logged
as an error (`… Skipping block...` / `… Skipping request block...`) and skipped.

#### Storage options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `auth_path` | Yes | — | Path to the [authentication file](#authentication-files) with `account_name` and `account_key`. |
| `tag` | No | random | Added to each event as `azure_storage_tag`. Without it a random `storage_<n>` is used and an info message is logged. |
| `container` | Yes | — | A blob container to read; the `name` attribute is required. Several may be given. A container without a valid `name` is skipped. |
| `blobs` | No | all blobs | Blob name filter, by extension (for example `.json`). |
| `content_type` | No | `text` | Blob content format: `json_file` (a JSON object with a `records` array), `json_inline` (one JSON object per line) or `text` (one plain-text event per line). Any other value skips the container. |
| `path` | No | — | Only read blobs whose name starts with this prefix. Cannot be empty. |
| `time_offset` | No | — | How far back each run reads, as in Log Analytics. |
| `timeout` | No | general `timeout` | Maximum run time of this container's scan, in seconds. |

A `<storage>` block without `auth_path` or without a valid container is logged as an error and
skipped.

The `application_id`, `application_key`, `account_name` and `account_key` elements are no longer
accepted: credentials are read only from the `auth_path` file, and a block that sets one of them is
skipped as described above.

## Azure setup

### Register an application

1. In the Azure portal, navigate to **Microsoft Entra ID** > **App registrations**.
2. Register a new application.
3. Under **API permissions**, add permissions based on the data sources you need:
   - **Log Analytics**: `Log Analytics API` > `Data.Read`
   - **Graph API**: `Microsoft Graph` > `AuditLog.Read.All`, `Directory.Read.All`
4. Grant admin consent for the permissions.
5. Create a client secret under **Certificates & secrets**.

### Authentication files

An authentication file holds two lines in `field = value` format (spaces are ignored).

For Log Analytics and Graph (the application's client ID and client secret):

```text
application_id = YOUR_APPLICATION_ID
application_key = YOUR_CLIENT_SECRET
```

For Storage:

```text
account_name = YOUR_STORAGE_ACCOUNT_NAME
account_key = YOUR_STORAGE_ACCOUNT_KEY
```

## Events

Every event carries an `azure_tag` naming its source — `azure-log-analytics` (one event per result
row, with the row's columns as fields), `azure-ad-graph` (one per Graph record) or `azure-storage`
(one per record or line of a blob) — plus the configured `tag` field described above. Plain-text
storage lines are sent as `azure_tag: azure-storage. [azure_storage_tag: <tag>.] <line>`.

## Verify the integration

Restart the agent and look for the module's lines (tag `wazuh-modulesd:azure-logs`):

```bash
systemctl restart wazuh-agent
grep "azure-logs" /var/ossec/logs/ossec.log
```

Each source logs `Starting … collection` and `Finished … collection` lines (for example
`Finished Log Analytics collection for request '<tag>'.`); a failed request or container is logged
as a warning with the script's error.
