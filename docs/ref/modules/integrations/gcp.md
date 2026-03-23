# GCP Integration

## Introduction

The Wazuh GCP (Google Cloud Platform) module retrieves logs from Google Cloud services and forwards them to the Wazuh analysis engine. The module supports two collection methods:

- **Pub/Sub**: Subscribes to a Google Cloud Pub/Sub topic to receive log messages in real time.
- **Cloud Storage buckets**: Reads logs stored in Google Cloud Storage buckets (for example, access logs).

The GCP module runs as a Wazuh wodle on the Wazuh agent. It invokes the `wodles/gcloud/gcloud` Python script to connect to Google Cloud services using a service account credentials file.

## Prerequisites

- A Google Cloud project with the required APIs enabled (Pub/Sub API or Cloud Storage API).
- A service account with appropriate permissions and a downloaded JSON credentials file.
- The credentials file must be accessible to the Wazuh agent.
- Python 3 and the required Google Cloud Python libraries installed on the Wazuh agent.

## Configuration

The GCP module is configured inside the `<ossec_config>` block of the Wazuh agent configuration file (`ossec.conf`).

### Pub/Sub configuration

```xml
  <wodle name="gcp-pubsub">
    <enabled>yes</enabled>
    <project_id>my-gcp-project</project_id>
    <subscription_name>wazuh-subscription</subscription_name>
    <credentials_file>/var/ossec/etc/credentials.json</credentials_file>
    <max_messages>100</max_messages>
    <num_threads>1</num_threads>
    <pull_on_start>yes</pull_on_start>
    <interval>1h</interval>
  </wodle>
```

#### Pub/Sub options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `enabled` | No | `yes` | Enables or disables the module. |
| `project_id` | Yes | — | The Google Cloud project ID. |
| `subscription_name` | Yes | — | The name of the Pub/Sub subscription to pull messages from. |
| `credentials_file` | Yes | — | Path to the Google Cloud service account JSON credentials file. |
| `max_messages` | No | `100` | Maximum number of messages to pull per request. |
| `num_threads` | No | `1` | Number of threads used for pulling messages. |
| `pull_on_start` | No | `yes` | Pull messages immediately when the module starts. |
| `interval` | No | `1h` | Time interval between pull requests. |

### Cloud Storage bucket configuration

```xml
  <wodle name="gcp-bucket">
    <enabled>yes</enabled>
    <run_on_start>yes</run_on_start>
    <interval>1h</interval>
    <bucket type="access_logs">
      <name>my-gcp-bucket</name>
      <credentials_file>/var/ossec/etc/credentials.json</credentials_file>
      <path>logs/</path>
      <only_logs_after>2024-01-01</only_logs_after>
      <remove_from_bucket>no</remove_from_bucket>
    </bucket>
  </wodle>
```

#### Bucket options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `enabled` | No | `yes` | Enables or disables the module. |
| `run_on_start` | No | `yes` | Process logs immediately when the module starts. |
| `interval` | No | `1h` | Time interval between bucket scans. |
| `bucket` | Yes | — | Defines a bucket to monitor. Use `type` attribute to specify the bucket type (for example, `access_logs`). |
| `name` | Yes | — | Name of the Cloud Storage bucket. |
| `credentials_file` | Yes | — | Path to the service account credentials file. |
| `path` | No | — | Prefix (path) filter for objects in the bucket. |
| `only_logs_after` | No | — | Only process logs created after this date (format: `YYYY-MM-DD`). |
| `remove_from_bucket` | No | `no` | Delete log objects from the bucket after processing. |

## Google Cloud setup

### Create a Pub/Sub topic and subscription

1. In the Google Cloud Console, navigate to **Pub/Sub** > **Topics**.
2. Create a new topic (for example, `wazuh-topic`).
3. Create a subscription for the topic (for example, `wazuh-subscription`).
4. Configure a log sink in **Logging** > **Log Router** to route audit logs to the Pub/Sub topic.

### Create a service account

1. In the Google Cloud Console, navigate to **IAM & Admin** > **Service Accounts**.
2. Create a new service account with the following roles:
   - `Pub/Sub Subscriber` (for Pub/Sub integration)
   - `Storage Object Viewer` (for bucket integration)
3. Generate a JSON key and download it to the Wazuh agent.

## Verify the integration

After configuring the module, restart the Wazuh agent:

```bash
systemctl restart wazuh-agent
```

Check the Wazuh agent logs for GCP module activity:

```bash
grep "gcp" /var/ossec/logs/ossec.log
```

GCP events appear in the Wazuh alerts with the `gcp` data field populated.
