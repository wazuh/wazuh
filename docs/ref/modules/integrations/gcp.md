# GCP Integration

## Introduction

The GCP (Google Cloud Platform) module collects Google Cloud logs and forwards them to the manager.
It has two independent blocks:

- **`<gcp-pubsub>`**: pulls log messages from a Pub/Sub subscription.
- **`<gcp-bucket>`**: reads Cloud Storage access logs from one or more buckets.

It is an agent module, configured in the agent's `ossec.conf`, and is not available on Windows agents
(see [Integrations](README.md)). On each run the agent's `wazuh-modulesd` invokes the
`wodles/gcloud/gcloud` Python script, which authenticates with a service account credentials file.
Each event is sent with `integration` set to `gcp` and the Google Cloud log under `gcp`.

## Prerequisites

- A Google Cloud project with the Pub/Sub API or the Cloud Storage API enabled.
- A service account and its JSON key file, stored on the agent host.
- The Google Cloud client libraries for Python (Pub/Sub and Cloud Storage) and `pytz`, installed for
  the agent host's `python3`.

## Configuration

Both blocks go inside `<ossec_config>` in the agent's `ossec.conf`. Any element not listed below
makes the configuration fail to load.

### Pub/Sub configuration

```xml
<gcp-pubsub>
  <enabled>yes</enabled>
  <project_id>my-gcp-project</project_id>
  <subscription_name>wazuh-subscription</subscription_name>
  <credentials_file>/var/ossec/etc/credentials.json</credentials_file>
  <max_messages>100</max_messages>
  <num_threads>1</num_threads>
  <pull_on_start>yes</pull_on_start>
  <interval>1h</interval>
</gcp-pubsub>
```

#### Pub/Sub options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `enabled` | No | `yes` | Enables or disables the module. |
| `project_id` | Yes | — | The Google Cloud project ID. |
| `subscription_name` | Yes | — | The Pub/Sub subscription to pull messages from. |
| `credentials_file` | Yes | — | Path to the service account JSON key; use an absolute path. The file must exist when the configuration is loaded, otherwise the configuration fails to load. |
| `max_messages` | No | `100` | Maximum number of messages pulled per request. Digits only. |
| `num_threads` | No | `1` | Number of threads pulling messages. Digits only. |
| `pull_on_start` | No | `yes` | Pull as soon as the module starts instead of waiting for the first `interval`. |
| `interval` | No | `1h` | Time between pulls. See [Scheduling](README.md#scheduling) for units and the `day`/`wday`/`time` alternatives. |

### Cloud Storage bucket configuration

```xml
<gcp-bucket>
  <enabled>yes</enabled>
  <run_on_start>yes</run_on_start>
  <interval>1h</interval>
  <bucket type="access_logs">
    <name>my-gcp-bucket</name>
    <credentials_file>/var/ossec/etc/credentials.json</credentials_file>
    <path>logs/</path>
    <only_logs_after>2024-JAN-01</only_logs_after>
    <remove_from_bucket>no</remove_from_bucket>
  </bucket>
</gcp-bucket>
```

#### Bucket options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `enabled` | No | `yes` | Enables or disables the module. |
| `run_on_start` | No | `yes` | Process the buckets as soon as the module starts instead of waiting for the first `interval`. |
| `interval` | No | `1h` | Time between bucket scans. See [Scheduling](README.md#scheduling). |
| `bucket` | Yes | — | A bucket to read. At least one is required, and several may be given. The `type` attribute is required and its only valid value is `access_logs`. |
| `name` | Yes | — | Name of the Cloud Storage bucket. |
| `credentials_file` | Yes | — | Path to the service account JSON key, with the same rules as in `<gcp-pubsub>`. |
| `path` | No | — | Only read objects whose name starts with this prefix. Cannot be empty. |
| `only_logs_after` | No | — | Only read logs from this date on, in `YYYY-MMM-DD` format (for example `2024-JAN-01`). |
| `remove_from_bucket` | No | `no` | Delete each object from the bucket after processing it. |

## Google Cloud setup

### Create a Pub/Sub topic and subscription

1. In the Google Cloud Console, navigate to **Pub/Sub** > **Topics**.
2. Create a new topic (for example, `wazuh-topic`).
3. Create a subscription for the topic (for example, `wazuh-subscription`).
4. Configure a log sink in **Logging** > **Log Router** to route audit logs to the Pub/Sub topic.

### Create a service account

1. In the Google Cloud Console, navigate to **IAM & Admin** > **Service Accounts**.
2. Create a new service account. The script checks these permissions before collecting:
   - `pubsub.subscriptions.consume` on the subscription (for example, the `Pub/Sub Subscriber` role).
   - `storage.buckets.get` and read access to the objects of the bucket (for example, the
     `Storage Object Viewer` role); object delete access as well if `remove_from_bucket` is `yes`.
3. Generate a JSON key and copy it to the agent host, at the path set in `credentials_file`.

## Verify the integration

Restart the agent and look for the module's lines (tags `wazuh-modulesd:gcp-pubsub` and
`wazuh-modulesd:gcp-bucket`):

```bash
systemctl restart wazuh-agent
grep "gcp-" /var/ossec/logs/ossec.log
```

Errors from the script, such as missing permissions, are logged under the same tags.

---

## Deprecated Options

### logging

**DEPRECATED:** The `<logging>` tag in both `<gcp-pubsub>` and `<gcp-bucket>` blocks is parsed but ignored.

- **Status:** Deprecated
- **Behavior:** Parser accepts the tag and logs a debug-level message, only visible with `wazuh_modules.debug=1` or higher in `local_internal_options.conf` (or `wazuh-modulesd -d`): "Tag 'logging' from the 'gcp-pubsub' (or 'gcp-bucket') module is deprecated. This setting will be skipped."
- **Replacement:** Set the GCP script log level with `wazuh_modules.debug` in `local_internal_options.conf` (`0`: warning, `1`: info, `2`: debug)
- **Note:** This tag has no effect and will be removed in a future version
