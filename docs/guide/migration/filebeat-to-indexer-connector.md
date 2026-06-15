# Migrating from Filebeat to the Indexer Connector

When upgrading the Wazuh Manager from 4.x to 5.x, Filebeat must be stopped and removed from the manager host. Filebeat was a separate package responsible for shipping alert and archive JSON files to the Wazuh Indexer. In Wazuh 5.x this role is handled by the built-in **Indexer Connector**, which is part of the manager process itself.

Filebeat is not uninstalled automatically when the manager package is upgraded. The steps below are a required part of the manager upgrade procedure.

## Configuration mapping

### Core connection settings

These settings have a direct equivalent and must be translated during the upgrade.

| `filebeat.yml` (4.x) | Wazuh 5.x equivalent | Where |
|---|---|---|
| `output.elasticsearch.hosts` | `<indexer><hosts><host>` | `wazuh-manager.conf` |
| `output.elasticsearch.protocol` | Scheme prefix in the host URL (`https://`) | `wazuh-manager.conf` |
| `output.elasticsearch.username` | `wazuh-manager-keystore -f indexer -k username -v <value>` | Keystore |
| `output.elasticsearch.password` | `wazuh-manager-keystore -f indexer -k password -v <value>` | Keystore |
| `output.elasticsearch.ssl.certificate_authorities` | `<indexer><ssl><certificate_authorities><ca>` | `wazuh-manager.conf` |
| `output.elasticsearch.ssl.certificate` | `<indexer><ssl><certificate>` | `wazuh-manager.conf` |
| `output.elasticsearch.ssl.key` | `<indexer><ssl><key>` | `wazuh-manager.conf` |

### Advanced output settings

These settings were available in Filebeat and commonly tuned in production deployments.

| `filebeat.yml` (4.x) | Wazuh 5.x equivalent | Notes |
|---|---|---|
| `output.elasticsearch.ssl.verification_mode` | No equivalent, always enforced | Certificate verification cannot be disabled. Deployments using `verification_mode: none` must provide a valid CA. |
| `output.elasticsearch.ssl.supported_protocols` | No equivalent | The connector uses the system's default TLS negotiation. |
| `output.elasticsearch.ssl.cipher_suites` | No equivalent | Cipher selection is not user-configurable. |
| `output.elasticsearch.bulk_max_size` | No equivalent, auto-adapting | The connector starts at 25 000 events per bulk request and dynamically halves the size on HTTP 413 errors. |
| `output.elasticsearch.worker` | No equivalent | The connector uses a single async thread. Multiple workers are not supported. |
| `output.elasticsearch.timeout` | No equivalent, fixed at 10 s | The per-request HTTP timeout is hardcoded and cannot be changed. |
| `output.elasticsearch.compression_level` | No equivalent | The connector does not compress bulk payloads. |

### Queue and buffering settings

| `filebeat.yml` (4.x) | Wazuh 5.x equivalent | Notes |
|---|---|---|
| `queue.mem.events` | `WAZUH_INDEXER_QUEUE_MAX_EVENTS` env var | Default: 131 072 events. See [Tuning the indexer queue](#tuning-the-indexer-queue). |
| `queue.mem.flush.min_events` | No equivalent | The connector flushes when the bulk reaches 25 000 events or the flush interval elapses. |
| `queue.mem.flush.timeout` | No equivalent | Fixed flush interval; see [Tuning the indexer queue](#tuning-the-indexer-queue). |

### Module and pipeline settings

| `filebeat.yml` (4.x) | Wazuh 5.x equivalent | Notes |
|---|---|---|
| `filebeat.modules[wazuh].alerts.enabled` | Always active, no setting required | Alert indexing is always on; it cannot be disabled independently. |
| `filebeat.modules[wazuh].archives.enabled` | No equivalent | Raw event archiving is managed by the Engine pipeline, not a module toggle. |
| `filebeat.modules[wazuh].alerts.var.paths` | No equivalent | The Engine reads events from internal queues, not from filesystem paths. |
| `filebeat.modules[wazuh].alerts.var.index_prefix` | No equivalent | Index names are fixed |

### Processors

Filebeat's `processors` section allowed field-level manipulation of events before they were sent to Elasticsearch — adding host metadata, cloud metadata, custom fields, or dropping fields. **The Indexer Connector has no equivalent for any processor.**

| Filebeat processor (4.x) | Wazuh 5.x status |
|---|---|
| `add_host_metadata` | Not available. Host context is embedded in the event by the Engine. |
| `add_cloud_metadata` | Not available. Cloud context is enriched at the Engine level via GeoIP and integration decoders. |
| `add_fields` | Not available. |
| `drop_fields` | Not available. |
| `rename` | Not available. |
| Any other processor | Not available. |

If you relied on processors to add fields required by downstream consumers, that enrichment must be moved to the Engine's decoder/integration layer or handled post-indexing.

### Settings with no 5.x equivalent

These settings are removed and require no action during the upgrade.

| `filebeat.yml` (4.x) | Reason removed |
|---|---|
| `setup.template.json.*` | Index templates are provisioned by the Wazuh Indexer at install time. |
| `setup.ilm.*` | ILM/ISM policies are configured directly on the Wazuh Indexer. |
| `logging.*` | Filebeat-specific logging; use manager logs at `/var/wazuh-manager/logs/wazuh-manager.log`. |
| `logging.metrics.enabled` | Filebeat internal metrics; see [Observability](#observability) for 5.x equivalents. |
| `seccomp` | Filebeat process sandboxing; not applicable to the in-process connector. |

## Tuning the indexer queue

In Filebeat, queue behaviour was controlled with `queue.mem.*` keys in `filebeat.yml`. In Wazuh 5.x, the equivalent is the `WAZUH_INDEXER_QUEUE_MAX_EVENTS` environment variable, which controls the maximum number of events the async queue can hold before new events are dropped.

| Parameter | Filebeat 4.x | Wazuh 5.x | Default |
|---|---|---|---|
| Max queue depth | `queue.mem.events` | `WAZUH_INDEXER_QUEUE_MAX_EVENTS` env var | 131 072 events |
| Flush interval | `queue.mem.flush.timeout` | Not user-configurable (20 s, hardcoded) | 20 s |
| Min events to flush | `queue.mem.flush.min_events` | Not user-configurable (25 000 events per bulk) | 25 000 |

To override the queue depth, set the environment variable for the `wazuh-manager` service before starting it:

```bash
# Example: raise the queue to 262144 events
sudo systemctl edit wazuh-manager
```

Add the following to the override file:

```ini
[Service]
Environment="WAZUH_INDEXER_QUEUE_MAX_EVENTS=262144"
```

Then reload and restart the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart wazuh-manager
```

> **Note:** Setting `WAZUH_INDEXER_QUEUE_MAX_EVENTS=0` disables the limit (unlimited queue). This can cause unbounded memory growth if the indexer is unreachable for an extended period. Monitor queue usage with the metrics described in [Observability](#observability).

## Observability

In Filebeat 4.x, `logging.metrics.enabled: true` periodically logged throughput and queue statistics. In Wazuh 5.x the equivalent data is exposed as internal metrics by the Engine.

| Filebeat metric | Wazuh 5.x equivalent |
|---|---|
| Events published | `INDEXER_QUEUE_SIZE` (pending events in queue) |
| Events dropped | `INDEXER_EVENTS_DROPPED` (events dropped when queue is full) |
| Queue usage | `INDEXER_QUEUE_USAGE_PERCENT` (queue fill percentage) |

These metrics are written to the manager log and exposed via the metrics subsystem. No additional configuration is required.

## Required steps during the manager upgrade

### 1. Note your current Filebeat settings

Before upgrading, record the values from `/etc/filebeat/filebeat.yml` that you will need:

- Indexer host(s) and port
- Username and password (from the Filebeat keystore or environment)
- Paths to CA, certificate, and key files
- Any advanced settings listed in the tables above that have a 5.x equivalent

### 2. Deploy certificates to the new path

TLS certificates previously placed under `/etc/filebeat/certs/` must be available under `/var/wazuh-manager/etc/certs/` after the upgrade.

```bash
NODE_NAME=manager  # Replace with your manager node name

sudo mkdir -p /var/wazuh-manager/etc/certs

sudo tar -xf wazuh-certificates.tar -C /var/wazuh-manager/etc/certs/ \
  ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem

sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME.pem \
        /var/wazuh-manager/etc/certs/manager.pem
sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME-key.pem \
        /var/wazuh-manager/etc/certs/manager-key.pem

sudo chmod 500 /var/wazuh-manager/etc/certs
sudo chmod 400 /var/wazuh-manager/etc/certs/*
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc/certs
```

> **If you used `ssl.verification_mode: none` in Filebeat**, you must now provide a valid CA certificate. The Indexer Connector always verifies the server certificate. Obtain the indexer's root CA and place it at `/var/wazuh-manager/etc/certs/root-ca.pem` before proceeding.

### 3. Store credentials in the manager keystore

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username -v <your_username>
sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -v <your_password>
```

### 4. Add the `<indexer>` block to `wazuh-manager.conf`

The `<indexer>` block accepts the following fields:

| Field | Required | Description |
|---|---|---|
| `<hosts><host>` | Yes | URL of a Wazuh Indexer node. Must include scheme (`http://` or `https://`) and port. Repeat for each node in a cluster. |
| `<ssl><certificate_authorities><ca>` | Yes (HTTPS) | Path to a CA certificate file used to verify the indexer's TLS certificate. Repeat for each CA file. |
| `<ssl><certificate>` | No | Path to the manager's client TLS certificate, used for mutual TLS authentication. |
| `<ssl><key>` | No | Path to the private key matching `<certificate>`. Required when `<certificate>` is set. |

Credentials (`username` and `password`) are not set here, they are stored exclusively in the manager keystore (step 3).

Add the following block inside `<wazuh_config>` in `/var/wazuh-manager/etc/wazuh-manager.conf`, using the hosts and certificate paths from your old `filebeat.yml`:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/var/wazuh-manager/etc/certs/manager.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/manager-key.pem</key>
  </ssl>
</indexer>
```

For a multi-node indexer cluster, list each node as a separate `<host>` element:

```xml
<hosts>
  <host>https://10.0.0.1:9200</host>
  <host>https://10.0.0.2:9200</host>
  <host>https://10.0.0.3:9200</host>
</hosts>
```

### 5. Stop Filebeat and start the upgraded manager

```bash
sudo systemctl stop filebeat
sudo systemctl disable filebeat
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

### 6. Remove Filebeat

Once indexing is confirmed, uninstall the Filebeat package:

> **Note**: Please note that uninstalling this will delete the filebeat.yml file.

**Debian-based platforms:**

```bash
sudo apt-get remove --purge filebeat
sudo rm -rf /etc/filebeat /var/log/filebeat
```

**Red Hat-based platforms:**

```bash
sudo rpm -e filebeat
sudo rm -rf /etc/filebeat /var/log/filebeat
```
