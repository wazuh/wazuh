# Migrating from Filebeat to the Indexer Connector

In Wazuh 4.x, Filebeat was a separate package on the manager host that read the alerts and archives files and shipped them to the Wazuh Indexer. In Wazuh 5.x Filebeat is gone: the manager daemons write to the indexer themselves through the built-in **Indexer Connector**, a library the engine (`wazuh-manager-analysisd`) uses to index events and the manager modules use to index their state.

There is no Filebeat configuration to reproduce. The manager connects to the indexer directly, so the only values you need to carry over are the ones you already set in `filebeat.yml`: the indexer hosts, the credentials, and the TLS certificates.

Filebeat is its own package, so removing the 4.x manager does not remove it. Removing it is part of the procedure below.

## Configuration mapping

| `filebeat.yml` (4.x) | Wazuh 5.x | Where |
|---|---|---|
| `output.elasticsearch.hosts` | `<indexer><hosts><host>` (include `https://` and port) | `wazuh-manager.conf` |
| `output.elasticsearch.username` | `username` in the `indexer` family of the keystore (default `wazuh-manager`) | Keystore |
| `output.elasticsearch.password` | `password` in the `indexer` family of the keystore, filled from `WAZUH_INDEXER_MANAGER_PASSWORD` | Keystore |
| `output.elasticsearch.ssl.certificate_authorities` | `<indexer><ssl><certificate_authorities><ca>` | `wazuh-manager.conf` |
| `output.elasticsearch.ssl.certificate` | `<indexer><ssl><certificate>` | `wazuh-manager.conf` |
| `output.elasticsearch.ssl.key` | `<indexer><ssl><key>` | `wazuh-manager.conf` |

Every other `filebeat.yml` setting is gone:

- **Output tuning** (`bulk_max_size`, `worker`, `timeout`, `compression_level`) and **queue/buffering** (`queue.mem.*`): the engine's connector is tuned with the `analysisd.indexer_*` internal options (bulk size in bytes, flush interval, queue size, request timeout, retry delay). See [Indexer Connector Settings](../../ref/modules/engine/configuration.md#indexer-connector-settings).
- **TLS options** (`ssl.verification_mode`, `ssl.supported_protocols`, `ssl.cipher_suites`): the `<indexer><ssl>` section has only `certificate_authorities`, `certificate` and `key`; there is no option to turn off server-certificate verification. If you used `verification_mode: none`, you must now provide the CA that signed the indexer's certificate.
- **Processors** (`add_host_metadata`, `add_fields`, `drop_fields`, etc.): not supported. If you relied on them to enrich events, move that logic to the Engine decoders/integrations.
- **Templates and ILM** (`setup.template.*`, `setup.ilm.*`): the manager does not install index templates; they are managed on the Wazuh Indexer.
- **Logging** (`logging.*`): connector messages go to the manager log, `/var/wazuh-manager/logs/wazuh-manager.log`.

## Migration steps

The 5.x installation already configures the connector: the installer writes an `<indexer>` section pointing at `https://127.0.0.1:9200` with the certificates under `etc/certs`, issues those certificates, and stores in the keystore the indexer password supplied as `WAZUH_INDEXER_MANAGER_PASSWORD` in `/etc/wazuh/credentials.env` (see [Credentials](../../ref/getting-started/credentials.md)). The steps below carry over what differs in your 4.x deployment.

### 1. Record your current Filebeat settings

From `/etc/filebeat/filebeat.yml`, note:

- Indexer host(s) and port
- Username and password
- Paths to the CA, certificate, and key files

### 2. Deploy the certificates

The connector presents `etc/certs/indexer-connector.pem` to the indexer and verifies the indexer against the CA files listed in `<certificate_authorities>`. The installation's `etc/certs/root-ca.pem` is also the CA of the agent listener: it signs `remoted.pem` and is what agents pin, so **do not overwrite it** with a different CA after the installation.

- **The manager was installed with the certificates of your 4.x deployment** (placed in `etc/certs` or `/etc/wazuh/ca` before the install, as [Certificates and credentials](manager-4x-to-5x.md#certificates-and-credentials) describes): nothing to do.
- **Otherwise**, deploy the client pair Filebeat used under the connector's file names, and the indexer's CA under a name of its own. Run as root:

```bash
NODE_NAME=manager  # Replace with your manager node name in wazuh-certificates.tar
CERTS=/var/wazuh-manager/etc/certs

tar -xf wazuh-certificates.tar -C /tmp ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
install -m 0640 -o root -g wazuh-manager /tmp/$NODE_NAME.pem     $CERTS/indexer-connector.pem
install -m 0640 -o root -g wazuh-manager /tmp/$NODE_NAME-key.pem $CERTS/indexer-connector-key.pem
install -m 0640 -o root -g wazuh-manager /tmp/root-ca.pem        $CERTS/indexer-root-ca.pem
rm -f /tmp/$NODE_NAME.pem /tmp/$NODE_NAME-key.pem /tmp/root-ca.pem
```

The files are `root:wazuh-manager` `0640`, the ownership and mode the installation gives the connector's files, so the daemons read them after dropping privileges. Nothing checks them before the daemons start: a file the `wazuh-manager` group cannot read fails only at the first indexer request.

### 3. Store the credentials in the keystore

The installation stored the password supplied in `WAZUH_INDEXER_MANAGER_PASSWORD` and the username `wazuh-manager`. To use the account Filebeat used instead, overwrite both as root:

```bash
printf '%s' '<your_username>' | sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username
printf '%s' '<your_password>' | sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password
```

A value already in the keystore is kept on every later start, whatever `/etc/wazuh/credentials.env` says. Each daemon reads the credentials once, so restart the manager after changing them (step 5).

### 4. Configure the `<indexer>` block

Edit the `<indexer>` section of `/var/wazuh-manager/etc/wazuh-manager.conf` with your hosts and certificate paths:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>etc/certs/indexer-root-ca.pem</ca>
    </certificate_authorities>
    <certificate>etc/certs/indexer-connector.pem</certificate>
    <key>etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

Use `etc/certs/root-ca.pem` as the `<ca>` when you skipped step 2. Relative paths are resolved from `/var/wazuh-manager`. For a multi-node indexer cluster, list each node as a separate `<host>`:

```xml
<hosts>
  <host>https://10.0.0.1:9200</host>
  <host>https://10.0.0.2:9200</host>
  <host>https://10.0.0.3:9200</host>
</hosts>
```

Credentials are not set here; they come from the keystore (step 3). Validate the file:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-conf validate
```

The section is described in full in the [Indexer Connector configuration reference](../../ref/modules/indexer_connector/configuration.md).

### 5. Stop Filebeat and restart the manager

```bash
sudo systemctl stop filebeat
sudo systemctl disable filebeat
sudo systemctl restart wazuh-manager
sudo /var/wazuh-manager/bin/wazuh-manager-control status
```

Confirm that the indexer accepts the manager's certificate and credentials, and read the connector's verdict on each node in the manager log, as [Verifying Connectivity](../../ref/modules/indexer_connector/configuration.md#verifying-connectivity) describes.

### 6. Remove Filebeat

Once indexing is confirmed, uninstall the package and delete what it leaves behind, `filebeat.yml` included.

**Debian-based:**

```bash
sudo apt-get remove --purge filebeat
sudo rm -rf /etc/filebeat /var/log/filebeat
```

**Red Hat-based:**

```bash
sudo rpm -e filebeat
sudo rm -rf /etc/filebeat /var/log/filebeat
```
