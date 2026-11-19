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
| `output.elasticsearch.ssl.certificate` | `<indexer><ssl><certificate>`, only for an indexer that requires client certificates | `wazuh-manager.conf` |
| `output.elasticsearch.ssl.key` | `<indexer><ssl><key>`, with `certificate` | `wazuh-manager.conf` |

Every other `filebeat.yml` setting is gone:

- **Output tuning** (`bulk_max_size`, `worker`, `timeout`, `compression_level`) and **queue/buffering** (`queue.mem.*`): the engine's connector is tuned with the `analysisd.indexer_*` internal options (bulk size in bytes, flush interval, queue size, request timeout, retry delay). See [Indexer Connector Settings](../../ref/modules/engine/configuration.md#indexer-connector-settings).
- **TLS options** (`ssl.verification_mode`, `ssl.supported_protocols`, `ssl.cipher_suites`): the `<indexer><ssl>` section has only `certificate_authorities`, `certificate` and `key`; there is no option to turn off server-certificate verification. If you used `verification_mode: none`, you must now provide the CA that signed the indexer's certificate.
- **Processors** (`add_host_metadata`, `add_fields`, `drop_fields`, etc.): not supported. If you relied on them to enrich events, move that logic to the Engine decoders/integrations.
- **Templates and ILM** (`setup.template.*`, `setup.ilm.*`): the manager does not install index templates; they are managed on the Wazuh Indexer.
- **Logging** (`logging.*`): connector messages go to the manager log, `/var/wazuh-manager/logs/wazuh-manager.log`.

## Migration steps

The 5.x installation already configures the connector: the installer writes an `<indexer>` section pointing at `https://127.0.0.1:9200` with `certs/indexer-ca.pem` and no client certificate, imports that file from a 5.x indexer on the same host, and stores in the keystore the indexer password supplied as `WAZUH_INDEXER_MANAGER_PASSWORD` in `/etc/wazuh-manager/local.env` or published by that indexer (see [Indexer trust](../../ref/getting-started/credentials.md#indexer-trust)). The steps below carry over what differs in your 4.x deployment.

### 1. Record your current Filebeat settings

From `/etc/filebeat/filebeat.yml`, note:

- Indexer host(s) and port
- Username and password
- Path to the CA file, and to the certificate and key files if the indexer requires client certificates

### 2. Deploy the certificates

The connector verifies the indexer against `/etc/wazuh-manager/certs/indexer-ca.pem` and authenticates with the
indexer password (step 3). `/etc/wazuh-manager/certs/root-ca.pem` is the manager's own CA bundle, the one agents
pin: it is not the connector's, so **do not overwrite it** with the indexer's CA.

- **The indexer runs on this host as 5.x**: nothing to do; the manager imported its CA.
- **Otherwise**, stage the indexer's CA as `indexer-ca.pem`. Run as root:

```bash
tar -xf wazuh-certificates.tar -C /tmp ./root-ca.pem
install -m 0640 -o root -g wazuh-manager /tmp/root-ca.pem /etc/wazuh-manager/certs/indexer-ca.pem
rm -f /tmp/root-ca.pem
```

The file is `root:wazuh-manager` `0640`, the ownership and mode the installation gives the connector's files, so
the daemons read it after dropping privileges. These commands run after the 5.x package is installed, which creates
the `wazuh-manager` group, and before the first start. To stage the file before installing instead, create
`/etc/wazuh-manager` (`0770`) and `certs/` (`0750`) `root:root` and install the file with `-g root`: the DEB and RPM
packages re-own every `certs/*.pem` to `root:wazuh-manager` `0640` before their credential resolver runs (see
[Using certificates issued elsewhere](../../ref/getting-started/installation.md#using-certificates-issued-elsewhere)). Staged without an import marker, it is checked before every start
and never replaced: a file that holds anything but CA certificates stops the start with an `INVALID` line naming
it, while an expired or not-yet-valid CA only logs a `WARNING` (the indexer connection fails until it is renewed).

The certificate and key Filebeat used are not needed. Only an indexer that requires client certificates needs a
client pair, named in `<certificate>` and `<key>`; it must carry `extendedKeyUsage` `clientAuth`, which a
`wazuh-certs-tool` node certificate lacks (see [Configured file names](../../ref/getting-started/credentials.md#configured-file-names)).

### 3. Store the credentials in the keystore

The installation stored the password supplied in `WAZUH_INDEXER_MANAGER_PASSWORD` and the username `wazuh-manager`. To use the account Filebeat used instead, overwrite both as root:

```bash
printf '%s' '<your_username>' | sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username
printf '%s' '<your_password>' | sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password
```

A value already in the keystore is kept on every later start, whatever `local.env` or the environment says; only a different password published by an indexer on the same host (`/etc/wazuh-indexer/export/credentials.env`) replaces it. Each daemon reads the credentials once, so restart the manager after changing them (step 5).

### 4. Configure the `<indexer>` block

Edit the `<indexer>` section of `/etc/wazuh-manager/wazuh-manager.conf` with your hosts and CA path:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/wazuh-manager/certs/indexer-ca.pem</ca>
    </certificate_authorities>
  </ssl>
</indexer>
```

Give every file as an absolute path directly inside `/etc/wazuh-manager/certs`. The schema also accepts a relative path, resolved from the installation directory, `/var/wazuh-manager`, but the start then refuses it, as it refuses any file outside that directory (see [Configured file names](../../ref/getting-started/credentials.md#configured-file-names)). For a multi-node indexer cluster, list each node as a separate `<host>`:

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

Confirm that the indexer accepts the manager's credentials, and read the connector's verdict on each node in the manager log, as [Verifying Connectivity](../../ref/modules/indexer_connector/configuration.md#verifying-connectivity) describes.

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
