# Indexer Connector Configuration Reference

Configuration reference for the connection between the Wazuh manager and the Wazuh Indexer. The
`indexer` section is read by every manager component that talks to the Indexer: the Indexer Connector
library (Vulnerability Scanner, Inventory Sync Server, engine) and the Python framework.

For module overview and architecture, see [Indexer Connector Module](README.md).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<indexer>`

The section is **required**, and so is `<hosts>` with at least one `<host>`: without them the
configuration is rejected and the manager does not start. `<ssl>` is optional; omitted, it takes the
defaults below (no CA, no client certificate).

The installer writes this section:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>etc/certs/indexer-connector.pem</certificate>
    <key>etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### hosts

List of Indexer node URLs, one per `<host>` child element.

- **Default value:** None (required)
- **Allowed values:** URLs starting with `http://` or `https://` (e.g. `https://10.0.0.1:9200`); at
  least one, no duplicates
- **Note:** The connector load-balances requests round-robin across the hosts its health monitor
  sees as available, and skips the ones that are not.

### ssl

TLS material of the connection. Relative paths are resolved from the manager home
(`/var/wazuh-manager`).

The configuration check run before every start does **not** verify these files. A missing CA file
makes the component that loads the connector fail when it starts; a client certificate or key that
does not exist or cannot be read is only noticed when the connector opens a connection with it.

#### certificate_authorities

CA certificates used to verify the Indexer's certificate, one per `<ca>` child element.

- **Default value:** empty list
- **Allowed values:** paths to PEM-encoded CA certificates
- **Note:** With a single CA, the file must exist when the connector starts (`The CA root
  certificate file: '<path>' does not exist.`). With several, the connector concatenates them into
  `/var/wazuh-manager/tmp/root-ca-merged.pem`.

#### certificate

Client certificate the manager presents to the Indexer.

- **Default value:** empty (no client certificate)
- **Allowed values:** path to a PEM-encoded certificate

#### key

Private key of `certificate`.

- **Default value:** empty
- **Allowed values:** path to a PEM-encoded private key

---

## Indexer Credentials

The connector always authenticates with HTTP basic authentication. The user and password are not
part of `wazuh-manager.conf`: they are read from the `indexer` column family of the
[keystore](../keystore/README.md), keys `username` and `password`.

The credential resolver fills them in at installation and before every start: `username` defaults to
`wazuh-manager` when it is not set, and `password` is taken from `WAZUH_INDEXER_MANAGER_PASSWORD` in
`/etc/wazuh/credentials.env`. There is no default password: when the keystore holds no password and
the variable is not supplied, the start is refused with `MISSING WAZUH_INDEXER_MANAGER_PASSWORD`. See
[Credentials](../../getting-started/credentials.md).

To change them by hand (as root):

```bash
printf '%s' 'wazuh-manager' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username
printf '%s' '<password>' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password
```

Each process reads the credentials once, so restart the manager after changing them.

---

## Internal Options

The `indexer` section has no internal options of its own. The connectors' buffering, flushing and
retry settings belong to each consumer:

- engine: `analysisd.indexer_*` — see [Indexer Connector Settings](../engine/configuration.md#indexer-connector-settings)
- Vulnerability Scanner: `wazuh_modules.indexer_*` — see [Internal Options](../vulnerability-scanner/configuration.md#internal-options)
- Inventory Sync Server: `wazuh_modules.inventory_sync_server_indexer_*` — see its [configuration reference](../inventory-sync-server/configuration.md)

All of them are set in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`.

---

## Manager Configuration Examples

### Multi-Node Cluster

```xml
<indexer>
  <hosts>
    <host>https://10.0.0.1:9200</host>
    <host>https://10.0.0.2:9200</host>
    <host>https://10.0.0.3:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>etc/certs/indexer-connector.pem</certificate>
    <key>etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### Multiple CA Certificates

If the Indexer nodes' certificates come from different CAs:

```xml
<indexer>
  <hosts>
    <host>https://indexer1.example.com:9200</host>
    <host>https://indexer2.example.com:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/wazuh-manager/etc/certs/root-ca-1.pem</ca>
      <ca>/var/wazuh-manager/etc/certs/root-ca-2.pem</ca>
    </certificate_authorities>
    <certificate>etc/certs/indexer-connector.pem</certificate>
    <key>etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### Plain HTTP (development only)

**WARNING:** Not for production: credentials and data travel unencrypted.

```xml
<indexer>
  <hosts>
    <host>http://127.0.0.1:9200</host>
  </hosts>
</indexer>
```

---

## Verifying Connectivity

Validate the configuration:

```bash
/var/wazuh-manager/bin/wazuh-manager-conf validate
```

Check that the Indexer accepts the manager's certificate and credentials, using the same files and
account the connector uses:

```bash
curl --cacert /var/wazuh-manager/etc/certs/root-ca.pem \
     --cert   /var/wazuh-manager/etc/certs/indexer-connector.pem \
     --key    /var/wazuh-manager/etc/certs/indexer-connector-key.pem \
     -u "wazuh-manager:$(/var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -g)" \
     https://127.0.0.1:9200/_cluster/health
```

The connector treats a node as available when its health is `green` or `yellow`.

Then check the manager log for the connector's verdict on each node:

```bash
grep -E "Indexer node|Health check failed|indexer credentials" /var/wazuh-manager/logs/wazuh-manager.log
```

| Message | Meaning |
|---|---|
| `Health check failed for '<host>' - Unauthorized - Check indexer credentials` | The Indexer answered `401`: wrong user or password in the keystore (logged only at debug level 2) |
| `Health check failed for '<host>' - Forbidden - Check user permissions` | The Indexer answered `403` (logged only at debug level 2) |
| `Indexer node '<host>' is no longer available. Reason: <reason>` | The node stopped answering `green`/`yellow` |
| `Indexer node '<host>' is available again.` | The node recovered |
| `No indexer credentials found in the keystore. ...` | The keystore has no `username` or `password` |

---

## Certificates

The installation issues the client certificate and key from the manager's CA, once (see
[Credentials](../../getting-started/credentials.md)). Installed ownership and modes:

| File | Owner:group | Mode |
|---|---|---|
| `/var/wazuh-manager/etc/certs/root-ca.pem` | root:wazuh-manager | 0640 |
| `/var/wazuh-manager/etc/certs/indexer-connector.pem` | root:wazuh-manager | 0640 |
| `/var/wazuh-manager/etc/certs/indexer-connector-key.pem` | root:wazuh-manager | 0640 |

The daemons read them as `wazuh-manager`, so a replacement file must stay readable by that group.

`root-ca.pem` is not the connector's alone: it is also the default
[`remote.https.ca_certificate`](../remoted/configuration.md#httpsca_certificate), the CA bundle
remoted serves to agents on `GET /cacerts`. Replacing it changes the agent listener's trust anchor
too (see the [CA rotation runbook](../remoted/ca-rotation.md)). To trust an Indexer signed by a
different CA, put that CA in its own file and list it under
[`certificate_authorities`](#certificate_authorities) instead.

---

## See Also

- [Indexer Connector Module](README.md) - Module overview and architecture
- [Keystore](../keystore/README.md) - Where the Indexer credentials are stored
- [Vulnerability Scanner Configuration](../vulnerability-scanner/configuration.md) - Uses the Indexer connection for feeds and results
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
