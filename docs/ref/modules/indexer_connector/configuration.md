# Indexer Connector Configuration Reference

Configuration reference for the connection between the Wazuh manager and the Wazuh Indexer. The
`indexer` section is read by every manager component that talks to the Indexer: the Indexer Connector
library (Vulnerability Scanner, Inventory Sync Server, engine) and the Python framework.

For module overview and architecture, see [Indexer Connector Module](README.md).

---

## Manager Configuration

**Configuration file:** `/etc/wazuh-manager/wazuh-manager.conf`

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
      <ca>/etc/wazuh-manager/certs/indexer-ca.pem</ca>
    </certificate_authorities>
    <certificate>/etc/wazuh-manager/certs/indexer-connector.pem</certificate>
    <key>/etc/wazuh-manager/certs/indexer-connector-key.pem</key>
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

TLS material of the connection. The schema's defaults are empty (no CA file, no client
certificate); the installer writes the `/etc/wazuh-manager/certs/` names shown above.

**Every file must sit directly in `/etc/wazuh-manager/certs`.** The schema accepts any path (a
relative one resolves against the manager home, `/var/wazuh-manager`), but the
[credential resolver](../../getting-started/credentials.md#configured-file-names) checks these files
before every start and refuses any other location, a relative path included:
`INVALID indexer.ssl.certificate: /var/wazuh-manager/client.pem is outside /etc/wazuh-manager/certs, the only place the resolver checks (set in /etc/wazuh-manager/wazuh-manager.conf)`,
and `wazuh-manager-control` stops with `Invalid credentials. Exiting` (error 22 in `-j` output).
`wazuh-manager-conf validate` does not look at these files: the resolver owns them. A listed file that
is absent, and that the resolver cannot import from a co-located indexer, refuses the start with
`MISSING <path>` and `Unresolved credentials. Exiting` (error 21).

#### certificate_authorities

CA certificates used to verify the Indexer's certificate, one per `<ca>` child element.

- **Default value:** empty list
- **Allowed values:** paths of PEM files holding only CA certificates, directly in
  `/etc/wazuh-manager/certs`
- **Note:** With a single CA, the connector refuses to start when the file does not exist
  (`The CA root certificate file: '<path>' does not exist.`). With several, it concatenates them into
  `/var/wazuh-manager/tmp/root-ca-merged.pem`. Only `indexer-ca.pem` is imported from a co-located
  indexer, and only while this list names it; any other listed file is yours to stage.

#### certificate

Client certificate the manager presents to the Indexer.

- **Default value:** empty (no client certificate)
- **Allowed values:** path of a PEM-encoded certificate directly in `/etc/wazuh-manager/certs`; set
  together with `key` (one without the other is refused:
  `INVALID indexer.ssl.key: must be set together with indexer.ssl.certificate …`)

#### key

Private key of `certificate`.

- **Default value:** empty
- **Allowed values:** path of a PEM-encoded private key directly in `/etc/wazuh-manager/certs`; set
  together with `certificate`

---

## Indexer Credentials

The connector always authenticates with HTTP basic authentication. The user and password are not
part of `wazuh-manager.conf`: they are read from the `indexer` column family of the
[keystore](../keystore/README.md), keys `username` and `password`.

The credential resolver fills in what is missing at installation and before every start: `username` is
set to `wazuh-manager` when it is not set, and, while the keystore holds no password, `password` is taken from
`WAZUH_INDEXER_MANAGER_PASSWORD` (see [Credentials](../../getting-started/credentials.md#the-keys) for where it
is looked up). There is no default password: when the keystore holds none and no source supplies one, the start
is refused with `MISSING WAZUH_INDEXER_MANAGER_PASSWORD`. A password already in the keystore is never replaced
from those sources, so changing `local.env` afterwards changes nothing.

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

All of them are set in `/etc/wazuh-manager/wazuh-manager-internal-options.conf`.

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
      <ca>/etc/wazuh-manager/certs/indexer-ca.pem</ca>
    </certificate_authorities>
    <certificate>/etc/wazuh-manager/certs/indexer-connector.pem</certificate>
    <key>/etc/wazuh-manager/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### Multiple CA Certificates

If the Indexer nodes' certificates come from different CAs, either put them all in `indexer-ca.pem`
or list several files. Files other than `indexer-ca.pem` are never imported: stage them in
`/etc/wazuh-manager/certs` (`root:wazuh-manager 0640`) before the start. The client pair may chain to
any of the listed CAs.

```xml
<indexer>
  <hosts>
    <host>https://indexer1.example.com:9200</host>
    <host>https://indexer2.example.com:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/wazuh-manager/certs/indexer-ca.pem</ca>
      <ca>/etc/wazuh-manager/certs/indexer-ca-2.pem</ca>
    </certificate_authorities>
    <certificate>/etc/wazuh-manager/certs/indexer-connector.pem</certificate>
    <key>/etc/wazuh-manager/certs/indexer-connector-key.pem</key>
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

Without `<ssl>` no CA file or client pair is required or imported, but the indexer password is still
required in the keystore.

---

## Verifying Connectivity

Validate the configuration, then the TLS files and their modes (as root):

```bash
/var/wazuh-manager/bin/wazuh-manager-conf validate
/var/wazuh-manager/bin/wazuh-manager-resolve-credentials --check
```

Check that the Indexer accepts the manager's certificate and credentials, using the same files and
account the connector uses:

```bash
curl --cacert /etc/wazuh-manager/certs/indexer-ca.pem \
     --cert   /etc/wazuh-manager/certs/indexer-connector.pem \
     --key    /etc/wazuh-manager/certs/indexer-connector-key.pem \
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
| `Indexer node '<host>' is no longer available. Reason: <reason>` | The node stopped answering `green`/`yellow`; `<reason>` carries the cause above (for example `Unauthorized - Check indexer credentials`) |
| `Indexer node '<host>' is available again.` | The node recovered |
| `Indexer node '<host>' is throttling requests (<reason>); it stays in rotation and requests back off.` | The node answered `429` (for example a tripped circuit breaker) |
| `No indexer credentials found in the keystore. ...` | The keystore has no `username` or `password` |

---

## Certificates

The connector trusts the indexer's CA and presents a client pair the indexer issued for this manager. Neither
comes from the manager's own CA:

| File | Owner:group | Mode |
|---|---|---|
| `/etc/wazuh-manager/certs/indexer-ca.pem` | root:wazuh-manager | 0640 |
| `/etc/wazuh-manager/certs/indexer-connector.pem` | root:wazuh-manager | 0640 |
| `/etc/wazuh-manager/certs/indexer-connector-key.pem` | root:wazuh-manager | 0640 |

When the indexer runs on the same host, the credential resolver imports them from `/etc/wazuh-indexer/export/`;
otherwise stage them yourself under these names. The owner and mode above are checked exactly before every start:
a replacement file with any other is refused as `UNSAFE` (`Unsafe credentials. Exiting`). How imports, staged
files, validity checks and rotation work is described once, in
[Indexer trust](../../getting-started/credentials.md#indexer-trust).

`/etc/wazuh-manager/certs/root-ca.pem` is not the connector's: it is the manager's own CA bundle, the default
[`remote.https.ca_certificate`](../remoted/configuration.md#httpsca_certificate) that remoted serves to agents on
`GET /cacerts`.

---

## See Also

- [Indexer Connector Module](README.md) - Module overview and architecture
- [Keystore](../keystore/README.md) - Where the Indexer credentials are stored
- [Vulnerability Scanner Configuration](../vulnerability-scanner/configuration.md) - Uses the Indexer connection for feeds and results
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
