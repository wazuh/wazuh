# Indexer Configuration

The `<indexer>` section configures the connection from the manager to the Wazuh Indexer (OpenSearch). It is consumed by the Indexer Connector module and by the Vulnerability Scanner for feed downloads.

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parser: `src/shared/src/engine_external.c` (`get_indexer_cnf`) — converts the XML section to JSON before passing it to the engine. Only paths listed in `VALID_CONFIG_PATHS` are accepted; any unknown path causes a configuration error and the manager will not start.

For the full Indexer Connector module reference see [Indexer Connector](../modules/indexer_connector/README.md).

## Required Fields

Both `<hosts>` and `<ssl>` are required. The parser returns an error if either is absent or empty.

## Configuration Options

### hosts / host

List of Indexer node URLs. Each node is specified with a `<host>` child element. The connector load-balances across all listed hosts and fails over if a node is unavailable.

- **Required**: yes
- **Allowed values**: URL in the form `http://<address>:<port>` or `https://<address>:<port>`. Both schemes are accepted; use `https://` for TLS-protected deployments.

The host value is validated: it must start with `http://` or `https://` and include a port number.

```xml
<hosts>
  <host>https://127.0.0.1:9200</host>
</hosts>
```

### ssl / certificate_authorities / ca

Path to one or more CA certificates used to verify the Indexer's TLS certificate. Each CA is listed with a `<ca>` child element. The path must exist on disk at startup time.

- **Required**: no (the parser accepts an `<ssl>` block without `<certificate_authorities>`; omitting it disables server certificate verification, which is not recommended for production)
- **Allowed values**: Path to a PEM-encoded CA certificate (existence checked at startup; relative or absolute)

```xml
<ssl>
  <certificate_authorities>
    <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
  </certificate_authorities>
</ssl>
```

### ssl / certificate

Path to the manager's client TLS certificate for mutual authentication with the Indexer. The path must exist on disk at startup time.

- **Default value**: none
- **Allowed values**: Path to a PEM-encoded certificate (existence checked at startup; relative or absolute)

### ssl / key

Path to the private key corresponding to `ssl/certificate`. The path must exist on disk at startup time.

- **Default value**: none
- **Allowed values**: Path to a PEM-encoded private key (existence checked at startup; relative or absolute)

## Configuration Example

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

### Multi-node cluster

```xml
<indexer>
  <hosts>
    <host>https://10.0.0.1:9200</host>
    <host>https://10.0.0.2:9200</host>
    <host>https://10.0.0.3:9200</host>
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

## Indexer credentials

If the Wazuh Indexer requires username/password authentication (e.g. the built-in `admin` user), store the credentials in the Wazuh Keystore rather than embedding them in the configuration file:

```bash
wazuh-manager-keystore -f indexer -k username -v admin
wazuh-manager-keystore -f indexer -k password -v <password>
```

The Indexer Connector reads these values automatically at startup from the `indexer` column family in the keystore. For full keystore usage see [Keystore](../modules/keystore/README.md).

## Verifying connectivity

```bash
curl --cacert /var/wazuh-manager/etc/certs/root-ca.pem \
     --cert   /var/wazuh-manager/etc/certs/manager.pem \
     --key    /var/wazuh-manager/etc/certs/manager-key.pem \
     https://127.0.0.1:9200/_cluster/health
```

Expected response includes `"status": "green"`.
