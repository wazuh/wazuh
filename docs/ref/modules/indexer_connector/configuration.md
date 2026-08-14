# Indexer Connector Configuration Reference

Complete configuration reference for the Indexer Connector module.

The Indexer Connector manages the connection between the Wazuh manager and the Wazuh Indexer (OpenSearch), providing secure communication for indexing alerts, vulnerabilities, and agent inventory data.

For module overview and architecture, see [Indexer Connector Module](index.html).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<indexer>`

**Internal Options:** None

The Indexer Connector configuration establishes TLS-secured connections to one or more Indexer nodes for data indexing and feed synchronization.

**Required fields:** Both `<hosts>` and `<ssl>` are required. The parser returns an error if either is absent or empty.

### hosts

List of Indexer node URLs. Each node is specified with a `<host>` child element.

- **Default value:** None (required configuration)
- **Allowed values:** URL in the form `http://<address>:<port>` or `https://<address>:<port>`
- **Note:** At least one host must be defined. Must start with `http://` or `https://` and include a port number. The connector load-balances across all listed hosts and fails over if a node is unavailable

Example:
```xml
<hosts>
  <host>https://127.0.0.1:9200</host>
</hosts>
```

### ssl

TLS/SSL configuration block.

- **Default value:** None (required configuration block, even if empty)
- **Allowed values:** Contains sub-options: `certificate_authorities`, `certificate`, `key`
- **Note:** This block is required by the parser even if no TLS verification is configured

#### certificate_authorities

Path to one or more CA certificates used to verify the Indexer's TLS certificate. Each CA is listed with a `<ca>` child element.

- **Default value:** None
- **Allowed values:** Path to a PEM-encoded CA certificate (relative or absolute)
- **Note:** Omitting this disables server certificate verification (not recommended for production). Path must exist on disk at startup time

Example:
```xml
<ssl>
  <certificate_authorities>
    <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
  </certificate_authorities>
</ssl>
```

#### certificate

Path to the manager's client TLS certificate for mutual authentication with the Indexer.

- **Default value:** None
- **Allowed values:** Path to a PEM-encoded certificate (relative or absolute)
- **Note:** Required if Indexer requires client certificate authentication. Path must exist on disk at startup time

#### key

Path to the private key corresponding to the client certificate.

- **Default value:** None
- **Allowed values:** Path to a PEM-encoded private key (relative or absolute)
- **Note:** Required if `certificate` is specified. Path must exist on disk at startup time

---

## Indexer Credentials

If the Wazuh Indexer requires username/password authentication (e.g. the built-in `admin` user), store the credentials in the Wazuh Keystore rather than embedding them in the configuration file:

```bash
wazuh-manager-keystore -f indexer -k username -v admin
wazuh-manager-keystore -f indexer -k password -v <password>
```

The Indexer Connector reads these values automatically at startup from the `indexer` column family in the keystore.

For full keystore usage, see [Keystore Module](../keystore/index.html).

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/local_internal_options.conf`

The Indexer Connector does not have dedicated internal options. Connection and bulk indexing behavior is controlled through the XML configuration and module-specific settings.

---

## Manager Configuration Examples

### Single Node with TLS

Basic configuration with one Indexer node:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/var/wazuh-manager/etc/certs/indexer-connector.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### Multi-Node Cluster

High availability configuration with multiple Indexer nodes:

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
    <certificate>/var/wazuh-manager/etc/certs/indexer-connector.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### Multiple CA Certificates

If using certificates from different CAs:

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
    <certificate>/var/wazuh-manager/etc/certs/indexer-connector.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### Development/Testing (No TLS Verification)

**WARNING:** Not recommended for production. Only for isolated development environments.

```xml
<indexer>
  <hosts>
    <host>http://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <!-- Empty SSL block required but no verification -->
  </ssl>
</indexer>
```

---

## Verifying Connectivity

Test connectivity to the Indexer manually:

```bash
curl --cacert /var/wazuh-manager/etc/certs/root-ca.pem \
     --cert   /var/wazuh-manager/etc/certs/indexer-connector.pem \
     --key    /var/wazuh-manager/etc/certs/indexer-connector-key.pem \
     https://127.0.0.1:9200/_cluster/health
```

Expected response includes `"status": "green"` or `"yellow"`.

With authentication:

```bash
curl --cacert /var/wazuh-manager/etc/certs/root-ca.pem \
     --cert   /var/wazuh-manager/etc/certs/indexer-connector.pem \
     --key    /var/wazuh-manager/etc/certs/indexer-connector-key.pem \
     -u admin:password \
     https://127.0.0.1:9200/_cluster/health
```

---

## Certificate Management

### Generate Self-Signed Certificates

For testing purposes only:

```bash
# Generate CA
openssl req -x509 -new -nodes -newkey rsa:4096 \
  -keyout root-ca-key.pem -out root-ca.pem -days 3650

# Generate manager certificate
openssl req -new -nodes -newkey rsa:4096 \
  -keyout manager-key.pem -out manager.csr

# Sign with CA
openssl x509 -req -in manager.csr -CA root-ca.pem \
  -CAkey root-ca-key.pem -CAcreateserial \
  -out manager.pem -days 365
```

### Certificate Permissions

Ensure proper ownership and permissions:

```bash
chown root:wazuh-manager /var/wazuh-manager/etc/certs/*.pem
chmod 640 /var/wazuh-manager/etc/certs/*-key.pem
chmod 644 /var/wazuh-manager/etc/certs/*.pem
```

---

## Troubleshooting

### Connection Failures

Check connectivity:

```bash
# Test network connectivity
telnet 127.0.0.1 9200

# Test TLS handshake
openssl s_client -connect 127.0.0.1:9200 -CAfile /var/wazuh-manager/etc/certs/root-ca.pem
```

Check manager logs:

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep -i indexer
```

### Certificate Errors

Verify certificate validity:

```bash
# Check certificate dates
openssl x509 -in /var/wazuh-manager/etc/certs/indexer-connector.pem -noout -dates

# Verify certificate against CA
openssl verify -CAfile /var/wazuh-manager/etc/certs/root-ca.pem \
  /var/wazuh-manager/etc/certs/indexer-connector.pem
```

### Authentication Errors

Verify keystore credentials:

```bash
# List keystore entries
wazuh-manager-keystore -l

# Test with curl
curl -u admin:password https://127.0.0.1:9200/_cat/health
```

### Configuration Validation

Validate configuration before restarting:

```bash
/var/wazuh-manager/bin/wazuh-logtest-config
```

---

## Performance Considerations

### Connection Pooling

The Indexer Connector maintains persistent connections to configured hosts. For large deployments:

- Use multiple Indexer nodes for load distribution
- Monitor connection pool usage in logs
- Adjust Indexer thread pool settings if needed

### Load Balancing

The connector uses round-robin load balancing across configured hosts. For optimal performance:

- Use at least 3 Indexer nodes in production
- Ensure network latency is similar to all nodes
- Monitor individual node health

---

## See Also

- [Indexer Connector Module](index.html) - Module overview and architecture
- [Vulnerability Scanner Configuration](../vulnerability-scanner/configuration.md) - Uses Indexer connection for feeds
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
