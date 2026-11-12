# Indexer Client Configuration Reference

Configuration reference for the connection between the Wazuh manager and the Wazuh Indexer. Three things configure it:

- the `<indexer>` section of `wazuh-manager.conf`: hosts and TLS files;
- the `indexer` entries of the [keystore](../keystore/README.md): the account;
- the internal options: the runtime's own (`wazuh_modules.indexer_client_*`, below) and each consumer's.

The `<indexer>` section and the credentials are read by every manager component that talks to the Indexer: the Indexer Client (modulesd), the engine and the Python framework.

For the module overview, see [Indexer Client](README.md).

---

## Manager Configuration

**Configuration file:** `/etc/wazuh-manager/wazuh-manager.conf`

**XML Section:** `<indexer>`

The section is **required**, and so is `<hosts>` with at least one `<host>`: without them the configuration is rejected and the manager does not start. `<ssl>` is optional. An `https` host without a `<ca>` is verified against the first existing system CA store, or not verified (with a warning) when none of the 5 system paths exists (see [verify_certificates](#verify_certificates)).

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
- **Allowed values:** URLs starting with `http://` or `https://` that name a host (a host name, an IPv4 address, or an IPv6 address in brackets), then an optional `:port` and path (e.g. `https://10.0.0.1:9200`, `https://[fd00::1]:9200`); at least one, no duplicates. `https://` alone is refused
- **Note:** The runtime probes every host and load-balances requests round-robin across the ones that are available, skipping the ones that are down (see [Node health](README.md#node-health)). An unreachable host does not stop the manager from starting.

### ssl

TLS material and verification policy of the connection. The runtime resolves a relative path from the manager home (`/var/wazuh-manager`), but the credential resolver only accepts files directly inside `/etc/wazuh-manager/certs` and reports anything else (a relative path included) as `INVALID`: use absolute paths in that directory.

The configuration check run before every start (`wazuh-manager-conf validate`, and `wazuh-manager-modulesd -t`) does **not** open these files. They are read when modulesd starts the runtime, and any problem stops the runtime from starting, with the reason in the log (see [Troubleshooting](README.md#troubleshooting)). The files are read once: replacing a CA, certificate or key takes a restart.

#### certificate_authorities

CA certificates used to verify the Indexer's certificate, one per `<ca>` child element.

- **Default value:** empty list
- **Allowed values:** paths to PEM-encoded CA files, each at most 1 MiB and holding at least one certificate
- **Note:** Optional. Without any `<ca>` the system CA store is used (see [verify_certificates](#verify_certificates)). Every configured file must exist and be well-formed PEM, also when `verify_certificates` is `no`. With several CAs, all of them are trusted; the files are concatenated in memory, no merged file is written. A configured CA always wins over the system store. The minimum protocol is TLS 1.2.

#### verify_certificates

Whether the runtime verifies the Indexer's certificate and host name. Same behaviour as the Wazuh 5.0 connector, so an update keeps connecting.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** In the XML the values are `yes` and `no`; in the JSON schema and the effective configuration it is the boolean `ssl.verify_certificates`. What the runtime does, for an `https` host:

| `verify_certificates` | `<ca>` configured | Trust anchor | Peer / host name checked | Log at start |
|---|---|---|---|---|
| `yes` | yes | the configured CAs | yes / yes | none |
| `yes` | no, a system store exists | the first **existing** of `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/usr/share/ssl/certs/ca-bundle.crt`, `/usr/local/share/certs/ca-root-nss.crt`, `/etc/ssl/cert.pem` | yes / yes | INFO `indexer TLS: using the system CA store <path>` |
| `yes` | no, none of the five exists | none (curl's built-in bundle is never used) | no / yes | WARN `indexer TLS: no CA configured and no system CA store found (<paths>); the server certificate is not verified (the host name is) for https host(s) <hosts>; the indexer credentials are sent to an unverified server` |
| `no` | either | the configured CA, if any | no / no | WARN `indexer TLS: certificate and host name verification disabled (verify_certificates is false) for https host(s) <hosts>; the indexer credentials are sent to an unverified server` |

- The first existing path of the list is the one used, whatever it holds: a broken store (unreadable, not PEM) makes every handshake fail, it does not switch verification off and the next path is not tried.
- A malformed `<ca>` or client pair is an error whatever the value: with `no` they are still loaded and validated.
- The INFO and the WARN are logged once per start, and only when some host is `https`. Plain `http` hosts are not affected.
- The Python framework (`wazuh.core.indexer`) reads the same option. With `no` it does not verify the server certificate and, unlike modulesd and the engine, it cannot check the host name either (Python cannot check the host name without verifying the peer); it logs `indexer TLS: certificate verification disabled (verify_certificates is false); the host name is not checked either; the indexer credentials are sent to an unverified server`. With `yes` and no CA it uses the same first existing system path, else OpenSSL's default trust; with no trust at all it keeps verifying, so its connections fail (fail-closed, as before this option existed) and it logs `indexer TLS: no CA configured, no system CA store found and no default trust available; ...`.

#### certificate

Client certificate the manager presents to the Indexer.

- **Default value:** empty (no client certificate)
- **Allowed values:** path to a PEM-encoded certificate: the leaf, optionally followed by its intermediate CAs, sent whole
- **Note:** `certificate` and `key` come together or not at all.

#### key

Private key of `certificate`.

- **Default value:** empty
- **Allowed values:** path to a PEM-encoded private key, **not encrypted**, matching the first certificate of `certificate`

---

## Indexer Credentials

The runtime always authenticates with HTTP basic authentication, also over plain `http`. The user and password are not part of `wazuh-manager.conf`: they are read from the `indexer` column family of the [keystore](../keystore/README.md), keys `username` and `password`.

The credential resolver fills them in at installation and before every start: `username` defaults to `wazuh-manager` when it is not set, and `password` is taken from `WAZUH_INDEXER_MANAGER_PASSWORD` in the environment, in `/etc/wazuh-manager/local.env`, or in the indexer's `/etc/wazuh-indexer/export/credentials.env` when the indexer runs on the same host. There is no default password: when the keystore holds no password and none of them supplies one, the start is refused with `MISSING WAZUH_INDEXER_MANAGER_PASSWORD`. See [Credentials](../../getting-started/credentials.md).

A password already in the keystore is never replaced from the environment or `local.env`, so changing `local.env` afterwards changes nothing. It is replaced only when it comes from a co-located indexer's `/etc/wazuh-indexer/export/credentials.env` and differs from the stored one (the indexer was reinstalled, or published a new password): every start, installation and upgrade then writes the new one to the keystore. See [Credentials](../../getting-started/credentials.md).

To change them by hand (as root):

```bash
printf '%s' 'wazuh-manager' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username
printf '%s' '<password>' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password
```

modulesd reads the credentials once, when it starts the runtime (an empty user or password stops the runtime: `indexer credentials missing: user` or `password`), and the engine once when it starts. Restart the manager after changing them. The Python framework (API, cluster) reads them again for every Indexer client it builds and needs no restart. The password never appears in a log line or a metric.

---

## Internal Options

Internal options are set in `/etc/wazuh-manager/wazuh-manager-internal-options.conf`, one `key=value` per line. The shipped file carries none of the options below: the defaults are compiled in, and a line is only needed to override one.

### The `wazuh_modules.indexer_client_*` family

**Internal Options prefix:** `wazuh_modules.indexer_client_*`

These are the options of the runtime that `wazuh-manager-modulesd` owns and every consumer shares ([Inventory Sync Server](../inventory-sync-server/README.md), [Vulnerability Scanner](../vulnerability-scanner/README.md)).

- Every value is an unsigned decimal integer; a leading zero does not mean octal.
- **When a consumer exists, the family is validated in full** by `wazuh-manager-modulesd -t` and again at startup, before any module thread exists, and a failure is logged with the offending key: a value outside its range, a value that is not an unsigned decimal integer, an empty value, **or a key under the prefix that is not listed here (a typo is an error, not an ignored line)**. In every case modulesd refuses to start. A key that is not under the `wazuh_modules.indexer_client_` prefix is not read by the runtime.
- The runtime starts only when a consumer exists (the Inventory Sync Server is configured, or the Vulnerability Scanner is enabled); with none, the options are **not** validated (a typo in a `wazuh_modules.indexer_client_*` key passes `modulesd -t`) and no threads or probes are created.
- The table is the operator's copy of the schema, `kSchema` in `src/shared_modules/indexer_client/src/config/runtimeConfig.cpp`; the library README owns the semantics. Every minimum is 1 except `log_summary_interval_ms`, whose minimum is 1000; bounds are inclusive.

| Name (after the prefix) | Unit | Allowed values | Default |
|---|---|---|---|
| `network_threads` | count | 1 to 64 | 1 |
| `cpu_threads` | count | 1 to 64 | 2 |
| `global_quota_bytes` | bytes | 1 to 68719476736 (64 GiB) | 268435456 (256 MiB) |
| `max_response_bytes` | bytes | 1 to 1073741824 (1 GiB) | 67108864 (64 MiB) |
| `drr_quantum_bytes` | bytes | 1 to 67108864 (64 MiB) | 1048576 (1 MiB) |
| `request_timeout_ms` | ms | 1 to 3600000 (1 h) | 60000 |
| `probe_timeout_ms` | ms | 1 to 300000 (5 min) | 5000 |
| `probe_interval_ms` | ms | 1 to 3600000 (1 h) | 10000 |
| `drain_ms` | ms | 1 to 600000 (10 min) | 10000 |
| `ambiguous_retry_window_ms` | ms | 1 to 3600000 (1 h) | 30000 |
| `latency_target_ms` | ms | 1 to 600000 (10 min) | 2000 |
| `pace_initial_ms` | ms | 1 to 60000 (1 min) | 100 |
| `pace_relax_after` | count | 1 to 1000000 | 20 |
| `retry_after_max_ms` | ms | 1 to 3600000 (1 h) | 60000 |
| `callback_budget_ms` | ms | 1 to 60000 (1 min) | 200 |
| `max_open_pits` | count | 1 to 10000 | 64 |
| `log_summary_interval_ms` | ms | 1000 to 3600000 (1 h) | 60000 |
| `node_window_max` | count | 1 to 64 | 4 |
| `bulk_min_bytes` | bytes | 1 to 33554432 (32 MiB) | 65536 (64 KiB) |

The ones an operator reaches for:

- `request_timeout_ms` - the per-request timeout of every bucket. The Inventory Sync Server's [post-deletion sweep](../inventory-sync-server/architecture.md#the-post-deletion-sweep) window is derived from it (`request_timeout_ms + 5 s`).
- `global_quota_bytes` - the ceiling every bucket's quota is carved from. It bounds the **queued writes** only, not the process: the answers to reads are not charged to it (see [Memory used by reads](#memory-used-by-reads)).
- `probe_interval_ms`, `probe_timeout_ms` - the host health probe.
- `max_response_bytes` - the largest response body the client reads. A query answer is held to an eighth of it (8 MiB by default), because parsing builds a structure several times the body's size; the content pages of the content manager (the vulnerability feed, the Engine's ruleset and IoCs) use the whole value, since single CTI documents exceed 8 MiB, and a page over it is requested again with fewer documents. Raising it raises the memory a feed download may take. A `_bulk` answer over it may have been applied: a bucket with `onAmbiguous5xx = Retry` (the three above) splits the batch and resends the halves; one with `Fail` (the engine's `events` and `raw`) fails every operation `ambiguous` without resending it.
- `ambiguous_retry_window_ms` - the longest an `agent-state` bucket stays pinned to one indexer node after an ambiguous `5xx` (see [Effects to know](../inventory-sync-server/architecture.md#effects-to-know)).
- `drain_ms` - the shutdown budget used when no deadline was fixed first. On a normal stop modulesd fixes one (see [Start and stop](README.md#start-and-stop)); `drain_ms` applies to a `Client` destroyed, or a runtime stopped, without it.
- `network_threads`, `cpu_threads` - the runtime's threads, shared by every consumer.
- `log_summary_interval_ms` - how often each active bucket logs its summary line.

### Memory used by reads

`global_quota_bytes` counts the operations the buckets hold until the indexer confirms them. The answers to reads (searches, counts, point-in-time pages) are not charged to it, and the runtime does not limit how many reads run at once. Each answer is bounded on its own:

| Read | Largest body read | In memory while it is parsed |
|---|---|---|
| An ordinary query (the consumers' searches and counts) | `max_response_bytes` / 8: 8 MiB by default | the body and its parsed form; the library bounds the parsed form at 8 times the body, so up to about 64 MiB per answer |
| A content page (the vulnerability feed, the Engine's ruleset and IoCs) | `max_response_bytes`: 64 MiB by default | the body and its parsed form, estimated at about 6 times the body on CTI content, so roughly 400 MiB per page |

The Vulnerability Scanner downloads a full feed with 2 point-in-time slices in parallel by default, so two content pages can be in memory at the same time, next to the scanner's own queries and the writes held under `global_quota_bytes`. In modulesd, with the default values, a full feed download while scans read and the buckets are full can therefore reach about 1 GiB. That figure is an estimate built from the bounds above: the 8 times factor is the bound the library assumes, the 6 times factor and the total have not been measured. The Engine runs its own runtime, with its own `global_quota_bytes` and its own content pages, in its own process; this matters most for the engine embedded in the Wazuh Indexer, which shares the host with it.

`indexer_client.query.response_bytes_in_flight` gives the body bytes of the answers being processed and `indexer_client.query.peak_response_bytes_in_flight` its highest value since start (see [Metrics](metrics.md)); they count the bodies, not their parsed form. Lowering `max_response_bytes` lowers both bounds, at the cost of smaller content pages (a page over the limit is requested again with fewer documents; one CTI document over it cannot be downloaded).

### The consumers' options

Each consumer sizes its own buckets from its own internal options; they do not live in the family above and are not interchangeable:

| Consumer | Options | Reference |
|---|---|---|
| Inventory Sync Server | `wazuh_modules.inventory_sync_server_indexer_sync_*` (bucket `inventory`), `wazuh_modules.inventory_sync_server_indexer_async_*` (bucket `agent-state`) | [Inventory Sync Server configuration](../inventory-sync-server/configuration.md#indexer-client-buckets-indexer_sync_-and-indexer_async_) |
| Vulnerability Scanner | `wazuh_modules.indexer_bulk_size_bytes`, `wazuh_modules.indexer_max_retry_attempts`, `wazuh_modules.indexer_max_retry_duration_seconds` (`wazuh_modules.indexer_flush_interval` is ignored) | [Vulnerability Scanner configuration](../vulnerability-scanner/configuration.md#indexer_bulk_size_bytes) |
| Engine | `analysisd.indexer_*` | [Engine configuration](../engine/configuration.md) |

Options of the previous library that no longer act (a flush interval, a request timeout per bucket, a shared session) are accepted so that existing files do not abort the daemon; a value other than the default logs a warning once, and the consumers' pages mark them **Ignored**.

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

If the Indexer nodes' certificates come from different CAs:

```xml
<indexer>
  <hosts>
    <host>https://indexer1.example.com:9200</host>
    <host>https://indexer2.example.com:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/wazuh-manager/certs/root-ca-1.pem</ca>
      <ca>/etc/wazuh-manager/certs/root-ca-2.pem</ca>
    </certificate_authorities>
    <certificate>/etc/wazuh-manager/certs/indexer-connector.pem</certificate>
    <key>/etc/wazuh-manager/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

### System CA store (no CA configured)

The indexer's certificate comes from a public or corporate CA that the operating system already trusts:

```xml
<indexer>
  <hosts>
    <host>https://indexer.example.com:9200</host>
  </hosts>
</indexer>
```

### Verification disabled (testing only)

```xml
<indexer>
  <hosts>
    <host>https://10.0.0.1:9200</host>
  </hosts>
  <ssl>
    <verify_certificates>no</verify_certificates>
  </ssl>
</indexer>
```

Certificate and host name are not checked and a WARN is logged at every start. Do not use it in production: the indexer credentials travel to whoever answers.

### Plain HTTP (development only)

**WARNING:** Not for production: credentials and data travel unencrypted.

```xml
<indexer>
  <hosts>
    <host>http://INDEXER_HOST:9200</host>
  </hosts>
</indexer>
```

`INDEXER_HOST` is a placeholder for the indexer's address. Without `<ssl>` no CA file or client pair is required or imported, but the indexer password is still required in the keystore.

### Giving the runtime more memory and threads on a busy manager

```ini
wazuh_modules.indexer_client_global_quota_bytes=536870912
wazuh_modules.indexer_client_network_threads=2
```

Raise the quota only after checking that a bucket really is full (`rejected.queue_full`, `retained_bytes` against `quota_bytes` in [Metrics](metrics.md)): a larger quota holds more data in memory when the indexer is slow, it does not make the indexer faster. A bucket's own quota is capped by what the global one leaves it.

---

## Verifying Connectivity

Validate the configuration:

```bash
/var/wazuh-manager/bin/wazuh-manager-conf validate
/var/wazuh-manager/bin/wazuh-manager-modulesd -t
```

Check that the Indexer accepts the manager's certificate and credentials, using the same files and account the runtime uses. The command sends the indexer password, so send it only to a host this manager is configured for: the example assumes a co-located indexer (`127.0.0.1`); otherwise replace the address with one from the output of `/var/wazuh-manager/bin/wazuh-manager-conf get indexer.hosts` rather than typing it.

```bash
curl --cacert /etc/wazuh-manager/certs/indexer-ca.pem \
     --cert   /etc/wazuh-manager/certs/indexer-connector.pem \
     --key    /etc/wazuh-manager/certs/indexer-connector-key.pem \
     -u "wazuh-manager:$(/var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -g)" \
     'https://127.0.0.1:9200/_cluster/health/wazuh-*,.wazuh-*'
```

The runtime treats a node as available when its health is `green` or `yellow`, and probes exactly this URL.

Then check the manager log for the runtime's verdict on each node:

```bash
grep "indexer-client" /var/wazuh-manager/logs/wazuh-manager.log
```

| Message | Meaning |
|---|---|
| `Indexer client runtime started.` | The options, files and credentials were accepted |
| `Indexer node '<host>' is available.` | The first probe of that node succeeded |
| `Indexer node '<host>' is no longer available. Reason: HTTP 401: check indexer credentials / permissions` | The Indexer answered `401` or `403`: wrong user or password in the keystore, or missing permissions |
| `Indexer node '<host>' is no longer available. Reason: <reason>` | The node stopped answering `green`/`yellow`, or could not be reached |
| `The indexer client runtime did not start: <cause>: <reason>. ...` | The runtime refused to start; the reason names the file, host or credential |
| `Invalid indexer client configuration: <reason>` | An option under `wazuh_modules.indexer_client_` or the `<indexer>` section is invalid |

---

## Certificates

The runtime trusts the indexer's CA and presents a client pair the indexer issued for this manager. Neither comes from the manager's own CA:

| File | Owner:group | Mode |
|---|---|---|
| `/etc/wazuh-manager/certs/indexer-ca.pem` | root:wazuh-manager | 0640 |
| `/etc/wazuh-manager/certs/indexer-connector.pem` | root:wazuh-manager | 0640 |
| `/etc/wazuh-manager/certs/indexer-connector-key.pem` | root:wazuh-manager | 0640 |

The name of the pair, `indexer-connector*.pem`, is historical: it is the name the credential resolver, the installer's configuration template and [Credentials](../../getting-started/credentials.md) agree on. It was kept when the Indexer Connector was replaced, and it is not an indication of which library reads it.

When the indexer runs on the same host, the credential resolver imports them from `/etc/wazuh-indexer/export/` (`ca.pem`, `manager-client.pem`, `manager-client-key.pem`), records the import with a marker file, and imports them again when the indexer's files change. Otherwise stage them yourself under these names: files without a marker are validated at every start and never replaced. The client certificate must chain to a certificate of `indexer-ca.pem` (an intermediate CA that issued it goes in `indexer-connector.pem`, after the leaf), match its key, be inside its validity window and carry an `extendedKeyUsage` with `clientAuth`. See [Indexer trust](../../getting-started/credentials.md#indexer-trust).

The daemons read them as `wazuh-manager`, so a replacement file must stay readable by that group. modulesd reads them when it starts the runtime: restart the manager after replacing any of them.

`/etc/wazuh-manager/certs/root-ca.pem` is not the runtime's: it is the manager's own CA bundle, the default [`remote.https.ca_certificate`](../remoted/configuration.md#httpsca_certificate) that remoted serves to agents on `GET /cacerts`. To trust more than one indexer CA, put them all in `indexer-ca.pem`. Other files listed under [`certificate_authorities`](#certificate_authorities) widen what the runtime trusts, but the credential resolver still requires `indexer-ca.pem` and checks the client pair against it.

---

## See Also

- [Indexer Client](README.md) - Module overview, buckets, node health, logs and troubleshooting
- [Metrics](metrics.md) - The `indexer_client.*` metrics
- [Keystore](../keystore/README.md) - Where the Indexer credentials are stored
- [Inventory Sync Server Configuration](../inventory-sync-server/configuration.md) and [Vulnerability Scanner Configuration](../vulnerability-scanner/configuration.md) - The consumers' options
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
