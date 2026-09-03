# Configuration

The Container Images module is configured in the agent `ossec.conf` file using the `<container_images>` section. The configuration is agent-only: the block is parsed in agent builds and ignored by the server/manager.

Synchronization options are not available in this stage. State synchronization and manager-side cleanup are planned for later development stages; this stage stores the inventory locally on the agent.

The block is optional. When the block is present, all settings have defaults and the module can be disabled with `<enabled>no</enabled>`.

> **Note:** Images are read from two kinds of source. On disk through `<archive>`: saved image archives (`docker save`) and OCI image layout directories. From a remote registry through `<ref>`, which supports GitHub Container Registry (`ghcr.io`). The `<local>` entry type is accepted by the parser and reported as unimplemented.

---

## Basic Configuration

### Minimal Configuration

```xml
<container_images>
  <enabled>yes</enabled>
  <references>
    <archive>/var/tmp/images/myapp.tar</archive>
  </references>
</container_images>
```

This enables the module with default settings:

- Scan on start: enabled
- Scan interval: `1h`
- Source type: image archive or OCI image layout on disk

### Full Configuration Example

```xml
<container_images>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <references>
    <archive>/var/tmp/images/myapp.tar</archive>
    <archive>/var/tmp/images/myapp-oci-layout</archive>
  </references>
</container_images>
```

---

## Configuration Options

### Core Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `yes` | Enable or disable the module. When disabled, the module thread exits without scanning. |
| `scan_on_start` | boolean | `yes` | Run a scan when the agent starts. |
| `interval` | time | `1h` | Time between scans. |

### Reference Management

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `references` | section | empty | Container section for image sources. |
| `references/archive` | string | empty | Path to a saved image archive or to an OCI image layout directory. This element can be repeated. |
| `references/ref` | string | empty | Image in a remote GHCR registry, by tag or by digest. This element can be repeated. |
| `registry_auth` | section | empty | Container section for per-registry credentials. See [Registry Credentials](#registry-credentials). |
| `ca_bundle` | string | detected | Path to the certificate bundle used to verify a registry. Detected at run time when unset. |
| `references/local` | string | empty | Image in the local container engine store. Accepted and reported as unimplemented. |

---

## Time Interval Format

The `interval` option accepts a positive integer with an optional unit suffix:

| Format | Example | Description |
|--------|---------|-------------|
| Seconds | `3600s` or `3600` | Scan every 3600 seconds |
| Minutes | `60m` | Scan every 60 minutes |
| Hours | `1h` | Scan every hour |
| Days | `1d` | Scan once per day |

Invalid values include `0`, an empty value, or a value with an unsupported suffix.

---

## Reference Configuration

### Entry Types

The grammar holds three entry types.

| Entry | Meaning | Status |
|-------|---------|--------|
| `<archive>` | Saved image archive or OCI image layout on disk. | Implemented. |
| `<ref>` | Image in a remote registry. | Implemented for `ghcr.io`. |
| `<local>` | Image in the local container engine store. | Accepted, reported as unimplemented. |

```xml
<references>
  <archive>/var/tmp/images/myapp.tar</archive>
  <archive>/var/tmp/images/myapp-oci-layout</archive>
  <ref>ghcr.io/owner/app:1.4</ref>
  <ref>ghcr.io/owner/other@sha256:2f3a4b5c6d7e8f900112233445566778899aabbccddeeff00112233445566778</ref>
</references>
```

An unimplemented entry type is reported once per scan and costs nothing else:

```sql
wazuh-modulesd:container_images: WARNING: NOT IMPLEMENTED: the '<local>' reference 'nginx:1.27' needs container engine support, which is not available yet. Skipping it.
```

### Remote References

A `<ref>` entry names an image in GitHub Container Registry, pinned either by tag or by digest:

```xml
<ref>ghcr.io/owner/app:1.4</ref>
<ref>ghcr.io/owner/app</ref>
<ref>ghcr.io/owner/app@sha256:2f3a...</ref>
```

An entry with no tag and no digest is read as `latest`, matching every other registry client.

Only `ghcr.io` is supported. A reference naming any other registry, or naming none at all, is reported and skipped rather than fetched from somewhere it was not asked for:

```sql
wazuh-modulesd:container_images: WARNING: Reference 'docker.io/library/nginx:1.27' cannot be used: only ghcr.io is supported, and the reference names 'docker.io'.
```

An image published for several platforms is inventoried from the variant matching the agent's architecture. The operating system matched is always `linux`, not the agent's own: a container image is a Linux image whatever runs the engine, so on a macOS agent matching `darwin` would reject every image that exists. A reference that offers no matching variant is reported with the platforms it does offer:

```sql
wazuh-modulesd:container_images: WARNING: Reference 'ghcr.io/owner/app:1.4' was not inventoried: no image variant matches linux/arm64, the reference offers linux/amd64.
```

A reference whose image still reports the configuration digest already stored is not retrieved again. Its metadata is read, no layer is fetched, and its stored inventory is kept as it is.

### Registry Credentials

A public repository needs no credential. A private one is read with a user name and an access token, and neither is written into this file: the configuration names the keys, and the values live in the agent credential store.

```xml
<registry_auth>
  <registry>
    <host>ghcr.io</host>
    <user_keystore_key>ghcr_user</user_keystore_key>
    <passkey_keystore_key>ghcr_token</passkey_keystore_key>
  </registry>
</registry_auth>
```

| Element | Meaning |
|---------|---------|
| `host` | Registry host the entry applies to. |
| `user_keystore_key` | Name of the key holding the user name. |
| `passkey_keystore_key` | Name of the key holding the access token. |

The values are deposited beforehand, with the value read from standard input so it does not appear in the shell history or in the process list:

```
echo "owner" | /var/ossec/bin/wazuh-agent-keystore -f container_images -k ghcr_user
echo "$GHCR_TOKEN" | /var/ossec/bin/wazuh-agent-keystore -f container_images -k ghcr_token
```

A registry with no entry in this block is attempted with no credential. A registry with an entry whose keys are not in the store is reported once and the remaining references are still scanned:

```sql
wazuh-modulesd:container_images: WARNING: Reference 'ghcr.io/owner/private:1.0' could not be resolved: the credential configured for ghcr.io is missing from the agent credential store.
```

No credential value is written to the log at any level, and the configuration dump reports the key names only.

#### What the credential store protects

The store keeps the credential out of `ossec.conf`, and therefore out of configuration backups, out of shared-configuration pushes and out of support bundles. That is what it is for.

It is not encryption at rest. The stored bytes are produced by the same mechanism the manager keystore uses, which keeps the key alongside the value, so anyone able to read the file can recover the credential. What protects it locally is the file's permissions: `queue/credentials/credentials.json`, mode `0640`, owned by root. An attacker who already has root on the agent can read it, exactly as they could read the manager keystore.

Storing a credential is not supported on Windows agents. The module is built there, but its registry support is not, and the store refuses to write a value whose permissions it cannot restrict rather than leaving it readable by every local user.

### Certificate Verification

A registry is verified against a certificate bundle. When `<ca_bundle>` is not set, the bundle is looked for at the usual locations for the distribution, in this order:

```
/etc/ssl/certs/ca-certificates.crt
/etc/pki/tls/certs/ca-bundle.crt
/etc/ssl/ca-bundle.pem
/etc/pki/tls/cacert.pem
/etc/ssl/cert.pem
/usr/local/share/certs/ca-root-nss.crt
```

The first one that exists is used. This is resolved on the agent rather than taken from the HTTP library's build-time default, because that default is whichever path existed on the machine that built the package and is not necessarily present on the host running it.

When no bundle is found, or when a configured one does not exist, the reference is reported and skipped. It is never fetched over an unverified connection:

```sql
wazuh-modulesd:container_images: WARNING: Reference 'ghcr.io/owner/app:1.4' cannot be verified: no certificate bundle was found at any of the well-known locations, so the registry's certificate cannot be verified.
```

### Bounds on a Scan

A remote reference is bounded so one slow or hostile registry cannot hold the module thread. These are fixed defaults rather than configuration.

| Bound | Default | What it protects |
|-------|---------|------------------|
| Bytes per image | 2 GiB | One reference cannot consume the whole scan. |
| Bytes per scan | 8 GiB | Checked before a reference starts, so a scan stops taking on new work rather than abandoning an image half read. |
| Time per metadata request | 30 s | A registry that accepts a connection and then says nothing. |
| Time per layer transfer | 5 min | A registry that trickles bytes indefinitely. A layer transfer is suspended whenever the agent is slower than the network, so a plain total timeout would abort a healthy read of a large layer and a rate-based stall detector never fires against a slow trickle. This wall-clock ceiling is the bound that holds. |
| Attempts per request | 4 | With a doubling back-off from one second, honouring `Retry-After` when the registry sends one. |

A scan that is asked to stop abandons what it is reading, including a layer transfer in progress. This matters because every module shares one shutdown budget: a reference that would not return would delay every other module's clean stop.

### Network Requirements

Two hosts must be reachable over HTTPS on port 443:

| Host | What for |
|------|----------|
| `ghcr.io` | Authentication, image indexes and manifests. |
| `pkg-containers.githubusercontent.com` | Layer contents. A layer request to `ghcr.io` is redirected here. |

The redirect is followed, and the access token is deliberately not carried across it: the redirect target is already a signed URL, and sending the credential to it would disclose it to a host that does not need it.

### Archive Input Detection

An `<archive>` value is either a file or a directory, and the layout it holds is identified from its content:

| Input | Marker | Behavior |
|-------|--------|----------|
| Saved image archive | A tar file holding `index.json` or `manifest.json` | The images it holds are inventoried. |
| OCI image layout directory | `oci-layout` file | The images it holds are inventoried. |
| Saved archive extracted into a directory | `manifest.json` file | The images it holds are inventoried. |
| containerd content store | `io.containerd.content.v1.content` entry | Reported as unimplemented, it belongs to the engine store. |
| Unknown | none of the above | Logged and skipped. |

An input that cannot be read is not fatal. The module logs a warning and continues with the remaining references.

### Supported Package Formats

The packages of an image come from the package database its layers carry:

| Format | Database path | Status |
|--------|---------------|--------|
| dpkg | `var/lib/dpkg/status` | Parsed. Installed packages only. |
| apk | `lib/apk/db/installed`, `usr/lib/apk/db/installed` | Parsed. The second path is used by Wolfi and Chainguard images. |
| rpm, sqlite | `var/lib/rpm/rpmdb.sqlite`, `usr/lib/sysimage/rpm/rpmdb.sqlite` | Parsed. The format rpm 4.16 and later use, so the current Red Hat, Fedora and Amazon Linux families. |
| rpm, ndb | `var/lib/rpm/Packages.db`, `usr/lib/sysimage/rpm/Packages.db` | Parsed. The format the SUSE family uses. |
| rpm, Berkeley DB | `var/lib/rpm/Packages`, `usr/lib/sysimage/rpm/Packages` | Recognized, not parsed. The format rpm used before 4.16. |
| pacman | `var/lib/pacman/local/` | Recognized, not parsed yet. |
| portage | `var/db/pkg/` | Recognized, not parsed yet. |
| xbps | `var/db/xbps/` | Recognized, not parsed yet. |
| swupd | `usr/share/clear/bundles/` | Recognized, not parsed yet. |

The rpm database format is taken from the content of the database, not from where it was found, so both formats are read at either location.

The rpm sqlite database is read from the database file alone. An image whose database still holds uncommitted write-ahead log entries is inventoried as of its last checkpoint, which is what a committed image carries.

Package versions are stored the way the distribution expresses them, `version-release`, with the epoch kept as `epoch:version-release` whenever the package carries one.

An image whose package format is recognized but not parsed is still inventoried, with zero packages and one warning:

```sql
wazuh-modulesd:container_images: WARNING: NOT IMPLEMENTED: image at '/var/tmp/images/centos.tar' uses the package format(s) rpm, which are recognized but not supported yet. Reporting zero packages.
```

### Layer Compression

A layer blob is identified from its own first bytes rather than from the media type the image declares:

| Compression | Status |
|-------------|--------|
| gzip | Decompressed. |
| zstd | Decompressed. |
| none | Read as a plain tar. |
| xz, bzip2, lz4 | Recognized, not supported. The layer is skipped and reported. |

A layer using a compression that is recognized but not supported is skipped, and the image is inventoried with whatever its other layers hold:

```sql
wazuh-modulesd:container_images: WARNING: NOT IMPLEMENTED: layer 'blobs/sha256/<digest>' of '/var/tmp/images/myapp.tar' is xz compressed, which is recognized but not supported yet. Skipping it.
```

---

## Configuration Validation

### Validation Rules

The Container Images module validates configuration at startup:

1. `enabled` must be `yes` or `no`.
2. `scan_on_start` must be `yes` or `no`.
3. `interval` must be a positive time value.

### Error Handling

An invalid module setting, meaning `enabled`, `scan_on_start` or `interval`, causes a configuration error and rejects the module block.

Anything wrong with a single entry inside `<references>` costs that entry only: it is logged with a warning and ignored, and the remaining references are still configured. This covers an entry name that is not one of the three types, and an entry whose value is empty. Unknown elements directly inside `<container_images>` are also logged with a warning and ignored.

The same holds inside `<registry_auth>`: an entry naming no host, an entry naming no keystore key, and an unrecognised element are each reported and skipped, and the rest of the block is still applied.

A reference entry is skipped rather than rejected because rejecting it invalidates the whole module configuration, which stops `wazuh-modulesd` from starting; since the control script tests every daemon's configuration before starting any of them, a single empty entry would otherwise leave the agent with no daemon running.

---

## Platform Notes

- The module is configured only on agents.
- Images are read from disk, through saved archives and OCI image layout directories, and from GitHub Container Registry through `<ref>`. No container engine is involved.
- Remote references are not supported on Windows agents.
- Layers are streamed, gzip-compressed, zstd-compressed or plain, so no image is extracted to disk and the image filesystem is never reconstructed.
- No existing module configuration options are changed by this block.
