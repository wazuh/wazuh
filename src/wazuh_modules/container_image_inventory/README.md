# container_image_inventory (PoC)

Proof-of-concept Wazuh module that inventories packages from container images without running them.

This module is not wired into `wazuh-modulesd` or the manager publication path. The current deliverable is the standalone scanner binary `container-image-inventory-poc`.

The scanner supports local `docker save` archive scanning and remote registry scanning via Registry HTTP API v2, with manifest list / OCI index platform selection, anonymous / bearer / basic auth, and a digest-keyed result plus blob cache.

## Supported sources

| Source                              | Status        |
|-------------------------------------|---------------|
| `docker save` tar                   | Supported     |
| Remote image via Registry HTTP v2   | Supported     |
| OCI image layout directory          | Not in PoC    |
| Running containers / live runtime   | Not in PoC    |

## Supported package backends

| Backend                       | Status              |
|-------------------------------|---------------------|
| `dpkg` (`var/lib/dpkg/status`) | Supported          |
| `apk` (`lib/apk/db/installed`) | Supported          |
| RPM SQLite (`rpmdb.sqlite`)    | Supported          |
| RPM Berkeley DB (`Packages`)   | Supported          |
| RPM NDB (`Packages.db`)        | Detect-only        |

RPM NDB is reported as `rpm_backend=ndb-unsupported`, `package_count=0`. Used by openSUSE Tumbleweed and SLES 15 SP3+. Full support is deferred.

## Layout

```
src/wazuh_modules/container_image_inventory/
  CMakeLists.txt
  README.md
  docs/
    archive_scanner_design.md
    remote_registry_design.md
  include/
    containerImageInventory.hpp
    containerImageInventoryTypes.hpp
  src/
    blobProvider.hpp               # Abstract byte source (archive | registry)
    containerImageInventory.cpp    # Archive scanner orchestration + JSON
    digestCache.{hpp,cpp}          # Local blob + result + refs cache
    httpClient.{hpp,cpp}           # libcurl wrapper (GET, redirects, headers)
    imageArchiveParser.{hpp,cpp}   # docker-save tar parser
    imageReference.{hpp,cpp}       # Docker-style ref parser + default platform
    overlayFsResolver.{hpp,cpp}    # OCI/Docker whiteout-aware overlay
    packageDbExtractor.{hpp,cpp}   # Candidate selection, extract bytes
    packageInventoryScanner.{hpp,cpp}  # dpkg / apk / RPM SQLite / RPM BDB
    registryClient.{hpp,cpp}       # Registry HTTP v2 API + auth flows
    remoteImageScanner.{hpp,cpp}   # Remote scan orchestration + cache lookup
    tarUtils.{hpp,cpp}             # Tar listing / member extraction helpers
  testtool/
    main.cpp                       # CLI entry point
```

**Do not commit anything under `src/wazuh_modules/container_image_inventory/build/`.** That directory is the CMake output tree and is excluded by `.gitignore`.

## Build

The PoC links statically against the libraries already shipped in the Wazuh
source tree:

- `src/external/libarchive/.libs/libarchive.a` — tar reading
- `src/external/sqlite/libsqlite3.a` — RPM SQLite reader
- `src/external/curl/lib/.libs/libcurl.a` — Registry HTTP client
- `src/external/openssl/libssl.a` + `libcrypto.a` — TLS for libcurl

A standard Wazuh agent build (`make TARGET=agent`) is enough to populate them.
After that:

```bash
cd src/wazuh_modules/container_image_inventory
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j8
```

Output binary:

```
src/wazuh_modules/container_image_inventory/build/container-image-inventory-poc
```

System runtime dependencies: `zlib`, `pthread`, `dl`, a CA bundle. The HTTP client probes `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, and `/etc/ssl/cert.pem`. Set `SSL_CERT_FILE` or `SSL_CERT_DIR` to override.

## CLI

```bash
# Archive mode
container-image-inventory-poc --archive <docker-save-tar>
                              [--ref <image-ref>]
                              [--output-json <path>]
                              [--summary] [--trace]

# Remote mode
container-image-inventory-poc --image <remote-ref>
                              [--platform <os/arch[/variant]>]
                              [--cache-dir <path>]
                              [--username <user>]
                              [--password <pwd-or-token>]
                              [--bearer-token <token>]
                              [--no-cache] [--no-blob-cache]
                              [--output-json <path>]
                              [--summary] [--trace]

# Config mode (mixed archive + remote entries)
container-image-inventory-poc --config <ossec.conf>
                              [--cache-dir <path>]
                              [--summary] [--trace]
```

Defaults:

- `--cache-dir`: `/tmp/wazuh-container-image-inventory-cache`
- `--platform`: `linux/amd64` on x86_64, `linux/arm64` on aarch64, otherwise `linux/<host machine>`.

Credentials in traces: passwords, bearer tokens, and basic-auth values are never logged. Trace lines report registry, repository, reference, platform, media type, digest, byte counts, and cache hit/miss.

### Summary output — remote

```
source=remote ref=alpine:3.19 platform=linux/amd64 root_digest=sha256:6baf... manifest=sha256:b588... pm=apk rpm_backend=null db=lib/apk/db/installed count=15 cache_hit=false
```

### JSON output — remote

```json
{
  "source": {
    "type": "remote",
    "configured_ref": "alpine:3.19",
    "registry": "registry-1.docker.io",
    "repository": "library/alpine",
    "reference": "3.19",
    "platform": "linux/amd64"
  },
  "image": {
    "repo_tags": [],
    "os": "linux",
    "architecture": "amd64",
    "image_id": "sha256:<config-bytes-sha256>",
    "config_digest": "sha256:<config-blob>",
    "root_digest": "sha256:<manifest-list-or-manifest>",
    "selected_manifest_digest": "sha256:<platform-manifest>",
    "manifest_digest": "sha256:<same-as-selected>",
    "layer_count": 1
  },
  "scan": {
    "package_manager": "apk",
    "rpm_backend": null,
    "database_path": "lib/apk/db/installed",
    "package_count": 15,
    "elapsed_ms": 1996,
    "cache_hit": false
  },
  "packages": []
}
```

Archive mode keeps the archive JSON shape unchanged.

## Reference parsing

Docker-style image references parsed in remote mode:

```
alpine:3.19                          -> registry-1.docker.io / library/alpine / 3.19
alpine                               -> registry-1.docker.io / library/alpine / latest
docker.io/library/debian:bookworm    -> registry-1.docker.io / library/debian / bookworm
ghcr.io/owner/repo:tag               -> ghcr.io / owner/repo / tag
ghcr.io/owner/repo@sha256:<digest>   -> ghcr.io / owner/repo / sha256:<digest>
localhost:5000/repo:tag              -> localhost:5000 / repo / tag
123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag
                                     -> ECR registry / repo / tag
```

Rules:

- If the first path component contains `.` or `:`, or is `localhost`, it is the registry.
- Otherwise the registry is `registry-1.docker.io` and the repo is prefixed with `library/` when it has no slash.
- `@sha256:...` wins as the reference. Else a colon after the last slash is a tag. Else `latest`.

## Tag vs digest

- **Configure by tag.** Tags are mutable. `latest` is allowed but treated like any other mutable tag: every scan re-resolves it.
- **Cache by digest.** Each scan starts by fetching the manifest for the tag, which returns the registry's `Docker-Content-Digest`. That value is the `root_digest`. For an index/list, the PoC then fetches the platform-specific manifest and stores its digest as `selected_manifest_digest`.
- **Reuse by digest.** Package results are cached under `<cache>/results/sha256/<selected_manifest_digest>.json`. Two configured tags that resolve to the same platform manifest digest reuse the same cached result.
- **Audit by digest.** Every resolution writes a `refs/<...>.json` record with `registry`, `repository`, `reference`, `platform`, `root_digest`, `selected_manifest_digest`, and `scanned_at` ISO-8601 timestamp.

## Cache layout

```
<cache-dir>/
  blobs/
    sha256/<hex>                     # raw downloaded blobs (config + layers)
  results/
    sha256/<selected-manifest-hex>.json   # cached scan result JSON
  refs/
    <reg>_<repo>_<ref>_<platform>.json    # resolution audit record
```

Cache controls:

- `--cache-dir <path>` — override default location.
- `--no-cache` — still resolve the tag and download missing blobs, but do not read or write `results/`. Forces re-extraction. Blob cache is still used unless `--no-blob-cache` is also passed.
- `--no-blob-cache` — never read or write `blobs/`. Forces fresh downloads of every blob.

## Credentials

The PoC supports three auth modes layered on top of anonymous access:

| Mode             | Flags                                  | Notes |
|------------------|----------------------------------------|-------|
| Anonymous        | none                                   | Default. Used for public Docker Hub images. |
| Bearer challenge | `--username` + `--password`            | On 401 with `WWW-Authenticate: Bearer`, the credentials are sent to the realm token endpoint. Token is cached per (service, scope). |
| Direct Bearer    | `--bearer-token <token>`               | Sent as `Authorization: Bearer <token>` on the original request. No challenge dance. |
| Basic            | `--username` + `--password`            | If the registry responds with `WWW-Authenticate: Basic`, basic auth is sent on the retry. |

GHCR — bearer challenge via PAT or `GITHUB_TOKEN` with `read:packages`:

```bash
container-image-inventory-poc \
  --image ghcr.io/<owner>/<repo>:<tag> \
  --username "$GHCR_USER" \
  --password "$GHCR_TOKEN" \
  --summary --trace
```

ECR — pass the AWS short-lived password produced by
`aws ecr get-login-password`:

```bash
container-image-inventory-poc \
  --image <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag> \
  --username AWS \
  --password "$(aws ecr get-login-password --region <region>)" \
  --summary --trace
```

The PoC does not call AWS APIs itself. Production deployments should pull the ECR token from the Wazuh keystore or a dedicated credential refresher rather than from a one-shot CLI invocation. Token refresh strategy is out of scope for this PoC.

## ossec.conf configuration

```xml
<wodle name="container-image-inventory">
  <disabled>no</disabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <trace>yes</trace>
  <cache_dir>/var/ossec/queue/container-image-inventory-cache</cache_dir>

  <image>
    <type>remote</type>
    <ref>alpine:3.19</ref>
    <platform>linux/amd64</platform>
  </image>

  <image>
    <type>remote</type>
    <ref>ghcr.io/wazuh/wazuh-manager:4.14.0</ref>
    <platform>linux/amd64</platform>
    <username>${GHCR_USER}</username>
    <password>${GHCR_TOKEN}</password>
  </image>

  <image>
    <type>archive</type>
    <path>/var/lib/wazuh/images/alpine_3.19.tar</path>
    <ref>alpine:3.19</ref>
  </image>
</wodle>
```

`${VAR}` substitution from environment variables is supported. Production deployments must source credentials from the Wazuh keystore — plain-text credentials in `ossec.conf` are acceptable only for the PoC.

## Validation results

### Public remote images (Docker Hub anonymous)

```
alpine:3.19           pm=apk  count=15  root=sha256:6baf...  manifest=sha256:b588...
debian:bookworm-slim  pm=dpkg count=88  root=sha256:67b3...  manifest=sha256:2749...
fedora:39             pm=rpm  rpm_backend=sqlite count=143
                                          root=sha256:d63d...  manifest=sha256:2c06...
```

Package-name parity against the reference registry extractor, using the same selected `linux/amd64` manifest:

| Image                 | Reference count | C++ count | Name diff |
|-----------------------|-----------------|-----------|-----------|
| `alpine:3.19`         | 15       | 15        | 0         |
| `debian:bookworm-slim`| 88       | 88        | 0         |
| `fedora:39`           | 143      | 143       | 0         |

### Cache behavior

- First scan: `cache_hit=false`, layers downloaded, result written to `results/sha256/<selected_manifest_digest>.json`.
- Second scan for the same `selected_manifest_digest`: `cache_hit=true`, no layer or config downloads.
- `--no-cache`: re-extracts (`cache_hit=false`) but reuses cached blobs.
- `--no-blob-cache`: re-downloads every blob.

### Archive regression

| Image                       | Backend            | Reference count | C++ count | Name diff |
|-----------------------------|--------------------|-------------|----------|-----------|
| `alpine_3.19.tar`           | `apk`              | 15          | 15       | 0         |
| `debian_bookworm_slim.tar`  | `dpkg`             | 88          | 88       | 0         |
| `ubuntu_2204.tar`           | `dpkg`             | 101         | 101      | 0         |
| `fedora_39.tar`             | `rpm/sqlite`       | 143         | 143      | 0         |
| `centos_7.tar`              | `rpm/bdb`          | 148         | 148      | 0         |
| `rockylinux_9.tar`          | `rpm/sqlite`       | 141         | 141      | 0         |
| `distroless_static.tar`     | `none`             | 0           | 0        | 0         |
| `whiteout_test.tar`         | `dpkg`             | 88          | 88       | 0         |
| `opensuse_leap_155.tar`     | `rpm/ndb-unsupported` | 0       | 0        | 0         |

### Authentication validation

- **Anonymous Docker Hub**: validated above.
- **GHCR with PAT**: not executed because no GHCR credentials were available in this environment. Code path is the standard bearer-challenge flow used by Docker Hub, plus the credential-bearing token request; expected to work with `--username <ghcr-user> --password <PAT>`.
- **ECR with `get-login-password`**: not executed because no AWS credentials were available. Bearer/basic challenge handling and `--username AWS --password $(aws ecr get-login-password ...)` are wired up; needs validation with real credentials before relying on it.

## Known limitations

- Single-image manifest selection only; OCI image index attestation descriptors (`vnd.oci.image.index.v1+json` with `platform.os=unknown`) are ignored.
- No OCI image layout directory support.
- No `wazuh-modulesd` integration. No event emission, no Wazuh DB write, no manager publication.
- Layer bodies and intermediate blobs are kept in memory for the duration of a scan. Adequate for PoC fixtures (3-100 MB); large images should stream.
- Temporary files (`/tmp/cii-poc-*.sqlite`, `/tmp/cii-poc-*.Packages`) are unlinked at the end of a scan. Signal-time cleanup is not implemented.
- `--config` uses regex parsing rather than the wazuh XML config helpers. Fine for PoC. Real module integration should use shared XML infrastructure.
- RPM NDB stays detect-only.
- TLS root store relies on system CA bundle or `SSL_CERT_FILE`/`SSL_CERT_DIR` env vars. No registry-level cert pinning.

## Future work

- Wire into `wazuh-modulesd` as a real wodle.
- Stream layer bodies instead of buffering, and persist blobs to disk incrementally.
- Persist results to the manager via the appropriate inventory channel.
- Add RPM NDB support for SUSE images.
- Wazuh keystore-backed credential sourcing for GHCR/ECR.

## Design notes

- `docs/archive_scanner_design.md`
- `docs/remote_registry_design.md`
