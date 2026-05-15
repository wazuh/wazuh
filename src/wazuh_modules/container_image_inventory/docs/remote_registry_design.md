# Remote registry scanner design

## Overview

This document describes remote registry support for the standalone container image inventory scanner under:

```text
src/wazuh_modules/container_image_inventory/
```

Remote registry support extends the scanner to process images configured by repository plus tag, while preserving all archive-mode behavior.

The scanner implements Registry HTTP API v2 flows directly in C++.

## Business rules

- Users configure remote images by repository plus tag, for example `ghcr.io/<owner>/<repo>:<tag>`.
- A missing tag means `latest`.
- `latest` is supported, but it is mutable. Resolve it on every scan cycle.
- The tag is the external monitoring target. The digest is internal state.
- Multiple configured tags can resolve to the same remote digest. If they do, reuse the same scan result.
- A digest-only reference is accepted for manual scans, but it is not the preferred monitoring input because immutable digests do not move when publishers release new versions.
- The remote scanner does not need vulnerability detection, Wazuh DB persistence, manager communication, or full `wazuh-modulesd` integration.

## Goal

Add remote image scan support to the existing standalone binary:

```text
container-image-inventory-poc
```

The scanner must:

1. Resolve a remote image reference through the Docker Registry HTTP API v2.
2. Handle manifest lists / OCI indexes and select a target platform.
3. Download the selected config blob and layer blobs by digest.
4. Feed the same package database detection, overlay, and package parser logic already used by archive mode.
5. Cache scan results by resolved digest so repeated tags and repeated runs do not re-extract packages unnecessarily.

Do not run containers. Do not require Docker, Podman, or containerd.

## Expected repository changes

Extend the existing module. Prefer this shape unless the current implementation suggests a cleaner split:

```text
src/wazuh_modules/container_image_inventory/
  include/
    containerImageInventory.hpp
    containerImageInventoryTypes.hpp
  src/
    registryClient.hpp
    registryClient.cpp
    remoteImageScanner.hpp
    remoteImageScanner.cpp
    blobProvider.hpp
    blobProvider.cpp
    digestCache.hpp
    digestCache.cpp
```

Refactor only as much as needed. Keep archive mode working.

Recommended internal interfaces:

```cpp
struct RemoteImageRef {
    std::string original;
    std::string registry;
    std::string repository;
    std::string reference; // tag or sha256:...
};

struct ResolvedRemoteImage {
    RemoteImageRef ref;
    std::string requested_platform;       // linux/amd64
    std::string root_media_type;          // index or manifest
    std::string root_digest;              // Docker-Content-Digest of configured tag/reference
    std::string selected_manifest_digest; // platform manifest digest
    std::string config_digest;
    std::vector<std::string> layer_digests;
    nlohmann::json config;
};
```

The package extraction code should not care whether bytes came from an archive or a registry. If the current archive code is tightly coupled to archive layer names, introduce a small abstraction:

```cpp
class BlobProvider {
public:
    virtual std::vector<unsigned char> get_blob(const std::string& digest_or_name) = 0;
};
```

Archive mode can continue using its existing path-based implementation. Remote mode can use digest-based blobs.

## CLI requirements

Add remote mode without breaking existing options.

Required new options:

```bash
container-image-inventory-poc --image <remote-ref>
                              [--platform <os/arch[/variant]>]
                              [--cache-dir <path>]
                              [--username <user>]
                              [--password <password-or-token>]
                              [--bearer-token <token>]
                              [--output-json <path>]
                              [--summary]
                              [--trace]
```

Existing archive options must still work:

```bash
container-image-inventory-poc --archive <docker-save-tar>
                              [--ref <image-ref>]
                              [--output-json <path>]
                              [--summary]
                              [--trace]
```

Config mode must support both archive and remote entries:

```bash
container-image-inventory-poc --config <ossec.conf> [--cache-dir <path>] [--summary] [--trace]
```

Default platform:

- On `x86_64` / `amd64`: `linux/amd64`
- On `aarch64` / `arm64`: `linux/arm64`
- Otherwise: `linux/<host-machine>`

Example remote commands:

```bash
container-image-inventory-poc \
  --image alpine:3.19 \
  --platform linux/amd64 \
  --summary \
  --trace
```

```bash
container-image-inventory-poc \
  --image ghcr.io/wazuh/wazuh-manager:4.14.0 \
  --platform linux/amd64 \
  --username "$GHCR_USER" \
  --password "$GHCR_TOKEN" \
  --cache-dir /tmp/wazuh-container-image-cache \
  --output-json /tmp/wazuh-manager.remote.json \
  --trace
```

```bash
container-image-inventory-poc \
  --image 123456789012.dkr.ecr.us-east-1.amazonaws.com/my-image:latest \
  --username AWS \
  --password "$(aws ecr get-login-password --region us-east-1)" \
  --summary \
  --trace
```

The scanner does not implement to shell out to `aws`. For ECR, accept the username/password pair passed by the user.

## Remote reference parsing

Implement reference parsing compatible with Docker conventions:

```text
alpine:3.19
debian:bookworm-slim
fedora:39
docker.io/library/alpine:3.19
registry-1.docker.io/library/alpine:3.19
ghcr.io/owner/repo:tag
ghcr.io/owner/repo@sha256:<digest>
localhost:5000/repo:tag
```

Rules:

- If the first path component contains `.` or `:` or is `localhost`, treat it as the registry.
- Otherwise use Docker Hub: `registry-1.docker.io`.
- For Docker Hub single-component names, prefix `library/`.
- If the reference contains `@sha256:...`, use that digest as the reference.
- Else if the last colon after the last slash exists, use that tag.
- Else use `latest`.

Examples:

```text
alpine:3.19          -> registry-1.docker.io / library/alpine / 3.19
alpine               -> registry-1.docker.io / library/alpine / latest
ghcr.io/acme/app:v1  -> ghcr.io / acme/app / v1
localhost:5000/a:b   -> localhost:5000 / a / b
```

## Registry API requirements

Implement the Docker Registry HTTP API v2 calls directly in C++.

Manifest request:

```text
GET https://<registry>/v2/<repository>/manifests/<tag-or-digest>
Accept: application/vnd.oci.image.index.v1+json,
        application/vnd.docker.distribution.manifest.list.v2+json,
        application/vnd.oci.image.manifest.v1+json,
        application/vnd.docker.distribution.manifest.v2+json
```

Blob request:

```text
GET https://<registry>/v2/<repository>/blobs/<digest>
```

HTTP requirements:

- Use Wazuh's existing HTTP helper if it is easy to link from this standalone .
- If not practical, use libcurl if available in the repository/build environment.
- Do not implement HTTP through shell commands.
- Follow registry blob redirects (`301`, `302`, `303`, `307`, `308`).
- Preserve the `Docker-Content-Digest` response header for manifest requests.
- Use a clear User-Agent, for example `wazuh-container-image-inventory-poc/2.0`.
- Emit useful errors for `401`, `403`, `404`, unsupported media types, and platform not found.

Authentication requirements:

1. Anonymous registries must work.
2. Bearer challenge flow must work:
   - On `401`, parse `WWW-Authenticate`.
   - If the scheme is `Bearer`, read `realm`, `service`, and `scope`.
   - Request a token from `realm?service=<service>&scope=<scope>`.
   - Retry the original registry request with `Authorization: Bearer <token>`.
3. Basic credentials must work:
   - If `--username` and `--password` are provided, use them for token requests.
   - For registries that accept direct basic auth, allow `Authorization: Basic ...`.
4. `--bearer-token` must work:
   - Use it directly as `Authorization: Bearer <token>`.
   - Do not request a new token unless the registry still returns `401` and a challenge.

Do not log credential values in traces.

## Manifest and platform resolution

Recognize these media types:

```text
application/vnd.oci.image.index.v1+json
application/vnd.docker.distribution.manifest.list.v2+json
application/vnd.oci.image.manifest.v1+json
application/vnd.docker.distribution.manifest.v2+json
```

Resolution flow:

1. Fetch the root object for the configured tag/digest.
2. Store `root_digest` from `Docker-Content-Digest`.
3. If the root object is an index / manifest list:
   - Search `.manifests[]` for `platform.os`, `platform.architecture`, and optional `platform.variant`.
   - Ignore descriptors with `platform.os == "unknown"` unless the requested platform is unknown.
   - Fetch the selected manifest by descriptor digest.
   - Store `selected_manifest_digest`.
4. If the root object is already an image manifest:
   - Use it directly.
   - `selected_manifest_digest` equals `root_digest` when available.
5. Read the image manifest `.config.digest`.
6. Read ordered `.layers[].digest`.
7. Download the config blob and parse `os`, `architecture`, and image id as `sha256(config-bytes)`.

Cache identity:

- For a selected platform scan, use `selected_manifest_digest` as the package-result cache key.
- Also store `root_digest` to explain which configured tag resolved to which manifest list or image manifest.
- This prevents duplicate scans when two tags resolve to the same selected platform manifest.
- For auditability, output both `root_digest` and `selected_manifest_digest`.

## Remote overlay and package extraction

Remote layers are tar blobs just like archive layers after downloading.

Reuse the existing candidate package DB paths:

```text
var/lib/dpkg/status
lib/apk/db/installed
var/lib/rpm/rpmdb.sqlite
usr/lib/sysimage/rpm/rpmdb.sqlite
var/lib/rpm/Packages
usr/lib/sysimage/rpm/Packages
var/lib/rpm/Packages.db
usr/lib/sysimage/rpm/Packages.db
```

The remote scanner must apply the same overlay behavior:

- `.wh.<name>` deletes lower-layer content.
- `.wh..wh..opq` hides lower-layer entries under the parent directory.
- Later regular files replace earlier files at the same normalized path.

Important edge case:

- If a whiteout deletes a directory that contains a package DB file, the candidate under that directory must be removed from the final view.
- Add a focused test or synthetic fixture for this if feasible.

Optimization requirement:

- The remote  may hold blobs in memory, like archive mode, but it must not download the same layer digest twice in a single scan.
- If the selected package DB is found in a layer that was already downloaded during overlay resolution, reuse those bytes.

## Digest cache

Add a simple local cache for remote scan results.

CLI:

```bash
--cache-dir <path>
```

Default:

```text
/tmp/wazuh-container-image-inventory-cache
```

Cache layout:

```text
<cache-dir>/
  blobs/
    sha256/<hex>
  results/
    sha256/<selected-manifest-hex>.json
  refs/
    <escaped-registry-repository-tag-platform>.json
```

Minimum required behavior:

- Store downloaded blobs by digest under `blobs/`.
- Store scan results by `selected_manifest_digest` under `results/`.
- Store a reference resolution record under `refs/` with:
  - configured ref,
  - platform,
  - root digest,
  - selected manifest digest,
  - scanned at timestamp.
- On a new remote scan:
  - Always resolve the configured tag first.
  - If `results/<selected-manifest-digest>.json` exists and `--no-cache` is not set, return the cached package result.
  - The summary and JSON output must indicate `cache_hit=true`.
  - If missing, download layers and scan, then write the result.

Add:

```bash
--no-cache
```

Behavior:

- Still resolve the tag.
- Do not read cached package results.
- It is acceptable to still reuse cached blob downloads unless `--no-blob-cache` is also added.

Add:

```bash
--no-blob-cache
```

Behavior:

- Download blobs from the registry even if they exist locally.

## JSON output requirements

Extend the existing JSON shape without breaking archive output.

Remote output:

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
    "repo_tags": ["alpine:3.19"],
    "os": "linux",
    "architecture": "amd64",
    "image_id": "sha256:<config-bytes-sha256>",
    "config_digest": "sha256:<config-digest>",
    "root_digest": "sha256:<manifest-list-or-manifest-digest>",
    "selected_manifest_digest": "sha256:<platform-manifest-digest>",
    "manifest_digest": "sha256:<same-as-selected-manifest-digest-for-compat>",
    "layer_count": 1
  },
  "scan": {
    "package_manager": "apk",
    "rpm_backend": null,
    "database_path": "lib/apk/db/installed",
    "package_count": 15,
    "elapsed_ms": 123,
    "cache_hit": false
  },
  "packages": []
}
```

Summary output:

```text
source=remote ref=alpine:3.19 platform=linux/amd64 root_digest=sha256:... manifest=sha256:... pm=apk rpm_backend=null db=lib/apk/db/installed count=15 cache_hit=false
```

For archive mode, keep the previous summary stable unless you need to append fields. Do not remove existing fields.

## Trace requirements

With `--trace`, remote mode must print messages equivalent to:

```text
container-image-inventory: remote scan started ref=alpine:3.19 platform=linux/amd64
container-image-inventory: parsed ref registry=registry-1.docker.io repository=library/alpine reference=3.19
container-image-inventory: fetching manifest reference=3.19
container-image-inventory: bearer challenge received realm=... service=... scope=repository:library/alpine:pull
container-image-inventory: manifest resolved media_type=application/vnd.oci.image.index.v1+json root_digest=sha256:...
container-image-inventory: selected platform manifest digest=sha256:...
container-image-inventory: config downloaded digest=sha256:... bytes=...
container-image-inventory: layers discovered count=1
container-image-inventory: cache lookup selected_manifest_digest=sha256:... hit=false
container-image-inventory: layer downloaded digest=sha256:... bytes=...
container-image-inventory: candidate found path=lib/apk/db/installed layer=0 digest=sha256:...
container-image-inventory: selected package_manager=apk database=lib/apk/db/installed
container-image-inventory: packages parsed count=15
container-image-inventory: remote scan completed elapsed_ms=...
```

Credential safety:

- Do not print passwords, bearer tokens, authorization headers, or full basic auth values.
- It is fine to print registry, repository, reference, platform, media type, digest, byte counts, and cache hit/miss.

## ossec.conf implementation configuration

Extend `--config` mode to support remote entries:

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
    <username>GHCR_USER_FROM_ENV_OR_CONFIG</username>
    <password>GHCR_TOKEN_FROM_ENV_OR_CONFIG</password>
  </image>

  <image>
    <type>archive</type>
    <path>/var/lib/wazuh/images/alpine_3.19.tar</path>
    <ref>alpine:3.19</ref>
  </image>
</wodle>
```

For the , credentials in config may be plain text. Document that production must use Wazuh keystore or another secure credential source.

Environment substitution is optional. If implemented, support:

```xml
<username>${GHCR_USER}</username>
<password>${GHCR_TOKEN}</password>
```

## Validation requirements

Validate at least these public references:

```bash
container-image-inventory-poc --image alpine:3.19 --platform linux/amd64 --summary --trace
container-image-inventory-poc --image debian:bookworm-slim --platform linux/amd64 --summary
container-image-inventory-poc --image fedora:39 --platform linux/amd64 --summary
```

Expected results, matching the Python registry  at the time of the original spike:

```text
alpine:3.19           pm=apk  count approximately 15
debian:bookworm-slim  pm=dpkg count approximately 88
fedora:39             pm=rpm  rpm_backend=sqlite count approximately 143
```

Counts may change if tags have moved since the original spike. Validate exact package names against the Python registry  for the digest resolved during the test:

```bash
python3 poc_registry_extract.py \
  alpine:3.19 \
  --platform linux/amd64 \
  --output-json /tmp/alpine.remote.python.json

container-image-inventory-poc \
  --image alpine:3.19 \
  --platform linux/amd64 \
  --output-json /tmp/alpine.remote.cpp.json

jq -r '.packages[].name' /tmp/alpine.remote.python.json | sort -u > /tmp/alpine.remote.python.names
jq -r '.packages[].name' /tmp/alpine.remote.cpp.json | sort -u > /tmp/alpine.remote.cpp.names
diff -u /tmp/alpine.remote.python.names /tmp/alpine.remote.cpp.names
```

Cache validation:

1. Run a remote image scan with `--cache-dir /tmp/cii-cache-test`.
2. Run it again with the same image and platform.
3. The second run must report `cache_hit=true`.
4. Configure two refs that resolve to the same selected manifest digest, if available, and verify the second ref reuses the cached result.

Authentication validation:

- GHCR:

```bash
container-image-inventory-poc \
  --image ghcr.io/<owner>/<repo>:<tag> \
  --username "$GHCR_USER" \
  --password "$GHCR_TOKEN" \
  --summary \
  --trace
```

- ECR:

```bash
container-image-inventory-poc \
  --image <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag> \
  --username AWS \
  --password "$(aws ecr get-login-password --region <region>)" \
  --summary \
  --trace
```

If private credentials are not available, document that only anonymous Docker Hub validation was executed.

Regression validation:

- Re-run archive fixture validation from implementation.
- Archive mode counts and JSON shape must remain compatible.
- `--config` with archive-only entries must still work.

## Non-goals

- No vulnerability detection.
- No `wazuh-modulesd` production integration.
- No Wazuh DB persistence.
- No manager communication.
- No Docker daemon use.
- No running container inspection.
- No Windows image support.
- No full OCI image layout directory support unless it falls out naturally from the refactor.
- No native AWS SDK integration. ECR auth is passed as registry credentials.
- No production credential storage.

## Documentation updates required

Update:

```text
src/wazuh_modules/container_image_inventory/README.md
```

Include:

- How to run remote scans.
- How tag resolution and digest caching work.
- How to use `latest` safely.
- How to pass GHCR and ECR credentials.
- How to configure remote images in the `ossec.conf` block.
- Cache directory layout.
- Known limitations.
- Validation results and any credentials that were unavailable.

Also add a short note that build artifacts under:

```text
src/wazuh_modules/container_image_inventory/build/
```

must not be committed.

## Final expected result

At completion, the branch must contain:

- Existing archive-mode behavior still working.
- Remote scans through Registry HTTP API v2.
- Manifest list / OCI index platform selection.
- Anonymous Docker Hub support.
- Basic/bearer credential support sufficient for GHCR and ECR token workflows.
- Remote config entries in `--config` mode.
- Digest-result cache with visible `cache_hit` output.
- JSON and summary output with root and selected manifest digests.
- Traces that explain registry resolution, cache behavior, and package extraction.
- README instructions and validation results.
