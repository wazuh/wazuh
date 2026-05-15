# Archive scanner design

## Overview

Implement a minimal C++ scanner that inventories packages from container images without running containers.

The input identity model is:

- Remote images are configured by repository plus tag, for example `ghcr.io/<owner>/<repo>:<tag>`.
- The tag is the external monitoring target. The digest is an internal identity and cache key.
- Multiple tags may resolve to the same manifest list or image manifest digest. If that happens, the scan result must be reusable.
- `latest` is allowed as a tag, but it must be treated like any other mutable tag: resolve it every run, compare the resulting digest, and only skip package extraction when the digest did not change.
- Configuring only a digest is not the primary monitoring model, because a digest is immutable and will not move when the publisher releases a new image.

## Goal

Create a minimal C++ scanner that can analyze container images and print a normalized package inventory without running containers.

The scanner must support local image archives. A local image means a tar archive produced by `docker save`, not a running container and not direct Docker/Podman/containerd storage inspection.

Remote registry support uses the same internal scanner interface.

## Expected repository shape

Add a new module under:

```text
src/wazuh_modules/container_image_inventory/
```

Use this structure unless the existing build system strongly suggests a better local pattern:

```text
src/wazuh_modules/container_image_inventory/
  CMakeLists.txt
  README.md
  include/
    containerImageInventory.hpp
    containerImageInventoryTypes.hpp
  src/
    containerImageInventory.cpp
    imageArchiveParser.cpp
    overlayFsResolver.cpp
    packageDbExtractor.cpp
    packageInventoryScanner.cpp
  testtool/
    CMakeLists.txt
    main.cpp
  tests/
    CMakeLists.txt
    overlayFsResolver_test.cpp
    imageArchiveParser_test.cpp
```

If a smaller structure is enough, keep it smaller, but keep the public scanner, testtool, and README separated.

The generated standalone binary must be named:

```text
container-image-inventory-poc
```

The binary can live in the CMake build output for the testtool. Document the exact path produced by the build you implement.

## Functional requirements

1. Parse a Docker saved image archive.
   - Read `manifest.json`.
   - Use the first manifest entry for archive scans.
   - Read the config blob referenced by `Config`.
   - Read ordered layer paths from `Layers`.
   - Extract basic image metadata: repo tags, config path, OS, architecture, image id as `sha256(config-bytes)`, and ordered layer count.

2. Reconstruct only the effective package database paths.
   - Do not unpack the whole root filesystem.
   - Scan the ordered layer tarballs and build a final-path map for supported package DB files.
   - Apply OCI/Docker overlay whiteout behavior:
     - `.wh.<name>` deletes the lower-layer entry named `<name>`.
     - `.wh..wh..opq` makes the parent directory opaque and hides lower-layer entries below it.
     - Later regular files replace earlier files at the same normalized path.

3. Probe these package database paths, in this order:
   - dpkg:
     - `var/lib/dpkg/status`
   - apk:
     - `lib/apk/db/installed`
   - rpm SQLite:
     - `var/lib/rpm/rpmdb.sqlite`
     - `usr/lib/sysimage/rpm/rpmdb.sqlite`
   - rpm Berkeley DB:
     - `var/lib/rpm/Packages`
     - `usr/lib/sysimage/rpm/Packages`
   - rpm NDB:
     - `var/lib/rpm/Packages.db`
     - `usr/lib/sysimage/rpm/Packages.db`

4. Parse packages and normalize output.
   - For dpkg and apk, reuse or adapt the existing C++ parser logic from `src/data_provider/src/packages/packageLinuxParserHelper.h` where practical.
   - For rpm Berkeley DB, reuse existing Wazuh code where practical, especially `src/data_provider/src/packages/berkeleyRpmDbHelper.h`.
   - For rpm SQLite, implement the minimal reader proven in `poc_rpm_extract.py`: open the extracted database read-only and read `SELECT blob FROM Packages`, then feed each RPM header blob into the same RPM header parser.
   - For rpm NDB, detection is enough for . Return `package_manager=rpm`, `rpm_backend=ndb-unsupported`, `package_count=0`, and a clear warning trace.

5. Produce JSON output with this shape:

```json
{
  "source": {
    "type": "archive",
    "path": "/tmp/alpine_3.19.tar",
    "configured_ref": "alpine:3.19"
  },
  "image": {
    "repo_tags": ["alpine:3.19"],
    "os": "linux",
    "architecture": "amd64",
    "image_id": "sha256:<config-bytes-sha256>",
    "config_digest": "sha256:<config-blob>",
    "manifest_digest": null,
    "layer_count": 1
  },
  "scan": {
    "package_manager": "apk",
    "rpm_backend": null,
    "database_path": "lib/apk/db/installed",
    "package_count": 15,
    "elapsed_ms": 123
  },
  "packages": [
    {
      "name": "alpine-baselayout",
      "version_": "3.4.3-r2",
      "architecture": "x86_64",
      "size": 0,
      "description": "Alpine base dir structure and init scripts",
      "priority": " ",
      "category": " ",
      "source": " ",
      "multiarch": " ",
      "vendor": " ",
      "installed": " ",
      "path": " ",
      "type": "apk"
    }
  ]
}
```

Use the existing Wazuh package field names, including `version_`.

6. Add trace logs.
   - The scanner must emit trace/debug messages describing:
     - input archive path and configured reference,
     - manifest/config discovery,
     - layer count and layer order,
     - each candidate package DB discovered or removed by whiteout,
     - selected package manager/backend,
     - package count,
     - elapsed time,
     - unsupported conditions.
   - The standalone binary must support `--trace` to print these messages to stderr.

7. Do not run containers.
   - The implementation must not call `docker run`.
   - The implementation must not require a running Docker daemon for archive mode.

## CLI requirements

The binary must support:

```bash
container-image-inventory-poc --archive <docker-save-tar> [--ref <image-ref>] [--output-json <path>] [--summary] [--trace]
```

Expected behavior:

- `--archive` is required for .
- `--ref` is optional metadata used to show which configured tag this archive represents.
- `--output-json` writes the full JSON result.
- `--summary` prints one line:

```text
source=archive ref=alpine:3.19 os=linux arch=amd64 pm=apk rpm_backend=null db=lib/apk/db/installed count=15
```

- Without `--summary`, print the full JSON to stdout.
- With `--trace`, print process traces to stderr without corrupting JSON stdout.

Example commands:

```bash
container-image-inventory-poc \
  --archive /tmp/container-image-test-images/alpine_3.19.tar \
  --ref alpine:3.19 \
  --summary \
  --trace
```

```bash
container-image-inventory-poc \
  --archive /tmp/container-image-test-images/debian_bookworm_slim.tar \
  --ref debian:bookworm-slim \
  --output-json /tmp/debian_bookworm_slim.packages.json
```

## ossec.conf  configuration

Add and document a minimal module configuration block. The  does not need full manager persistence or inventory synchronization, but it must show how the future module would be enabled from `ossec.conf`.

Use this proposed configuration:

```xml
<wodle name="container-image-inventory">
  <disabled>no</disabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <trace>yes</trace>

  <image>
    <type>archive</type>
    <path>/tmp/container-image-test-images/alpine_3.19.tar</path>
    <ref>alpine:3.19</ref>
  </image>

  <image>
    <type>archive</type>
    <path>/tmp/container-image-test-images/debian_bookworm_slim.tar</path>
    <ref>debian:bookworm-slim</ref>
  </image>
</wodle>
```

Implementation requirement :

- It is acceptable if the standalone binary is the primary execution path.
- If wiring into `wazuh-modulesd` is implemented, add a minimal config parser for this block and make the module run the same scanner on start.
- If full `wazuh-modulesd` wiring is too large, add the parser and a documented testtool mode that reads an `ossec.conf` file:

```bash
container-image-inventory-poc --config /var/ossec/etc/ossec.conf --summary --trace
```

The `--config` mode must find every `<image>` entry under `<wodle name="container-image-inventory">` and run one scan per image.

## Expected traces

With `--trace`, a successful archive scan should include messages equivalent to:

```text
container-image-inventory: scan started source=archive path=/.../alpine_3.19.tar ref=alpine:3.19
container-image-inventory: manifest.json loaded entries=1
container-image-inventory: config loaded path=... os=linux architecture=amd64 image_id=sha256:...
container-image-inventory: layers discovered count=1
container-image-inventory: probing package database candidates count=8
container-image-inventory: candidate found path=lib/apk/db/installed layer=0
container-image-inventory: selected package_manager=apk database=lib/apk/db/installed
container-image-inventory: packages parsed count=15
container-image-inventory: scan completed elapsed_ms=...
```

Whiteout behavior must be traceable. For the `whiteout_test.tar` fixture, traces should show that a later layer removes lower-layer package DB entries or files when applicable.

## Validation requirements

Use these fixtures when available:

```text
/tmp/container-image-test-images/alpine_3.19.tar
/tmp/container-image-test-images/debian_bookworm_slim.tar
/tmp/container-image-test-images/fedora_39.tar
/tmp/container-image-test-images/centos_7.tar
/tmp/container-image-test-images/rockylinux_9.tar
/tmp/container-image-test-images/distroless_static.tar
/tmp/container-image-test-images/whiteout_test.tar
```

Minimum acceptance checks:

- `alpine_3.19.tar` detects `apk`, database `lib/apk/db/installed`, and returns packages.
- `debian_bookworm_slim.tar` detects `dpkg`, database `var/lib/dpkg/status`, and returns packages.
- `fedora_39.tar` detects `rpm`, backend `sqlite`, and returns packages.
- `centos_7.tar` detects `rpm`, backend `bdb`, and returns packages if the existing Wazuh BDB helper can be reused in this build environment.
- `distroless_static.tar` returns `package_manager=none`, `package_count=0`, and exits successfully.
- `whiteout_test.tar` honors whiteouts. The package list must not include packages removed by a later layer, matching the behavior documented by the Python validation script.

Compare package names against the Python  output, not against a live running container as the primary validation:

```bash
python3 poc_extract_packages.py \
  /tmp/container-image-test-images/alpine_3.19.tar \
  --output-json /tmp/alpine_python.json

container-image-inventory-poc \
  --archive /tmp/container-image-test-images/alpine_3.19.tar \
  --ref alpine:3.19 \
  --output-json /tmp/alpine_cpp.json
```

Then compare:

```bash
jq -r '.packages[].name' /tmp/alpine_python.json | sort -u > /tmp/alpine_python.names
jq -r '.packages[].name' /tmp/alpine_cpp.json | sort -u > /tmp/alpine_cpp.names
diff -u /tmp/alpine_python.names /tmp/alpine_cpp.names
```

## Non-goals 

- Do not implement vulnerability detection.
- Do not send results to the manager.
- Do not persist inventory in Wazuh DB.
- Do not implement full inventory synchronization.
- Do not inspect running containers.
- Do not inspect Windows container images.
- Do not add GHCR/ECR credential storage beyond documenting the future extension point.
- Do not implement a complete registry cache. Only document digest-based reuse for the future remote scanner.

## Remote scanner extension notes

If adding remote registry support, follow `poc_registry_extract.py`:

1. Parse image references.
   - Docker Hub short names normalize to `registry-1.docker.io/library/<name>`.
   - A missing tag means `latest`.

2. Fetch the manifest or manifest list with Registry HTTP API v2:

```text
GET https://<registry>/v2/<repository>/manifests/<tag-or-digest>
Accept: application/vnd.oci.image.index.v1+json,
        application/vnd.docker.distribution.manifest.list.v2+json,
        application/vnd.oci.image.manifest.v1+json,
        application/vnd.docker.distribution.manifest.v2+json
```

3. If the response is a manifest list or OCI index, select the requested platform, defaulting to host `linux/amd64` on x86_64.

4. Record the registry-provided `Docker-Content-Digest`.
   - Use this digest as the internal cache key.
   - If two configured tags resolve to the same digest, reuse the same scan result.
   - If a mutable tag such as `latest` resolves to a different digest on a later run, scan again.

5. Download config and layer blobs by digest and feed the same overlay/package scanner used by archive mode.

## Documentation deliverable

Update `src/wazuh_modules/container_image_inventory/README.md` with:

- How to build  binary.
- How to run archive scans.
- How to use `--summary`, `--trace`, `--output-json`, and `--config`.
- The proposed `ossec.conf` block.
- A short explanation of tag vs digest:
  - configure by tag,
  - resolve to digest,
  - use digest internally to avoid duplicate scans.
- Known limitations and unsupported cases.

## Final expected result

At the end of the implementation, the branch must contain:

- A buildable C++ scanner/testtool binary named `container-image-inventory-poc`.
- Local archive package extraction for dpkg, apk, and at least rpm SQLite.
- Whiteout-aware layer resolution.
- JSON and summary output.
- Trace output describing the process.
- A documented `ossec.conf`  configuration.
- Focused tests or validation commands showing parity with the Python s for package names.
