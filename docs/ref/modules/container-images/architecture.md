# Architecture

The **Container Images** module uses the same C and C++ split used by other Wazuh modules. The C layer lives inside `wazuh-modulesd` and handles configuration, lifecycle, dynamic loading, and logging. The C++ shared library contains the scan loop and image reader implementation.

> **Note:** This development stage covers module startup, image discovery from saved archives and OCI image layouts, package extraction for the `dpkg` and `apk` formats, logging, and local persistence of the inventory. RPM extraction, event generation, and synchronization are not part of this stage.

---

## Main Components

### **Configuration Parser**

The configuration parser reads the `<container_images>` block from `ossec.conf` and stores it in a `wm_container_images_t` structure.

The parser handles:

- `enabled`
- `scan_on_start`
- `interval`
- `references/archive`, `references/ref` and `references/local`

The three entry types are all accepted, and each is stored with its type, so the module reports the ones it cannot read yet instead of the configuration rejecting them.

The parser sets default values when the block is created:

| Field | Default |
|-------|---------|
| `enabled` | `yes` |
| `scan_on_start` | `yes` |
| `interval` | `1h` |
| `references` | empty |

### **Module Lifecycle (`wm_container_images`)**

The module lifecycle is managed by the `wm_context` callbacks used by `wazuh-modulesd`.

| Callback | Function | Description |
|----------|----------|-------------|
| `start` | `wm_container_images_main` | Loads and starts the shared library. |
| `stop` | `wm_container_images_stop` | Requests the shared library to stop. |
| `destroy` | `wm_container_images_destroy` | Frees module configuration. |
| `dump` | `wm_container_images_dump` | Dumps the active configuration as JSON. |
| `sync` | `NULL` | Not implemented in this stage. |
| `query` | `NULL` | Not implemented in this stage. |

### **Container Images Library**

The `libcontainer_images.so` library exposes a small C ABI and forwards calls to the C++ implementation.

| Layer | Responsibility |
|-------|----------------|
| C ABI (`container_images.h`) | Exported functions loaded by `wazuh-modulesd`. |
| `ContainerImages` | Singleton facade between the C ABI and C++ implementation. |
| `ContainerImagesImpl` | Scan loop, stop handling, and reader creation. |
| `IImageReader` | Source-specific discovery interface. |
| `ArchiveImageReader` | Reads saved image archives and OCI image layout directories. |
| `IByteStream` | Sequential byte source: a file, a member of an archive, and later a remote blob. |
| `LayerByteStream` | Decompresses a layer blob, or passes it through when it is a plain tar. |
| `LayerReader` | Streams the tar entries of one layer. |
| `LayerComposer` | Composes the layers of an image into the final state of its package databases. |
| `IPackageDbParser` | Package database format interface, implemented by `DpkgParser` and `ApkParser`. |

### **Reader Interface**

The `IImageReader` interface isolates source-specific discovery from the module orchestration logic. A reader returns discovered `ImageReferenceRecord` entries and identifies its source type.

The current implementation uses `ArchiveImageReader`. Future source types are added by implementing the same interface, and the reference type they serve is already part of the configuration grammar.

### **Archive Reader**

The reader identifies the input and reads its metadata. An OCI image layout is read from `index.json`; a saved image archive holds either that layout or the older `manifest.json` one.

For each image found, the reader:

1. Reads the index and resolves the manifest, following an image index for a multi-platform image. Entries whose platform is `unknown`/`unknown` (the convention buildx and containerd use for an attestation or provenance manifest) are skipped. Because the references table holds one row per reference (see [Data model](persistence.md#data-model)), an index or a saved archive naming more than one image after that filtering keeps the first deterministically and logs the rest as skipped; each image should be configured as its own `<archive>` reference to be inventoried.
2. Reads the image configuration blob and takes the platform fields from it.
3. Streams the layers in manifest order and keeps the package databases they carry.
4. Composes them and parses the result into package records.

Digest values and member names read from image metadata are validated before being used as path components, since both come from the image being scanned.

A saved archive is read twice: a tar is sequential, while the layer order comes from the metadata inside it. The first pass collects the metadata documents, the second reads the layers those documents named.

### **Registry Reader**

Reads an image from GitHub Container Registry or Amazon ECR. It implements the same reader interface as the archive reader, so the scan loop does not know which kind of source it is talking to.

The sequence is the one the registry advertises rather than one assumed of it:

1. An unauthenticated manifest request is answered with `401` and a `WWW-Authenticate` header naming the token endpoint, the service and the scope. A private Amazon ECR reference skips this step, see [Amazon ECR Private Authentication](#amazon-ecr-private-authentication), and Amazon ECR Public is read as the anonymous case above, with no credential ever sent.
2. A token is obtained from that endpoint: anonymously for a public repository, or with HTTP Basic and a credential read from the agent credential store for a private one. When the registry answers `401` or `403` to the token request that carries the credential, the reference is tried once more with an anonymous token, so a wrong credential does not fail the public references on the same host. If the registry serves the manifest that way, the reference is inventoried and one warning per scan and host reports the refusal. Otherwise the reference fails with the error of the credential. The same retry applies when a token is issued for the credential and the manifest request is then answered with `401` or `403`, as it is for a token without the scope the repository needs. A credential missing from the store, a transport failure and throttling get no anonymous retry. The token belongs to one reader, which is one reference, so the anonymous token cannot reach another reference. Only a refusal at the token endpoint is remembered for the rest of the scan, with the reason the registry gave, because it is the credential itself that was refused: the later references under the same registry and organization (`ghcr.io/owner`) are not sent the credential and ask for an anonymous token at once, and a private one among them is reported with the remembered reason. The memory is keyed by organization rather than host because a registry can answer per organization, so a refusal for one organization leaves the credential in use for the others on the same host. A refusal at the manifest speaks for one repository, so it is not remembered and the next reference sends the credential again. A manifest answered with `401` is reported as a rejected credential only when one was sent; with an anonymous token the registry is reported as requiring a credential for the reference. The warning is deduplicated separately and is logged once per scan and host for either kind. The scan's next run starts with nothing remembered.
3. The image index is fetched and the matching variant is selected: the architecture is the agent's, and the operating system is always `linux`, because an image is a Linux image whatever runs the engine. Build attestation entries, which carry no image content, are skipped.
4. The configuration digest is compared against the one already stored. When they match, nothing further is retrieved.
5. The configuration blob supplies the platform metadata, and each layer is streamed. A layer with a recognized compression this module cannot decompress is skipped with a warning, as the archive reader does, and the decompressed bytes read out of one layer are bounded at 8 GiB, which fails the reference when exceeded. The stop request is checked on every read of the decompressed bytes, so it does not wait for a large layer to finish.

The transport owns its own cURL handle rather than using the shared HTTP wrapper, because the registry flow needs two things that wrapper does not provide: the response headers, without which the advertised authentication method and `Retry-After` cannot be read, and incremental delivery, without which a layer would have to be held in memory in full.

Its security posture is set explicitly in one place: the peer and the host name are verified against a resolved certificate bundle, only `https` is allowed for a request and for anything it is redirected to, and the access token is not carried across a redirect to another host. That last one matters because a layer request is redirected off the registry to a content host which neither needs the token nor should receive it.

A request that produces no response is retried unless it would fail the same way again. The transport reports that on the response, and the reader attempts such a request once: peer verification and certificate bundle errors, a response over the size limit, a redirect loop and an unusable address or protocol. Every network-level failure stays retryable. A layer blob is requested as stored, with no content decoding by libcurl, so the bytes counted against the image ceiling are the bytes of the blob.

### **Registry Profiles**

The registry reader asks a small profile, chosen by the host of the reference, how a registry is authenticated. There are three, and no others: `ghcr.io`, `public.ecr.aws` and the private Amazon ECR hosts. The host is matched exactly, and the region of a private host is validated, because the host decides where a credential-derived value is sent.

| Profile | Authentication | Repository path |
|---------|----------------|-----------------|
| GHCR | Bearer token, anonymous or exchanged for a stored user name and token. | At least `owner/name`. |
| Amazon ECR Public | Bearer token, always anonymous. The realm must be `public.ecr.aws`. | At least `alias/name`. |
| Amazon ECR private | `Basic` with a token that comes from a signed AWS request. | One or more components. |

A profile also says which statuses can mean the credential was refused: `401` for the Bearer registries, and `400`, `401` or `403` for private ECR, which answered `400` and a `DENIED` body to a refused token. For private ECR those statuses are only a candidate: the token is dropped when the status is `401`, or when the body names the token as invalid or expired.

### **Amazon ECR Private Authentication**

A private registry does not issue its own token. It answers an unauthenticated request with a `Basic` challenge, and the password is obtained from AWS:

1. The reader looks up the `<registry>` entry for the host. With none, the reference fails before any request, naming the missing entry.
2. The token is taken from the shared token cache when one valid for ten more minutes is held for that host, credential key names and region.
3. Otherwise `EcrTokenClient` sends `GetAuthorizationToken` to `api.ecr.<region>.<domain>`, signed with AWS Signature Version 4 (`aws_sigv4`). The endpoint is built only from a region and a domain that passed strict validation, and the request is never redirected.
4. The token is stored in the cache with its expiry and sent as `Authorization: Basic <token>` on every request of the reference, the first one included.
5. When the registry refuses the token, as defined above, the cache entry is dropped, one new token is requested and the request is repeated. A second refusal fails the reference with the registry's reason. A refusal that does not name the token, such as a missing IAM permission, fails the reference with its reason and keeps the shared token, so it costs no further signed request. A refused layer has no body to read, so the manifest is requested again to learn which of the two it was. When `<region>` overrides the host's region and the registry refuses the token, the token is not renewed either, and the reason names both regions.

There is no anonymous retry for a private Amazon ECR registry: it has no anonymous access, so a refused credential is the answer and its error stands. What the retry does for GHCR, remembering a refusal for the rest of the scan, is kept for private ECR with a different scope. The refusal is remembered under the account host and the repository (`123456789012.dkr.ecr.us-east-1.amazonaws.com/my-backend`) and not under the host, because IAM grants access per repository and an account has no organizations. A later reference of the same repository, another tag for instance, then fails at once with the remembered reason, and nothing is requested. The other half of the memory is the credential itself. When AWS refuses it, with a `4xx` that is not throttling (an unknown access key id, a signature that does not match, an access denied on the token call), the reason is remembered under the account host, because it is the same for every repository of the account, and the later references of the scan fail with it at once. A mistyped secret then costs one signed call and one reason from AWS per scan, not one per reference. A server error, throttling and a call that got no answer say nothing about the credential and are not remembered. The memory ends with the scan, so a corrected store works at the next one. The shared token cache is untouched by the refusal memory.

`GetAuthorizationToken` follows the same retry rules as the token exchange of the other registries. A `5xx`, a `429` and the `ThrottlingException` AWS answers with `400` are retried with the usual back-off, waiting for `Retry-After` when AWS sends one and ending at once when the module is asked to stop. A call that was never answered and would fail the same way, a certificate that does not verify or a URL that is not usable, is tried once. The call carries no content decoding, as a blob does not.

The pieces are separate on purpose:

| Piece | Responsibility |
|-------|----------------|
| `aws_sigv4` | The signature, as pure functions of method, path, query, headers, payload, region, service and time. General, so the reference cases AWS publishes run against it unmodified. |
| `EcrTokenClient`, behind `IEcrTokenSource` | Builds and sends the `GetAuthorizationToken` call and reads the answer. The reader's tests replace it. |
| `RegistryTokenCache` | Tokens with an expiry, an injectable clock and a renewal margin. Owned by the module, not by a reader, so the references of one registry share a token. Only successes are stored. |
| `registry_errors` | Reads a registry error body and an AWS error into one reason that is safe to log. |

The token cache holds key names, never values, in its key. The signing key, the signature, the `Authorization` header, the token, the access key id and the secret are held in `Secret` objects or scrubbed after use, and none of them is logged at any level. The signed request is the only code that handles them together, and it does not throw with a message that contains an input. What stays outside that control is libcurl's own internal copy of a header while a request is in flight and the TLS send buffer, which this module cannot reach. Credentials are not encryption at rest in the store either, see [the credential store](configuration.md#what-the-credential-store-protects).

### **Registry Byte Stream**

Bridges libcurl, which pushes received bytes into a callback, to the byte-stream interface, which is pulled by the layer reader. The cURL multi interface is driven from inside `read()`, and the write callback answers `CURL_WRITEFUNC_PAUSE` once its buffer is full, suspending the transfer until the caller drains it. Everything happens on the caller's thread: no second thread and no locking.

The consequence is that memory is bounded by the suspend threshold rather than by the image size. Reading a 68 MB image measured 17 MB of peak resident memory.

A blob transfer carries no total wall-clock timeout, on purpose: the transfer is suspended whenever the caller is slower than the network, so a total ceiling would abort a healthy read of a large layer. It is bounded instead by a byte ceiling, by libcurl's stall detection, and by a no-progress bound that counts only time spent waiting for the network: it restarts whenever bytes arrive and does not run while the transfer is suspended or while the caller is parsing.

### **Layer Reader and Composition**

The layer reader consumes an `IByteStream` rather than a path, so the same code reads a layer from a file, from inside an archive, and later from a remote blob. `LayerByteStream` decides the compression from the blob's own first bytes rather than from the media type the image declares, which is metadata the image itself supplies. It decompresses the gzip and zstd layers the OCI image specification defines, and passes a plain tar through unchanged.

A blob compressed with something else that can be recognized from its signature, `xz`, `bzip2` or `lz4`, yields no bytes at all. That is deliberate: handing the compressed bytes to the tar reader would fail its header checksum and report a well-formed layer as malformed, so the stream stays empty and the reader reports the compression by name instead. Both readers check the compression before reading a layer, and both bound its decompressed size with the same constant. The archive reader treats a layer that reaches the bound as truncated and keeps what it read, and the registry reader fails the reference, since a remote image has no complete state to keep.

The reader parses the tar inline and supports the `ustar` prefix field, pax extended headers and GNU long names. Each entry is reported with a stream bounded to its content, and whatever the caller does not read is skipped, so an image costs the size of its package databases and nothing more.

Composition follows the OverlayFS rules, applied per layer in manifest order:

1. An opaque directory marker (`.wh..wh..opq`) hides what the earlier layers put under its directory.
2. A per-file marker (`.wh.<name>`) removes that path, and everything under it when it is a directory.
3. The files the layer itself carries override the earlier layers.

Only the tracked package database paths are kept: the image filesystem is never reconstructed.

### **Package Database Parsers**

Each format implements `IPackageDbParser` and registers the paths it owns, so a new format is added without changing the reader or the existing parsers. `dpkg` reports the stanzas whose status is `ok installed`; `apk` is read from both of its locations. The formats that are recognized but not parsed yet are reported once, and the image is inventoried with zero packages.

---

## Data Flow

### **Initialization Flow**

```mermaid
flowchart TD
    A[Agent starts] --> B[Parse container_images block]
    B --> C[Create wm_container_images_t]
    C --> D[Start wm_container_images_main]
    D --> E[Load libcontainer_images.so]
    E --> F[Resolve exported symbols]
    F --> G[Set log callback]
    G --> H[Initialize C++ implementation]
```

### **Scan Execution Flow**

```mermaid
flowchart TD
    A[container_images_start] --> B[ContainerImagesImpl::run]
    B --> C{scan_on_start?}
    C -- yes --> D[scanOnce]
    C -- no --> E[Wait interval]
    D --> E
    E --> F{stop requested?}
    F -- no --> D
    F -- yes --> G[Return from start]
```

During `scanOnce()`, the module processes each configured reference:

1. Read back what is stored for the reference, and create a reader for it, or report the reference type as unimplemented.
2. Identify the input and read its image metadata.
3. Stop there when the image still reports the configuration digest already stored: its contents cannot have changed, so its layers are not read and the stored inventory is kept.
4. Otherwise stream the layers of each image and compose its package databases.
5. Parse the databases into package records.
6. Store the references and their packages, reporting what changed since the previous scan.
7. Log the reference count and the package count.

### Reads that did not happen

A reader reports the outcome of its read, not just its result, because an empty result and a
failed read mean opposite things: the first says the reference holds nothing, the second says
nothing is known about it this time. The inventory is stored as one set covering every
reference, so a reference left out of that set is reported as deleted.

| Outcome | What the scan stores for that reference |
|---------|------------------------------------------|
| Read, holds images | What was read |
| Read, holds nothing | Nothing, so its records are reported as deleted |
| Could not be read | What is already stored, unchanged, with a warning |
| Still holds the stored digest | What is already stored, unchanged |

A scan cut short by a stop is abandoned rather than stored, for the same reason: it describes
only the references it reached. The stop is checked before each reference and again after the last
one, and a remote reference being read when it arrives fails whatever point its layer had reached
(a cut between two tar entries reads as the end of the layer), so no truncated inventory is synced
as complete.

---

## Threading Model

The module runs in the `wazuh-modulesd` module thread. `container_images_start()` blocks while the scan loop is active.

The interval wait is interruptible. When `container_images_stop()` is called, the implementation updates its running state and wakes the condition variable so the module can exit without waiting for the full interval.

---

## Event Types

This stage does not generate inventory events.

| Event type | Status | Notes |
|------------|--------|-------|
| Stateless alerts | Not implemented | Planned for later inventory changes. |
| Stateful events | Not implemented | Inventory is persisted locally; requires synchronization support. |
| Data clean notifications | Not implemented | Requires synchronization support. |

The current observable output is logging from the module scan flow.

---

## Image Reference Data

Discovered images are represented with `ImageReferenceRecord` entries:

| Field | Description |
|-------|-------------|
| `source.sourceType` | Reference type, `archive` at this stage. |
| `source.location` | Source location, such as the configured path. |
| `tag` | Name the image is known by. A saved image carries the whole reference in `io.containerd.image.name` and only the tag in `org.opencontainers.image.ref.name`, so the first is preferred. A remote reference is named `registry/repository[:tag][@digest]`, with the tag kept when a digest follows it. |
| `configDigest` | Image configuration blob digest. |
| `manifestDigest` | Manifest digest. |
| `os` | Operating system from the image configuration. |
| `architecture` | Architecture from the image configuration. |
| `variant` | Architecture variant, when present. |
| `osVersion` | Operating system version, when present. |
| `tags` | Every tag the image is known by, when the source lists more than one. A remote reference with a tag lists `registry/repository:tag`. |
| `packages` | The packages found in the image layers. |

---

## Integration Points

### **Build Integration**

- `src/wazuh_modules/container_images/CMakeLists.txt` builds `libcontainer_images.so`.
- `src/wazuh_modules/container_images/container_images_impl/CMakeLists.txt` builds the implementation library and tests.
- `src/wazuh_modules/CMakeLists.txt` builds the shared library for agent targets only. The C glue is compiled on every target, so the manager can parse and validate a `<container_images>` block.
- `src/init/inst-functions.sh` installs the shared library into the agent library directory.

### **Test Coverage**

The implementation includes:

- C++ tests for the byte streams, the tar variants, the composition rules, both package parsers, the supported inputs end to end, reader discovery, scan behavior, injected reader factories, no-source scans, and disabled-module behavior. The image inputs are built on disk by the tests.
- C tests for configuration parsing, defaults, every reference entry type, multiple references, invalid values, unknown entry names, and the Amazon ECR entry (valid, missing keys, invalid region, mixed tags, wrong host) and its configuration dump.
- C++ tests for the registry profiles and reference parsing, the AWS Signature Version 4 signature of the `GetAuthorizationToken` request, asserted against a value computed independently with Python, the request and its answers, the token cache lifetime with an injected clock, the error reasons, the reader against scripted registries (public, private, token reuse, renewal, refusal), and one test that runs the whole private flow with recognisable secrets and checks that no log line at any level carries a credential or a value derived from one.
