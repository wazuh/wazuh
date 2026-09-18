# ca_bundle — the CA bundle as a value

Static C++17 library over the manager's CA bundle (`etc/certs/root-ca.pem`): what certificates it
carries, what content they hash to, whether any of them signs the certificate the HTTPS listener
serves, and whether the bundle was stamped by `wazuh-manager-certs`. Pure functions over bytes and
`X509` objects — **no file reads, no logging, no configuration, no OpenSSL API in its public
header** (`X509` stays an incomplete type, as in remoted's `tlsCertificateStatus.hpp`).

It is not a certificate store, not a verifier (`X509_verify_cert` chain validation stays in
remoted's `chainValidates()`, which only informs the operator) and it never writes a file: the
caller reads the bundle — remoted through its own bounded, injectable reader — and only
`wazuh-manager-certs` writes one back.

Consumers: `remoted_module` (linked inside `libremoted_module.so`, see
[its README](../../remoted/remoted_module/README.md)) and, from PR 2 of issue #39319, the
`wazuh-manager-certs` tool. It exists because those two must answer the same questions with the
same code: the tool stamps a publication the manager then has to agree with, and two
implementations of "is this bundle publishable" would drift into an agent trusting a CA the
manager never vouched for.

## Requirements

### Functional

| ID | Requirement | Status |
|----|-------------|--------|
| RF-1 | `contentSha256()` identifies the SET of certificates: independent of their order in the document and of the PEM wrapping, sensitive to one changed byte | kept |
| RF-2 | `vouch()` returns a publication only when every guard passes, and otherwise 0 plus the first guard that failed, in a fixed order | kept |
| RF-3 | `parseBundle()` finds the publication block in any position of the document (the first complete one wins) and reports its absence as `nullopt` | kept |
| RF-4 | A document that is not well formed yields NO certificates at all (parity with the `parseCertificates()` this was extracted from) | kept |
| RF-5 | `renderBlock()` output round-trips through `parseBundle()`, and is loadable by OpenSSL and Python's `ssl` as an ordinary CA file | kept |

### Non-functional

| ID | Requirement | Status |
|----|-------------|--------|
| RNF-1 | OpenSSL only (the vendored `src/external/openssl`), no logging and no I/O: usable from a daemon thread and from a CLI alike | kept |
| RNF-2 | The public header pulls in `<openssl/types.h>` and nothing else of OpenSSL | kept |

## Design decisions

| ID | Decision | Why |
|----|----------|-----|
| D-1 | The hash covers the DER encodings **sorted by their own bytes**, concatenated | The publication has to survive an operator reordering or rewrapping the file; only the certificates themselves may change it (RF-1) |
| D-2 | The publication block is `##` comment lines, scanned in any position | `##` is a comment to every PEM reader, so a stamped bundle stays a valid CA file, and an operator may have appended a certificate after the stamp |
| D-3 | A block that is incomplete, or whose publication is not a number, is **no block** | Half a stamp is not a stamp: the bundle then reads as "never published" (INFO for the caller) rather than as broken (WARN), which is the distinction `no_block` vs the other guards carries |
| D-4 | `vouch()` fails with `no_ca_signs_leaf` when `leaf == nullptr` | With no served certificate to check against, nothing is vouched for — fail closed |
| D-5 | `serializedBytes` is a **parameter** of `vouch()`, not something it computes | The cap is about what the caller would actually hand out over HTTP, which only the caller knows (it may add nothing, or a legacy wrapper) |
| D-6 | `chainValidates()` stayed in remoted | It answers an operator-facing question (dates, constraints, purpose) that no decision of this library or of the tool depends on |
| D-7 | The library is STATIC and has no state | Two very different consumers (a long-lived daemon and a short-lived CLI); nothing here is worth a shared object or a singleton |

## Layout

```
src/shared_modules/ca_bundle/
├── include/ca_bundle/ca_bundle.hpp  # the whole public API (see below)
├── src/ca_bundle.cpp                # implementation; the PEM/DER/OpenSSL details live only here
├── test/
│   ├── ca_bundle_test.cpp           # ca_bundle_utest (GTest), suite CaBundleTest
│   ├── testPki.hpp                  # in-memory throwaway PKI (bounded copy, see Tests)
│   └── CMakeLists.txt               # ctest labels: ca_bundle_utest;ca_bundle
└── CMakeLists.txt                   # STATIC + `crypto` (vendored OpenSSL) PUBLIC
```

## Public API

| Symbol | What it answers |
|---|---|
| `X509Deleter` / `X509Ptr` | Owning `X509` handle; the type every bundle is a `std::vector` of |
| `parseBundle(pem) -> ParsedBundle` | The certificates, whether the document was understood whole (`wellFormed`), and the publication block if there is one |
| `serializeCertificates(certs) -> string` | The PEM document to publish: built from parsed objects, never forwarded bytes |
| `contentSha256(certs) -> string` | Lowercase hex SHA-256 of the sorted DER encodings (RF-1) |
| `identityOf(cert) -> string` | `"x509-sha256:<hex>"` of one certificate's DER, for logs and the registry |
| `anyCaSignsLeaf(leaf, cas) -> bool` | Whether the bundle would let an agent trust the served certificate (what decides `GET /cacerts`' 503) |
| `vouch(bundle, leaf, bytes) -> Vouch` | The publication to advertise, or 0 and the `GuardFailure` that refused (RF-2) |
| `renderBlock(block) -> string` | The eight `##` lines; only `wazuh-manager-certs` writes them |
| `describe(cert, leaf) -> CertificateFacts` | Subject, issuer, identity, validity window, `isCa`, `signsLeaf` — the tool's `inspect`/`check` |
| `kMaxCertificates` (6), `kMaxSerializedBytes` (8191) | The caps `vouch()` enforces |

`vouch()` evaluates in exactly this order and stops at the first failure:
`no_certificates` → `no_block` → `hash_mismatch` → `no_ca_signs_leaf` → `too_many_certificates` →
`too_many_bytes`. Callers name the cause in their logs and exit codes, so the order is part of the
contract, not an implementation detail.

## Consumer contract

- Link the CMake target `ca_bundle` (`target_link_libraries(<consumer> PRIVATE ca_bundle)`); its
  `PUBLIC` include directory propagates, so `#include "ca_bundle/ca_bundle.hpp"` needs nothing else.
  It brings the vendored OpenSSL (`crypto`) with it.
- `remoted::http` re-exports `X509Ptr`, `serializeCertificates` and `anyCaSignsLeaf` from
  `tlsCertificateStatus.hpp`, so remoted code keeps spelling them without a namespace change;
  `parseBundle()` is always called by its own name.
- Nothing here throws exceptions of its own: failures come back as empty strings, `nullopt`,
  `false` or a `GuardFailure`. The one exception that CAN escape is `std::bad_alloc`, from an
  allocation any of these functions may need to make (e.g. copying a certificate's DER encoding, or
  a hex digest, into a `std::string`) -- nothing here catches or works around that.

## Tests

`ca_bundle_utest` (`cmake --build $WAZUH_REPO/src/build -j --target ca_bundle_utest`, then the
binary in `src/build/shared_modules/ca_bundle/test/`, or `ctest -L ca_bundle`), suite
`CaBundleTest`:

| Area | Cases |
|---|---|
| `contentSha256` (RF-1) | Order- and PEM-format-independence; one changed DER byte changes the hash |
| `parseBundle` (RF-3, RF-4) | Block at the top / between certificates / after the last one; two blocks (the first wins); no block; five near-miss `##` shapes; truncated and non-base64 documents clear the certificates |
| `vouch` (RF-2) | One case per `GuardFailure` in its evaluation order, including `leaf == nullptr`, seven certificates and one byte over the size cap; and the success that returns the block's publication |
| `renderBlock` (RF-5) | The eight lines verbatim, and the round trip through `parseBundle()` |
| `identityOf` / `describe` | The identity against an independently computed SHA-256; subject/issuer/dates/`isCa`/`signsLeaf` coherent with `anyCaSignsLeaf()` |

`test/testPki.hpp` builds its certificates in memory (EC P-256, `X509_sign`) — a bounded copy of
`remoted_module/test/unit/testCertificates.hpp`, deliberately not a cross-module include: no shared
module includes another module's test headers. The SAN shapes and the private-key writer that file
carries are the listener's tests' business, not this library's.

RF-5's external half — that a stamped bundle is still a CA file to everyone else — cannot be
answered by a unit test, so it is checked against the real consumers: with `CA_BUNDLE_SEALED_DIR`
set to a directory, `CaBundleTest.RenderBlockRoundTripsThroughParseBundle` writes the sealed
`bundle.pem` and the `leaf.pem` it signs there, and that pair is then loaded with
`openssl storeutl -noout -certs`, verified with `openssl verify -CAfile bundle.pem leaf.pem` and
handed to Python's `ssl.create_default_context(cafile=...)`. Issue #39319 keeps that script and its
output as the stage's evidence.
