# manager_certs — the `wazuh-manager-certs` CLI

Manager-only C++17 module that builds `bin/wazuh-manager-certs`, the one tool in the product that
reads and writes the CA bundle the HTTPS listener serves (`etc/certs/root-ca.pem` by default,
wherever `remote.https.ca_certificate` points). Today (issue #39319, stage E8) it ships two
read-only commands — `inspect` (describe every certificate in the bundle plus its publication and
vouched status) and `check` (validate the bundle without writing anything, exit 0/1) — and the four
writing ones: `add <file>` (append certificates), `remove <identity>` (drop every copy of one),
`prune-expired` (drop what has expired) and `stamp` (publish the current contents unchanged). All
four go through the same transaction and publish a new generation. Since E8 it also ships
`--from-master`, the worker's side of the same file: it downloads the bundle its master publishes at
`GET /cacerts` over HTTPS — verified against this node's own bundle and nothing else — and installs
it under the generation the master announced.

Not a daemon and not `wazuh-manager-conf` (that tool validates/dumps the whole manager
configuration; this one only reads two of its keys to find the bundle and the leaf). It links
[`ca_bundle`](../ca_bundle/README.md) for every question about the bundle's certificates and
[`manager_config`](../manager_config/README.md) to read `/remote/https/ca_certificate` and
`/remote/https/certificate` from the effective configuration — both already documented, and not
duplicated here.

## Requirements

### Functional

| ID | Requirement | Status |
|----|-------------|--------|
| RF-10 | Installed binary `bin/wazuh-manager-certs` (`0750 root:wazuh-manager`); works with every daemon stopped; `--version`/`--help` never read the configuration | kept |
| RF-11 | `inspect`: per certificate subject, issuer, `notAfter`, days remaining, identity (`x509-sha256:<hex>`), whether it signs the leaf **on disk** (`remote.https.certificate`, C15 — not a running daemon's in-memory certificate); for the bundle, publication and whether the block vouches | kept |
| RF-12 | `check`: validates without writing (parsing, dates, CA capability, leaf coherence, limits), with distinct exit codes for valid/invalid | kept — see D-2 |
| RF-13 | `add <file>`: adds one or more certificates; refuses duplicates by identity, non-CAs and expired ones; refuses the 7th **naming the count** and the byte cap **naming the bytes**; refuses to leave the served leaf without a CA that signs it; atomic write with a rebuilt publication block; strictly increasing publication | kept — see D-6…D-9 |
| RF-14 | `remove <identity>`: drops **every** certificate with that identity, `prune-expired` drops every expired one; same guards as `add` (neither may leave the served leaf without an anchor), same atomic write and new publication | kept — see D-10, D-11 |
| RF-15 | `stamp`: publishes the current contents as they are (after the structural guards) — the first step for a hand-provisioned bundle, and the remedy for remoted's "not vouched" WARN | kept — see D-12 |
| RF-16 | Only the master publishes: `add`/`remove`/`prune-expired`/`stamp` refuse on a node whose `cluster.node_type` is `worker` | kept |
| RF-17 | `--from-master`: a **worker** downloads its master's published bundle over HTTPS, verifies it against its own leaf, and writes it locally under the generation the master's `Wazuh-CA-Generation` header announced (never this node's clock); equal is a no-op, behind is refused | kept — see D-13…D-15 |

### Non-functional

| ID | Requirement | Status |
|----|-------------|--------|
| RNF-1 | No JSON output flag: output is human-readable tables only (D38, `02-diseno.md` §2.6) | kept |
| RNF-2 | `inspect`/`check` never open the bundle for writing, and never take the write lock either | kept — see D-7 |
| RNF-3 | A refused write leaves the bundle byte for byte as it was (same SHA-256, same mtime), with no temporary left behind — and so does a write command that turns out to have nothing to do | kept — see D-8, D-10, D-11 |

## Design decisions

| ID | Decision | Why |
|----|----------|-----|
| D-1 | `runInspect()`/`runCheck()` (`include/manager_certs/commands.hpp`) are pure functions over an already-parsed `ca_bundle::ParsedBundle` and a leaf `X509*` — no file reads, no configuration | Lets `manager_certs_utest` exercise both commands in process, over synthetic PKI, with no compiled binary or filesystem fixture; `main.cpp` is the only thing that ever opens a file. The same shape carries into E7, which needs in-process GTest over the write guards too (C27) |
| D-2 | `check` runs `ca_bundle::vouch()`'s six guards first (structure, publication hash, leaf-signing, the two size caps — the same order `GET /cacerts` evaluates), then, only once those all pass, checks every certificate itself for `isCa` and its validity window (`notBefore <= now <= notAfter`) via `describe()`, in bundle order, stopping at the first failure of either group | RF-12/02-diseno.md §2.6 name "fechas"/`isCa` explicitly as part of `check`'s contract, and `vouch()` (§2.1) deliberately does not evaluate either — it answers "would `GET /cacerts` serve this", not "is every certificate still valid". A second implementation of `vouch()`'s own six guards would risk drifting from the one the manager itself vouches bundles against, so only the two properties it never checks are added on top, not duplicated |
| D-3 | `main.cpp` resolves the leaf certificate from disk (`remote.https.certificate`), not from a running daemon | RF-10/C15: the tool has to work with every daemon stopped; the leaf on disk is also what remoted will load on its next start, so `check`/`inspect` answer "would the next restart be fine", not "is the running listener fine right now" — the gap between the two is a restart, and that's a runbook note, not a bug |
| D-4 | `main.cpp` loads the configuration with `LoadOptions::checkFiles = false` and does its own existence/readability checks for the bundle and the leaf, each with its own message | `manager_config`'s own `checkFiles` guard never looks at `/remote/https/ca_certificate` at all (it does check `/remote/https/certificate`), so relying on it would collapse "leaf missing" into "configuration invalid" and leave "bundle missing" uncaught. Three separate checks keep "config unreadable", "bundle missing" and "leaf missing" distinguishable exit-2 causes |
| D-5 | No JSON output flag | D38 of the ca_rotation plan: deliberately deferred — issue #39320 (or a new one) if a programmatic consumer turns out to need it |
| D-6 | Writing is a three-part transaction, not a function: `prepareWrite()` (lock + open the bundle once + parse it), the command itself (`add`: build the candidate, refuse its own input), `finishWrite()` (the guards every writing command shares, then the atomic write). All three in `include/manager_certs/commands.hpp` | The guards that matter are about the RESULT, not the input (C29): after a successful write, `ca_bundle::vouch()` over the file returns the publication just written. Sharing `finishWrite()` is what keeps `remove`/`prune-expired`/`stamp` from each growing their own copy of the count, byte, chain and clock guards |
| D-7 | One exclusive `flock(LOCK_EX)` over `<bundle>.lock` covers read → validate → write. `inspect`/`check` do **not** take it | Two root processes publishing at once both read the same bundle and the second rename wins, so one operator's CA disappears (C34f). Readers are a different matter: the publish is a `rename(2)`, so a reader sees the whole old file or the whole new one and must never block behind a writer. The lock file is a **permanent, empty file beside the bundle** — it is not a certificate, nothing parses it, and removing it while a command runs only costs that command its exclusion |
| D-8 | The new bundle is written to `<bundle>.tmp.<16 hex>` in the same directory and `renameat(2)`d over the destination, carrying its owner and mode across; any failure before the rename unlinks **our** temporary and exits 2 with the errno, leaving the destination untouched. A failed `fsync` of the **directory**, after a rename that already happened, is success with a warning | RF-8/CA-19: the bundle is the fleet's trust anchor, so a half-written file must never be visible and a refused write must not cost the operator the file they had. The nonce is random rather than PID + counter because a crashed run can leave every `pid.0..9` name taken, and `O_EXCL` would then refuse every attempt (C36c). Steps, flags and the failure matrix: `ca_rotation/anexos/e7/escritura-atomica.md` |
| D-9 | The publication is the wall clock, never a future timestamp: if it equals the current publication — or the bundle carries none at all — the tool **waits for the next second** and publishes that; if it is behind the current publication it refuses (C28b/C36e). The wait is bounded with `CLOCK_MONOTONIC`, and the time-sensitive guards (the added certificates' dates, and "a CA still chains to the leaf") are evaluated **again** after it | A publication is the generation agents compare, so it has to be strictly increasing without ever being in the future, and two `add`s in the same second must not both publish the same number (CA-24/CA-25). Re-checking after the wait is what keeps D-6's invariant true: a CA that expired during that second would otherwise be published and rejected by `vouch()` a millisecond later |

| D-10 | `remove <identity>` drops **every** certificate with that identity, not the first; an identity the bundle does not carry is exit 1 with nothing written and **no new generation** | "Removed" has to mean the anchor is gone: a bundle that somehow lists the same CA twice (two operators, a hand-edited file) would otherwise keep serving it while the operator was told it was dropped (C34d). And republishing for a change that did not happen costs the whole fleet a `GET /cacerts` for nothing |
| D-11 | `prune-expired` with nothing expired **writes nothing at all** (exit 0, `nothing to prune`) — but audits the publication first and warns when the bundle is unstamped or its `Content-SHA256` is stale | C35: this is the command that goes in cron, and a new generation over unchanged bytes sends every agent back to `GET /cacerts` every night. C36i: staying silent on that path would let an operator read "nothing to prune" as "everything is published" — so it names the problem and the command that fixes it (`stamp`), still without writing |
| D-12 | `stamp` applies only the **structural** guards every writing command shares (G4/G6/G5/G8/GH) — never `vouch()`'s `no_block` or `hash_mismatch` | Those two states — a plain PEM that was never stamped, and a block that no longer describes its certificates — are exactly what `stamp` exists to fix (C29/CA-29). Refusing them here would leave a tool that only works once the problem is already solved, and the block it writes satisfies both by construction |
| D-13 | `--from-master` takes the write lock **before** it reads the local bundle and before it connects, and holds it for the whole download (up to the 10 s timeout) | The local bundle is what verifies the master's certificate. Taken afterwards, a concurrent `remove` could drop the very CA the handshake was authenticated with between the TLS session and the write, and this node would install material vouched for by an anchor it had just stopped trusting (C39d). The cost — other writers wait while a download runs — is the same trade-off C28b already accepts for the publication wait |
| D-14 | The publication written is the master's header, not this node's clock: `finishWrite()` takes an `explicitPublication` that skips **G8 and only G8** | A generation is a number the whole cluster compares, so a worker that minted its own would tell its agents about a bundle nobody else knows (C37b). Everything else still runs against THIS node's material: G4, G6 (the leaf here, never anything from the response), G5 and GH — a bundle the master is perfectly happy with can still be one this worker must not serve, and `managerCertsFromMaster_test.cpp` has a rejection case for each of those four |
| D-15 | Every libcurl option that decides what the connection trusts is set **and checked**: `CAINFO_BLOB` (the local bundle, as a blob, never a path), `CAPATH` cleared, `VERIFYPEER`/`VERIFYHOST`, `PROXY` emptied, no redirects, a 10 s timeout, and only `CURLINFO_RESPONSE_CODE == 200` counts | A `setopt` whose return nobody reads is a silent bypass: with the blob refused (a zero-length one is), libcurl falls back to this build's compiled-in CA file and the fleet's trust anchor quietly becomes whatever is in `/etc` (C39a). `CAPATH` is an independent source the blob does not replace; an inherited proxy can answer with a generation header of its own; and libcurl does not fail on a 302/206/500, whose body must never be read as a bundle (C39b). Detail and anchors: `ca_rotation/anexos/e8/tls-transporte.md` |

## Layout

```
src/shared_modules/manager_certs/
├── CMakeLists.txt                    # manager_certs_core STATIC + wazuh-manager-certs executable
├── include/manager_certs/commands.hpp # inspect/check + the write transaction and its seams
├── src/
│   ├── main.cpp                      # CLI: arg parsing, home/config resolution, exit-code mapping
│   └── commands/
│       ├── inspect.cpp
│       ├── check.cpp
│       ├── writeLock.{hpp,cpp}       # BundleWriteLock: the exclusive lock (private header)
│       ├── atomicWrite.{hpp,cpp}     # atomicWrite() + prepareWrite()/finishWrite() + G0/G7
│       ├── add.cpp                   # `add`: GI/G1/G2/G3 and the candidate it hands to finishWrite()
│       ├── remove.cpp                # `remove`: every occurrence of one identity
│       ├── pruneExpired.cpp          # `prune-expired`: the expired ones, or nothing at all (C35)
│       ├── stamp.cpp                 # `stamp`: the same certificates, a new publication
│       ├── masterTransport.{hpp,cpp} # the hardened HTTPS GET, over libcurl (private header)
│       └── fromMaster.cpp            # `--from-master`: the worker's twelve guards, in order
└── tests/
    ├── CMakeLists.txt
    ├── unit/
    │   ├── CMakeLists.txt            # target manager_certs_utest; registers manager_certs_cli too
    │   ├── managerCerts_test.cpp     # inspect/check
    │   ├── managerCertsWrite_test.cpp # lock, atomic write, add
    │   └── managerCertsWriteRemoveStampPrune_test.cpp # remove, prune-expired, stamp
    ├── testPki.hpp                   # in-memory throwaway PKI (bounded copy, see Tests)
    └── cli/manager_certs_cli_test.sh # end-to-end: the compiled binary, ctest `manager_certs_cli`
```

## Command reference

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `inspect` | bundle, leaf | — | always 0 |
| `check` | bundle, leaf | — | 0 valid, 1 rejected (guard named on stderr) |
| `add <file>` | bundle, leaf, `<file>` | bundle, `<bundle>.lock` | 0 published (new generation on stdout), 1 refused (guard named on stderr), 2 environment |
| `remove <identity>` | bundle, leaf | bundle, `<bundle>.lock` | 0 published, 1 refused or the identity is not in the bundle, 2 environment |
| `prune-expired` | bundle, leaf | bundle, `<bundle>.lock` (nothing at all when nothing expired) | 0 published **or** nothing to prune, 1 refused, 2 environment |
| `stamp` | bundle, leaf | bundle, `<bundle>.lock` | 0 published, 1 refused, 2 environment |
| `--from-master [--master <host>] [--port <port>]` | bundle (as its trust material), leaf, the master's `GET /cacerts` | bundle, `<bundle>.lock` | 0 installed **or** already at that generation, 1 refused (not vouched, behind, or a guard), 2 environment (not a worker, unreachable, TLS, not a complete 200, unreadable header, unparsable body) |
| `--version` / `-V` | nothing | — | 0 |
| `--help` / `-h` | nothing | — | 0 |

`-f <file>` picks the configuration file directly (default `<home>/etc/wazuh-manager.conf`);
`-H <home>` overrides the manager home used to resolve relative `ca_certificate`/`certificate`
paths (default `$WAZUH_MANAGER_HOME`, else the parent of the `bin/` directory holding the running
binary — the same `resolveHome()` shape as `wazuh-manager-conf`). `--version`/`--help` short-circuit
before either is ever consulted.

`--from-master` is an option, not a command word, and takes no argument of its own; `--master
<host>` and `--port <port>` only mean anything beside it (they override `/cluster/nodes[0]` and
`/remote/https/port`, which is what the URL is otherwise built from, together with
`/remote/https/global_prefix`).

### `inspect` example

Two CAs, the first signs the served leaf, the bundle is sealed and vouches:

```
$ wazuh-manager-certs inspect
subject: /CN=root-ca-2026
issuer: /CN=root-ca-2026
notAfter: 2027-09-18T00:00:00Z (365 days remaining)
identity: x509-sha256:3f9c1e...
signsLeaf: yes

subject: /CN=root-ca-2025
issuer: /CN=root-ca-2025
notAfter: 2026-12-01T00:00:00Z (74 days remaining)
identity: x509-sha256:7ab1de...
signsLeaf: no

publication: 1758150000
vouched: yes
```

A plain PEM with no publication block prints `publication: 0 (unpublished)` and `vouched: no`
instead of the last two lines above.

### `check` example

Silent on success:

```
$ wazuh-manager-certs check; echo $?
0
```

One line on stderr, naming the guard, on rejection — `ca_bundle::vouch()`'s own guards name the
failure in words or, for the two size caps, the observed count/bytes against the limit:

```
$ wazuh-manager-certs check; echo $?
wazuh-manager-certs: check: 7 certificates (max 6)
1
```

A certificate that is expired, not yet valid, or not a CA is named by its identity instead (D-2 —
these are `check`'s own guards, evaluated only once every `vouch()` guard above has passed):

```
$ wazuh-manager-certs check; echo $?
wazuh-manager-certs: check: x509-sha256:3f9c1e...: expired (notAfter 2026-09-17T00:00:00Z)
1
```

### `add` example

```
$ wazuh-manager-certs add /root/new-root-ca.pem; echo $?
added 1 certificate(s); published generation 1789840000
0
```

One line on stderr and nothing written, on a refusal — the certificate is named by its identity for
the guards that are about one certificate, and by the number for the two limits:

```
$ wazuh-manager-certs add /root/new-root-ca.pem; echo $?
wazuh-manager-certs: add: x509-sha256:3f9c1e...: duplicate of an existing certificate
1
```

### `remove` / `prune-expired` / `stamp` examples

The identity is the one `inspect` prints, `x509-sha256:<hex>`, and **every** copy of it goes:

```
$ wazuh-manager-certs remove x509-sha256:3f9c1e...; echo $?
removed 1 certificate(s); published generation 1789840123
0

$ wazuh-manager-certs remove x509-sha256:000000...; echo $?
wazuh-manager-certs: remove: identity x509-sha256:000000... not found in bundle
1
```

`prune-expired` with nothing expired writes nothing and publishes nothing — and says so instead of
raising a generation the whole fleet would have to re-fetch for identical bytes:

```
$ wazuh-manager-certs prune-expired; echo $?
nothing to prune
0
```

On that same path it still checks whether the bundle is actually published, so a nightly cron job
cannot quietly hide an unstamped one:

```
$ wazuh-manager-certs prune-expired; echo $?
wazuh-manager-certs: prune-expired: bundle is not vouched; run 'stamp' to publish it
nothing to prune
0
```

`stamp` publishes what is already there: it is what turns a hand-provisioned PEM into a bundle
remoted vouches for, and the remedy for its "not vouched" WARN.

```
$ wazuh-manager-certs stamp; echo $?
stamped 2 certificate(s); published generation 1789840456
0
```

### `--from-master` example

On a worker, with the master reachable at the configured `cluster.nodes[0]` and
`remote.https.port`. The generation written is the master's, so both nodes answer `GET /cacerts`
with the same number, and running it again changes nothing:

```
$ wazuh-manager-certs --from-master; echo $?
installed 2 certificate(s) from https://10.0.0.1:1517/wazuh-manager/cacerts; published generation 1789840456
0
$ wazuh-manager-certs --from-master; echo $?
already at generation 1789840456; nothing to do
0
```

A master that never stamped its own bundle announces generation 0, and there is nothing to adopt:

```
$ wazuh-manager-certs --from-master; echo $?
wazuh-manager-certs: --from-master: the master's bundle is not vouched for (generation 0); run 'wazuh-manager-certs stamp' there first
1
```

### Guards

In the order they are evaluated, and which commands they apply to:

| # | Guard | Refuses when | Commands | Exit |
|---|---|---|---|---|
| G0 | Not root | `geteuid() != 0` | all four + `--from-master` | 2 |
| G7 | Cluster worker | `cluster.node_type` is `worker` (run `--from-master` there instead) | all four | 2 |
| G7' | Not a cluster worker | `cluster.node_type` is anything but `worker` — the mirror of G7 | `--from-master` | 2 |
| GP | Existing bundle malformed | `parseBundle()` of the file on disk is not well formed | all four + `--from-master` | 2 |
| GI | Input malformed or empty | same, for `<file>`, or it carries no certificates | `add` | 2 |
| G1 | Duplicate | identity already in the bundle, or repeated within `<file>` | `add` | 1 |
| G2 | Not a CA | `basicConstraints` says it is not | `add` | 1 |
| G3 | Date | `notBefore`/`notAfter` is not a valid ASN.1 time, or now is outside the window | `add` | 1 |
| — | Identity absent | `<identity>` is in the bundle zero times | `remove` | 1 |
| G4 | Count | the result would carry 0 or more than 6 certificates | all four + `--from-master` | 1 |
| G6 | Chain | no certificate of the result chains to the served leaf | all four + `--from-master` | 1 |
| G8 | Clock | the wall clock is behind the current publication | all four (**never** `--from-master`, D-14) | 1 |
| G5 | Bytes | the result would serialise to more than 8191 bytes | all four + `--from-master` | 1 |
| GH | Hash | the content hash of the result came out empty (defensive) | all four + `--from-master` | 2 |

`stamp` deliberately does **not** apply `vouch()`'s `no_block`/`hash_mismatch`: those two are the
states it exists to fix (D-12). `prune-expired` with nothing expired stops before G4 — it writes
nothing and takes no generation (D-11).

No writing command creates the bundle: if `remote.https.ca_certificate` does not exist, they exit 2
asking for it to be provisioned and stamped — the installer expects that file to be provisioned
externally (`CheckListenerCerts()`), so creating one here would invent a trust anchor nobody asked
for.

Anything that runs while a write is in flight keeps working: `inspect`/`check` do not take the lock,
and the publish is a rename, so a reader sees the whole old bundle or the whole new one.

`--from-master` runs twelve guards in one fixed order, and the download sits in the middle of them
(`ca_rotation/anexos/e8/tls-transporte.md` §8): G0 + G7' → **the lock** → the local bundle read
through it (empty ⇒ exit 2, there would be nothing to verify the master with) → the URL, built from
components → the fetch → a failed fetch or anything that is not a complete 200 ⇒ exit 2 → the
generation header (absent or unreadable ⇒ 2, a readable `0` ⇒ 1) → equal to ours ⇒ 0, behind ours ⇒
1 → `parseBundle()` of the body (malformed ⇒ 2) → a publication block in the body that disagrees
with the header ⇒ 1 → `finishWrite()` with the master's generation, which still runs G4, G6, G5 and
GH against this node's own leaf.

Nothing relaxes the verification of the master: there is no flag for it, the trust material is this
node's own bundle (as an in-memory blob, so libcurl never opens a file outside the 1 MiB cap), the
response is capped at 1 MiB checked before each chunk is appended, and the body is treated as
untrusted input throughout — the chain is verified against the LOCAL leaf, never against anything
that arrived in the response.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including `--version`/`--help`, `check` on a bundle it vouches for, and `add` after publishing) |
| 1 | The bundle or a certificate was rejected (cause on stderr), the identity `remove` was given is not in the bundle, or a CLI usage error (unknown option/command, missing argument) |
| 2 | Environment: configuration file not found, configuration invalid, CA bundle/leaf/input not found or not readable, a bundle that is not well formed, not running as root, or a write that failed (errno on stderr, destination untouched). For `--from-master` also: this node is not a worker, the local bundle is empty, the master is unreachable or its certificate is not verified by the local bundle, the answer is not a complete 200, the generation header is missing or unreadable, or the downloaded body does not parse |

The rule behind the split, for every command: **what we could not read or parse is 2; what we read
fine and may not accept is 1.**

## Consumer contract

- `manager_certs_core` (STATIC) links `ca_bundle` **PUBLIC** — its include directory and the
  vendored `crypto` archive propagate to whoever links this target, which is exactly what
  `manager_certs_utest` relies on to build its own PKI fixtures. `wazuh-manager-certs` additionally
  links `manager_config` and `ext_rapidjson` **PRIVATE**: only `main.cpp` needs configuration
  parsing, so `manager_certs_core` (and its tests) do not pull those in.
- The executable is built in every CMake mode, including `UNIT_TEST=ON` — not just release — so
  `tests/cli/manager_certs_cli_test.sh` always has a fresh binary to exercise. It is **not** an
  automatic build dependency of `manager_certs_utest` itself (same precedent as
  `manager_config_utest`/`wazuh-manager-conf`): build both explicitly, e.g.
  `cmake --build $WAZUH_REPO/src/build -j --target manager_certs_utest wazuh-manager-certs`.
- Installed `0750 root:wazuh-manager` by `InstallLocal()` (`src/init/inst-functions.sh`, right
  after `wazuh-manager-conf`) and listed in `packages/rpms/SPECS/wazuh-manager.spec`. The deb
  `postinst` needs no change — it does not enumerate installed binaries individually, the same
  precedent `wazuh-manager-conf` already established.

## Tests

| File | Invariant it pins |
|------|-------------------|
| `tests/unit/managerCerts_test.cpp` (`manager_certs_utest`, suites `ManagerCertsInspect`/`ManagerCertsCheck`) | `inspect` lists both certificates of a sealed 2-CA bundle with `vouched: yes`, and reports `publication: 0 (unpublished)` for a plain PEM; `check` returns 0 and never touches the file on a valid bundle, returns 1 naming the guard for `too_many_certificates` (7 certificates) and `no_ca_signs_leaf` from `vouch()`, and — once `vouch()` passes — returns 1 naming the certificate's identity for an expired certificate and for one that is not a CA (RF-12, D-2) |
| `tests/unit/managerCertsWrite_test.cpp` (suites `BundleWriteLock`/`AtomicWrite`/`ManagerCertsAdd`) | The lock blocks a second writer, refuses a symlinked or non-root lock file, and notices one replaced while it waited; `atomicWrite()` preserves owner and mode, aborts when the destination changed since it was read, survives ten runs with every `pid.0..9` temporary name already taken, never lets a concurrent reader see a partial file, and — one case per row of the failure matrix — leaves the destination byte for byte intact when any syscall before the rename fails (a failed `fsync` of the directory afterwards is success with a warning); `add` waits for the next second and publishes strictly increasing generations, refuses a clock behind the publication or moved backwards during the wait, refuses duplicates (in the bundle and within the input), non-CAs, expired and unreadable dates, the 7th certificate, an oversized result and one that would leave the leaf unsigned, re-checks dates and the chain **after** the wait, and — the happy path — writes a bundle whose `vouch()` returns exactly the new publication with owner and mode preserved |
| `tests/unit/managerCertsWriteRemoveStampPrune_test.cpp` (suites `ManagerCertsRemove`/`ManagerCertsPruneExpired`/`ManagerCertsStamp`) | `remove` drops **every** copy of a duplicated identity (`{A,A,B}` → `{B}`), refuses an identity the bundle does not carry without republishing, refuses removing the only CA that chains to the leaf (CA-28) and refuses a removal that would still leave 7 certificates; `prune-expired` keeps the signing CA while dropping the expired one, refuses a prune whose result is still oversized or empty, and — with nothing expired — writes **nothing** (same SHA-256 **and** mtime, same generation, no wait) while warning when the bundle is unstamped or its hash is stale (C35/C36i); `stamp` publishes a plain PEM and the file it writes parses back with the same certificates and a `vouch()` that returns exactly the new publication (C29/CA-29); all three refuse on a worker (CA-30) |
| `tests/unit/managerCertsFromMaster_test.cpp` (suites `ManagerCertsFromMaster`/`ManagerCertsMasterTransport`) | Through the `MasterTransport` seam: a higher generation is installed and `vouch()` over the result returns exactly the master's number, the chain is validated against the LOCAL leaf (a CA fabricated in the response proves nothing), `0` and a generation behind ours are exit 1, an equal one is a no-op, a missing or non-numeric header is exit **2** (C38b), a body that does not parse is 2, and a body whose publication block disagrees with the header is 1; the four cases that prove skipping G8 skipped nothing else — a candidate with no CA for this leaf, 0 certificates, 7 certificates and an oversized serialisation, all under an explicit publication — are exit 1 with the local bundle unchanged; plus the URL built from components (the default prefix without `//`, IPv6 bracketed) and every unusable address refused without connecting. Through the `CurlPort` seam: every option that decides what the connection trusts, with its value (blob = the local bundle, `CAPATH` cleared, `VERIFYPEER` 1, `VERIFYHOST` 2, `PROXY` empty, no redirects, 10 s), that a refused `setopt` ends the run **before** `curl_easy_perform()`, that only a 200 counts, that the cap drops a crossing chunk whole, and that only the last response's generation header survives |
| `tests/component/manager_certs_from_master_test.sh` (ctest `manager_certs_from_master`) | The compiled binary against a real `SSLServer` (`tests/testHttpsMaster.hpp`), over a real handshake — the part no seam can fake (C39h): a master signed by a CA this node does not carry, one with the wrong identity, one trusted **only** through `SSL_CERT_FILE`/`SSL_CERT_DIR`, and an empty local bundle are all exit 2 with the bundle untouched, while an inherited `https_proxy` pointing nowhere is ignored and the pull still succeeds; a 1 MiB body exactly at the cap is installed, 1 MiB + 1 is refused (in one response and across two chunks alike), a body that stops halfway is refused, 302/500/206 with a perfectly valid payload are refused; the configured prefix produces `/wazuh-manager/cacerts` (no `//`), `--master ::1` produces `https://[::1]:<port>/…`, an unreachable port names `--port` and the `scp` fallback, and running it on a master refuses without leaving a lock file |
| `tests/cli/manager_certs_cli_test.sh` (ctest `manager_certs_cli`) | `--version`/`--help` work with `$WAZUH_MANAGER_HOME` unset and no configuration anywhere (RF-10); `-f` to a missing file, a config whose bundle is missing, and a config whose leaf is missing each exit 2 — the three environment paths `runInspect()`/`runCheck()` never see, because they are pure functions over an already-parsed bundle. For `add` (root only, skipped otherwise): a worker refuses without leaving a lock file behind, a refused `add` leaves the bundle's bytes and mtime untouched with no temporary left, and **two real processes adding at once keep both certificates** — the one thing no in-process test can show. For the other three (root only): `stamp` turns a plain PEM into a bundle the binary's own `check` then accepts, `add` + `remove` round-trip a certificate by the identity `inspect` printed with strictly growing generations, a `remove` of an absent identity and a `prune-expired` with nothing expired both leave the bytes and the mtime alone (the second one still warning about an unpublished bundle), and all three refuse on a worker without leaving a lock file |

```bash
cmake -S $WAZUH_REPO/src -B $WAZUH_REPO/src/build -DUNIT_TEST=ON -DTARGET=manager
cmake --build $WAZUH_REPO/src/build -j --target manager_certs_utest wazuh-manager-certs
$WAZUH_REPO/src/build/shared_modules/manager_certs/tests/unit/manager_certs_utest
ctest --test-dir $WAZUH_REPO/src/build -L manager_certs -V
```

`-L manager_certs` is the module-wide ctest label and runs all three registered tests: the GTest
binary, `manager_certs_cli` and `manager_certs_from_master`. `-L manager_certs_utest` selects the
GTest alone — that is what the ASAN job (`.github/workflows/5_testunit_managercerts.yml`) uses,
since it never builds `wazuh-manager-certs` itself. The two script tests write the bundle, so they
need root and skip themselves without it; the component one additionally needs its own server
binary:

```bash
cmake --build $WAZUH_REPO/src/build -j --target manager_certs_utest wazuh-manager-certs manager_certs_test_master
```

`tests/testHttpsMaster.hpp` is the other side of the wire: a cpp-httplib `SSLServer` whose response
shape (status, generation header, body size, chunking, a deliberately truncated body) is what the
component test's matrix varies. It is a bounded copy of the idiom in
`src/client-agent/https_client/tests/component/fakeManager.hpp`, for the same reason `testPki.hpp`
is a copy, and it links nothing of the module under test.

`tests/testPki.hpp` builds its certificates in memory (EC P-256, `X509_sign`, dates relative to
`now()` so nothing expires in CI) — a bounded copy of `ca_bundle/test/testPki.hpp`, itself
documented there as a bounded copy of `remoted_module`'s test certificate builder: no shared module
includes another module's test headers.

## Developer FAQ

**Why isn't the expiry/`isCa` check part of `ca_bundle::vouch()`?** Because `vouch()` answers a
narrower, reused question — "may this bundle be served as this leaf's trust anchor right now" — the
same one `GET /cacerts` asks, where a CA past its `notAfter` that still cryptographically signs the
leaf is not remoted's problem to refuse (an operator rotates it; the endpoint keeps serving in the
meantime). `check`'s contract is wider (RF-12), so it asks `vouch()` first and then asks `describe()`
about every certificate itself (D-2), instead of teaching `ca_bundle` a stricter notion of "valid"
that `GET /cacerts` never needed.

**Why don't `inspect` and `check` take the write lock?** Because they would gain nothing and cost
availability. The publish is a `rename(2)`, so a reader either sees the whole previous bundle or the
whole new one — never a mixture — and making readers queue behind a writer would mean a diagnostic
command hanging exactly when an operator is trying to understand a write that is stuck. The lock
exists to keep two WRITERS from overwriting each other (D-7).

**Is there any way to make `--from-master` skip the TLS verification?** No — there is no flag, no
environment variable and no configuration option that relaxes it, and that is deliberate (CA-33).
The master's certificate is verified against this node's own CA bundle and nothing else: not the
host's system store, not `SSL_CERT_FILE`/`SSL_CERT_DIR`, not a CA directory a distribution's curl
build might have been pointed at, and not anything that arrives in the response. If the handshake
fails, the honest fixes are to give this node the CA that signs the master's listener (`add`, then
`check`) or to copy the bundle across by hand (`scp`, `add`, `check`) — both of which leave an
operator in control of what this worker's agents will trust. The component test exercises each of
those refusals against a real server, so the answer cannot quietly stop being true.

**Why is there no JSON output flag?** Deliberately deferred (D-5/D38): today's only consumer is a
human running the tool at a terminal, and adding a machine-readable format ahead of a real consumer
would be a second output contract to keep in sync with the table for no one.

## Docs

- [`ca_bundle` README](../ca_bundle/README.md) — the bundle API this tool is built on
  (`parseBundle`, `vouch`, `describe`, the publication block format).
- [`manager_config` README](../manager_config/README.md) — the configuration loader
  (`Document::load()`) this tool's `main.cpp` uses to find the bundle and leaf paths.
- [CA Rotation Runbook](../../../docs/ref/modules/remoted/ca-rotation.md) — the operator-facing
  procedure this tool is built for: the fixed step order across `add`/`--from-master`/`remove`, why
  it cannot be reordered, and how to read `ca_generation`.
