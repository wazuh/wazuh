# manager_certs — the `wazuh-manager-certs` CLI

Manager-only C++17 module that builds `bin/wazuh-manager-certs`, the one tool in the product that
reads and writes the CA bundle the HTTPS listener serves (`etc/certs/root-ca.pem` by default,
wherever `remote.https.ca_certificate` points). Today (issue #39319, stage E7b) it ships two
read-only commands — `inspect` (describe every certificate in the bundle plus its publication and
vouched status) and `check` (validate the bundle without writing anything, exit 0/1) — and the four
writing ones: `add <file>` (append certificates), `remove <identity>` (drop every copy of one),
`prune-expired` (drop what has expired) and `stamp` (publish the current contents unchanged). All
four go through the same transaction and publish a new generation. `--from-master`, for worker
nodes, arrives in a later stage.

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
│       └── stamp.cpp                 # `stamp`: the same certificates, a new publication
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
| `--version` / `-V` | nothing | — | 0 |
| `--help` / `-h` | nothing | — | 0 |

`-f <file>` picks the configuration file directly (default `<home>/etc/wazuh-manager.conf`);
`-H <home>` overrides the manager home used to resolve relative `ca_certificate`/`certificate`
paths (default `$WAZUH_MANAGER_HOME`, else the parent of the `bin/` directory holding the running
binary — the same `resolveHome()` shape as `wazuh-manager-conf`). `--version`/`--help` short-circuit
before either is ever consulted.

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

### Guards

In the order they are evaluated, and which commands they apply to:

| # | Guard | Refuses when | Commands | Exit |
|---|---|---|---|---|
| G0 | Not root | `geteuid() != 0` | all four | 2 |
| G7 | Cluster worker | `cluster.node_type` is `worker` (run `--from-master` there instead) | all four | 2 |
| GP | Existing bundle malformed | `parseBundle()` of the file on disk is not well formed | all four | 2 |
| GI | Input malformed or empty | same, for `<file>`, or it carries no certificates | `add` | 2 |
| G1 | Duplicate | identity already in the bundle, or repeated within `<file>` | `add` | 1 |
| G2 | Not a CA | `basicConstraints` says it is not | `add` | 1 |
| G3 | Date | `notBefore`/`notAfter` is not a valid ASN.1 time, or now is outside the window | `add` | 1 |
| — | Identity absent | `<identity>` is in the bundle zero times | `remove` | 1 |
| G4 | Count | the result would carry 0 or more than 6 certificates | all four | 1 |
| G6 | Chain | no certificate of the result chains to the served leaf | all four | 1 |
| G8 | Clock | the wall clock is behind the current publication | all four | 1 |
| G5 | Bytes | the result would serialise to more than 8191 bytes | all four | 1 |
| GH | Hash | the content hash of the result came out empty (defensive) | all four | 2 |

`stamp` deliberately does **not** apply `vouch()`'s `no_block`/`hash_mismatch`: those two are the
states it exists to fix (D-12). `prune-expired` with nothing expired stops before G4 — it writes
nothing and takes no generation (D-11).

No writing command creates the bundle: if `remote.https.ca_certificate` does not exist, they exit 2
asking for it to be provisioned and stamped — the installer expects that file to be provisioned
externally (`CheckListenerCerts()`), so creating one here would invent a trust anchor nobody asked
for.

Anything that runs while a write is in flight keeps working: `inspect`/`check` do not take the lock,
and the publish is a rename, so a reader sees the whole old bundle or the whole new one.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including `--version`/`--help`, `check` on a bundle it vouches for, and `add` after publishing) |
| 1 | The bundle or a certificate was rejected (cause on stderr), the identity `remove` was given is not in the bundle, or a CLI usage error (unknown option/command, missing argument) |
| 2 | Environment: configuration file not found, configuration invalid, CA bundle/leaf/input not found or not readable, a bundle that is not well formed, not running as root, or a write that failed (errno on stderr, destination untouched) |

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
| `tests/cli/manager_certs_cli_test.sh` (ctest `manager_certs_cli`) | `--version`/`--help` work with `$WAZUH_MANAGER_HOME` unset and no configuration anywhere (RF-10); `-f` to a missing file, a config whose bundle is missing, and a config whose leaf is missing each exit 2 — the three environment paths `runInspect()`/`runCheck()` never see, because they are pure functions over an already-parsed bundle. For `add` (root only, skipped otherwise): a worker refuses without leaving a lock file behind, a refused `add` leaves the bundle's bytes and mtime untouched with no temporary left, and **two real processes adding at once keep both certificates** — the one thing no in-process test can show. For the other three (root only): `stamp` turns a plain PEM into a bundle the binary's own `check` then accepts, `add` + `remove` round-trip a certificate by the identity `inspect` printed with strictly growing generations, a `remove` of an absent identity and a `prune-expired` with nothing expired both leave the bytes and the mtime alone (the second one still warning about an unpublished bundle), and all three refuse on a worker without leaving a lock file |

```bash
cmake -S $WAZUH_REPO/src -B $WAZUH_REPO/src/build -DUNIT_TEST=ON -DTARGET=manager
cmake --build $WAZUH_REPO/src/build -j --target manager_certs_utest wazuh-manager-certs
$WAZUH_REPO/src/build/shared_modules/manager_certs/tests/unit/manager_certs_utest
ctest --test-dir $WAZUH_REPO/src/build -L manager_certs -V
```

`-L manager_certs` is the module-wide ctest label and runs both registered tests: the GTest binary
and `manager_certs_cli`. `-L manager_certs_utest` selects the GTest alone — that is what the ASAN
job (`.github/workflows/5_testunit_managercerts.yml`) uses, since it never builds
`wazuh-manager-certs` itself.

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

**Why is there no JSON output flag?** Deliberately deferred (D-5/D38): today's only consumer is a
human running the tool at a terminal, and adding a machine-readable format ahead of a real consumer
would be a second output contract to keep in sync with the table for no one.

## Docs

- [`ca_bundle` README](../ca_bundle/README.md) — the bundle API this tool is built on
  (`parseBundle`, `vouch`, `describe`, the publication block format).
- [`manager_config` README](../manager_config/README.md) — the configuration loader
  (`Document::load()`) this tool's `main.cpp` uses to find the bundle and leaf paths.
