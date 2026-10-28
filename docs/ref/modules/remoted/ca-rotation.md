# CA Bundle Rotation Runbook

How to rotate the CA that signs `wazuh-manager-remoted`'s HTTPS listener without ever taking `GET
/cacerts` down for the fleet — the order that must not change, the four ways to get it wrong, and
what the manager tells you along the way. For every command, flag, guard and exit code named here,
`wazuh-manager-certs`'s developer README (`src/shared_modules/manager_certs/README.md` in the source
tree) is the authoritative reference; this page does not repeat its command table or examples. The
tool is installed as `/var/wazuh-manager/bin/wazuh-manager-certs` (`root:wazuh-manager 0750`), runs
as root only, and serializes its writes on a lock file next to the bundle (`<bundle>.lock`).

Two things rotate on different clocks, and the whole procedure exists to keep that difference safe:

- **The CA bundle** (`remote.https.ca_certificate`, `/etc/wazuh-manager/certs/root-ca.pem` by default) — hot-reloaded
  on every read, no restart needed. `wazuh-manager-certs` is its only runtime writer (at installation the
  credential resolver writes `root-ca.pem` as a copy of the manager's CA when it is absent, unpublished, and never
  rewrites it afterwards).
- **The listener leaf** (`remote.https.certificate`) — loaded once, at `remoted` start. Only a
  restart of the manager makes a reissued leaf take effect: `wazuh-manager-control reload` restarts every
  daemon **except** remoted, so it does not.

## The procedure

Five steps, in this order. Steps 1–3 need no restart; step 4 is the only one that does; step 5 must
come after step 4 has landed everywhere, never before.

| # | Step | Restart? | What it changes |
|---|---|---|---|
| 1 | `wazuh-manager-certs add <new-ca.pem>` on the master — or place the file by hand and `wazuh-manager-certs stamp` | No | The bundle now carries **both** CAs; the old one still signs the served leaf. A CA whose `notBefore` is still ahead of this node's clock (`add` refuses one, so this is clock skew with the issuing host, or a file placed by hand) is served with the bundle at once; its window only matters once it is the leaf's sole anchor (see [Clocks, not files](#clocks-not-files)) |
| 2 | Distribute the published bundle to every other node: `wazuh-manager-certs --from-master` on each worker (see [Pulling the bundle on a worker](#pulling-the-bundle-on-a-worker)), or copy the master's file over the worker's bundle and run `check` | No | Every node advertises the same `ca_generation` and serves the same certificates |
| 3 | Wait out **the overlap window** (see below) | No | Agents catch up on their own schedule, at the pace the endpoint's rate limit allows |
| 4 | On every node: reissue the listener pair under the new CA, stage the new CA in `/etc/wazuh-manager/ca/` and reissue the Server API pair (see [The manager's own CA](#the-managers-own-ca-and-the-server-api-pair)), then **restart the manager** — under systemd `wazuh-manager-control check && systemctl restart wazuh-manager` (the check refuses a pair the start would refuse while the manager is still up; `systemctl restart` alone stops first), without systemd `wazuh-manager-control restart`; see [`wazuh-manager-control`](../../architecture.md#wazuh-manager-control) | **Yes — the only restart in the whole procedure** | The listener now presents a leaf signed by the new CA |
| 5 | `wazuh-manager-certs remove <old-ca-identity>` on the master, only once step 4 has completed on every node; then repeat step 2 (`--from-master`) on every worker | No | The old CA leaves the bundle. A worker keeps the old bundle until it pulls: `--from-master` is the only write a worker accepts |

On a fresh install the bundle has never been published: remoted serves it (generation `0`), but
`wazuh-manager-certs check` exits `1` with `no publication block (unpublished)` until the first
`stamp` (on a worker, `--from-master`). That is the expected state before a first rotation, not a
broken bundle.

Steps 1–3 are what make the switch in step 4 safe: by the time the leaf changes, every reachable
agent has already had the chance to add the new CA to what it trusts, so the moment the listener
starts presenting a leaf signed by it, agents keep verifying without interruption. Step 5 is cleanup,
not part of the cutover — nothing requires it to happen quickly, and rushing it is exactly what
Hazard 1 below is about.

### The overlap window (step 3)

**The window must be longer than the longest disconnection your deployment tolerates for a legitimate
agent** — a laptop closed for a weekend, a satellite site with intermittent connectivity. There is no
automated gate that measures fleet-wide adoption before you are allowed to move on to step 4: an
agent that was offline for the whole window has simply not seen the new CA yet, and step 4 is one
restart away from that agent's trust catching up.

Adoption itself is paced by
[`remote.https.cacerts_rate_limit`](configuration.md#httpscacerts_rate_limit) (default 50 requests/s
per node) and by a random delay each agent waits before fetching: at 10,000 agents on one node the
fleet adopts the change in roughly 200 s once every agent has had a chance to `notify`. Raise it for the duration of the rotation and restore the default
afterward if the window would otherwise be dominated by the rate limit rather than by how often
agents check in.

### Pulling the bundle on a worker

Run on each worker, as root (steps 2 and 5):

```bash
/var/wazuh-manager/bin/wazuh-manager-certs --from-master
/var/wazuh-manager/bin/wazuh-manager-certs --from-master --master master.example.com --port 1517
```

It downloads `https://<host>:<port><global_prefix>/cacerts` and installs it under the generation the
master announces in `Wazuh-CA-Generation`. By default `<host>` is the first entry of this node's
`cluster.nodes`, `<port>` this node's `remote.https.port` and the prefix this node's
`remote.https.global_prefix` (normalized, so the default `/wazuh-manager/` gives
`/wazuh-manager/cacerts`). `--master <host>` and `--port <port>` override the first two, for when the
cluster section does not name an address of the master's agent listener this node can reach; they are
accepted only together with `--from-master` (otherwise a usage error, exit 1). Before connecting, the
address is validated, and each refusal is exit 2: no `--master` and an empty `cluster.nodes`; a host
with whitespace, a control character, `/`, `?`, `#`, `@` or `\`, or unbalanced brackets; a port that
is not a number in 1–65535. A bare IPv6 literal (`--master ::1`) is bracketed for you.

The master's certificate is verified against **this worker's own bundle**, including its name, so the
host you pass must be a subject alternative name of the master's listener certificate; nothing relaxes
that check. That is why step 2 must run before step 4: a worker can only pull from a master whose leaf
chains to a CA the worker's bundle already holds. On success it prints `installed N certificate(s) from
<url>; published generation G`, or `already at generation G; nothing to do`; it refuses a generation
behind its own (see [the monotonicity limit](#2-the-monotonicity-limit)) and a master bundle that is not
vouched for (`generation 0`; run `stamp` on the master first). Run on a node whose `cluster.node_type` is
not `worker`, it exits 2 and writes nothing.

### The manager's own CA and the Server API pair

`wazuh-manager-certs` judges the bundle only against remoted's certificate, but every start of the
manager also runs the credential checks of [Credentials](../../getting-started/credentials.md), and
three of them involve the CA being rotated:

- `certs/root-ca.pem` must **contain** the manager's CA, `/etc/wazuh-manager/ca/root-ca.pem`;
- `certs/apid.pem` (the Server API pair) must chain to `/etc/wazuh-manager/ca/root-ca.pem`;
- `certs/remoted.pem` must chain to a certificate of `certs/root-ca.pem`.

So in step 4, on every node (`ca/` is not replicated by the cluster), before the restart:

1. Stage the new CA as `/etc/wazuh-manager/ca/root-ca.pem`, and replace `root-ca.key` with the new
   CA's key or remove it: an old key beside the new certificate is refused (`INVALID
   …/ca/root-ca.key: does not match root-ca.pem`). The CA requirements are in
   [The manager's CA](../../getting-started/credentials.md#the-managers-ca).
2. Issue `remoted.pem` and `apid.pem` with the new CA, with the profile in
   [Server pairs](../../getting-started/credentials.md#server-pairs), and put them in place with the owners
   and modes in [Files and modes](../../getting-started/credentials.md#files-and-modes). The resolver issues
   pairs only at installation and never reissues them.
3. Restart the manager. The restart loads both pairs (remoted, `wazuh-manager-authd`, which uses the
   remoted pair by default, and `wazuh-manager-apid` read their pairs only at start), and the start
   publishes the new CA in `export/ca.pem`, which clients of the Server API trust.

Skipped, the failure surfaces at a later start, not at the rotation: once step 5 has removed the old
CA, a node whose `ca/root-ca.pem` is still the old one refuses to start with `INVALID
/etc/wazuh-manager/certs/root-ca.pem: does not contain /etc/wazuh-manager/ca/root-ca.pem` (`Invalid
credentials. Exiting`, error 22 in `-j` output; see
[When the manager does not start](../../getting-started/credentials.md#when-the-manager-does-not-start)).
An `apid.pem` left under the old CA once `ca/` holds the new one is refused the same way. The
indexer connector pair is not part of this rotation: it comes from the indexer's CA.

## Reading `ca_generation`

Every `POST /control` `notify` response carries `ca_generation`
([full contract](https-events-api.md#notify-keepalive)), and every `GET /cacerts` `200` carries a
matching `Wazuh-CA-Generation` header
([full contract](https-events-api.md#ca-certificate-endpoint-get-cacerts)). Both come from the same
evaluation; the `notify` value re-reads the file at most once per second, so the two can differ for
up to a second after a change. Three states, not interchangeable:

| Value | Meaning | What to do |
|---|---|---|
| a timestamp (e.g. `1758150000`) | A guard vouched for the bundle at this publication; agents that see a **higher** number than the one they hold will refresh | Nothing — this is the steady state during and after a rotation |
| `0` | There is a bundle to serve, but nothing vouches for it: never `stamp`ed, or a guard refused it | Publish it — see the situation table below |
| `null` | No servable bundle at all: never readable since remoted started, or it carries no certificate (a file that becomes unreadable after a good read keeps being served from the last good copy) | Provision `remote.https.ca_certificate`, then `stamp` |

## What you see, what you do

The manager's own log lines, in operator terms. Every row is logged **once per event**, not on every
request; separately, `GET /cacerts` logs a throttled summary of the `404`/`503` answers it gave
(`GET /cacerts answered 404 to N request(s) in the last S s…`, a WARN; the same for `503`, an
ERROR), and the certificate evaluation remoted runs at start and every 24 hours repeats its ERROR
while the condition lasts. That evaluation also warns about the listener leaf itself, 30 days before
it expires and once it has expired; its lines are listed under
[`https.certificate`](configuration.md#httpscertificate).

| What you see | `ca_generation` / `GET /cacerts` | What it means | What to do |
|---|---|---|---|
| INFO `CA bundle '<path>' is published as generation N (was M); that is the generation agents asking this manager are told about.` | `N` / `200` | A write of the tool (`add`, `remove`, `prune-expired`, `stamp`, `--from-master`) was picked up | Nothing — this is the line each step 1, 2 and 5 should produce on every node |
| INFO ``Unpublished CA bundle at '<path>'; agents are told this manager has no published bundle (0). Publish it with `wazuh-manager-certs stamp` or `add` on the master.`` | `0` / `200` | A plain PEM was placed by hand, or by the installer, and never published | `stamp` on the master (or `add` if there's a second CA to bring in at the same time) |
| WARN ``CA bundle '<path>' changed outside the tool and is not published; previous publication N; agents are told this manager has no published bundle (0) until `wazuh-manager-certs stamp` is run on the master.`` | `0` / `200` | Something edited the file without going through `wazuh-manager-certs` — the content no longer matches what was last sealed | Confirm the new content is intentional, then `stamp` on the master to reseal it |
| WARN naming a `Content-SHA256` mismatch | `0` / `200` | The `##` block is present but no longer describes the certificates that follow it (partial edit, corruption) | `stamp` on the master — it rebuilds the block from what is actually there |
| WARN naming a guard (`7 certificates (max 6)`, `8402 bytes (max 8191)`) | `0` / `200` | The bundle fails one of the guards `wazuh-manager-certs` itself enforces on write — something bypassed it | Fix the bundle with `wazuh-manager-certs` (never by hand): `remove` the offending entry |
| WARN naming the chain guard (`does not chain to any CA in it`) — when only a date is in the way, the parenthesis names it (`CA '/CN=…' not valid until <date>`) | `0` / **`503`** | Nothing in the bundle chains to the served leaf: an edit that bypassed the tool or, for a date, clock skew with the issuing host | `add` back a CA that signs the leaf, or fix the clock |
| WARN `The CA bundle '<path>' no longer chains to the served leaf certificate, and the file did not change: a validity window closed (CA '/CN=…' expired at <date>). GET /cacerts answers 503 ca_mismatch from now on …` | `0` / **`503`** | The CA that anchored the served leaf — or the leaf itself — expired in place: nothing wrote the file, the clock moved. The parenthesis names every certificate on the leaf's path that is out of its window, and since or until when: two entries in the gap between a rotation's two same-name CAs. Said once, within a minute, whether or not a request arrives | Renew: `add` the re-issued CA on the master (reissue and reinstall the leaf too if it is the one that expired), then `prune-expired` |
| INFO `The CA bundle '<path>' chains to the served leaf certificate again, and the file did not change: a validity window opened. GET /cacerts serves it from now on, published as generation N.` | timestamp / `200` | A CA whose `notBefore` was ahead of this node's clock reached it (clock skew with the issuing host is the usual cause) | Nothing — the bundle is live |
| No bundle at all (`404`) | `null` | The configured file was never readable since remoted started, or carries no certificate | Provision it and `stamp` |
| WARN `Cannot persist the CA bundle publication record at '<path>': …` | unchanged | remoted could not write `var/run/remoted-ca-bundle/record.json`; serving and the generation agents are told are unaffected, and the write is retried | Fix the directory's permissions or free space; until the write succeeds, a restart reports the bundle as seen for the first time again |
| Nothing logged | `0`, same hash as last time | Steady state for an unpublished bundle nobody has touched | Nothing — this is silent by design so a hand-placed PEM doesn't spam the log on every read |

## Four things that go wrong only in the wrong order

### 1. Removing the old CA before restarting remoted

`wazuh-manager-certs`'s guards (`check`, `add`, `remove`, ...) validate against the leaf **on disk**
(`remote.https.certificate`) — the one `remoted` will load on its **next** start, not the one the
running listener holds in memory. If you reissue the leaf on disk and then run `remove` on the old
CA **before restarting remoted**, the tool sees the new leaf and happily lets you remove the old CA,
because on disk the new leaf chains to the new CA just fine. The running listener, though, is still
presenting the *old* leaf — and the bundle no longer has a CA that signs it.

**Symptom**: `GET /cacerts` starts answering `503 ca_mismatch` for the entire fleet, immediately
after the `remove`, and stays that way until the manager is restarted (`wazuh-manager-control
restart`; `reload` leaves remoted running).

This is why step 4 (reissue + restart) must complete before step 5 (`remove`) runs, never the other
way around. There is no guard against this in the tool itself — the fix is following the order above.

### 2. The monotonicity limit

Every publication is the wall-clock second of the write, and it must be strictly greater than the
publication in the bundle's `##` block: with the clock behind that block the write is refused (exit
1, `clock is behind the current publication N`), and on the same second the tool waits for the next
one. Agents only ever adopt a **strictly greater** number than the one they hold. If the system
clock is set backward **and** the `##` block is lost at the same time (a hand edit that stripped it,
a restore from an old backup), the tool has no record outside that block of the highest generation
the fleet has already seen — the next `add`/`stamp` can end up repeating or lowering a number agents
already adopted. Nothing errors; the rotation you meant to ship simply reaches no one.

**Before running `stamp`/`add` again after anything that could have stripped the block**, check the
system clock (NTP drift is the usual cause) and run `wazuh-manager-certs inspect`, which prints the
publication the block claims (`0 (unpublished)` once it is stripped) and whether it is vouched for;
the last generation remoted recorded is in `var/run/remoted-ca-bundle/record.json`. Do not assume a
fresh write will move the fleet forward.

The mirror case, on a worker, is a guard with the same limit: `--from-master` refuses (exit 1, `the
master publishes generation N, behind this node's M; refusing to move this worker's agents
backwards`) a generation lower than the one in the worker's own `##` block. It compares only against
that block: once the worker's block is gone, any generation the master publishes is installed.

### 3. Sharing one bundle across managers whose leaves come from different CAs

Every node of a cluster presents its own leaf, and that is fine as long as all of them chain to a CA
the shared bundle carries. `--from-master`, `check` and every write guard validate the bundle against
*this node's own* leaf on disk, so a node whose leaf was issued by a CA the bundle does not hold
refuses `--from-master` (exit 1, the chain guard) — and a bundle copied onto it by hand is announced
as `0` (unpublished) with its `/cacerts` answering `503`. Issue every node's leaf from the CA the
bundle carries, and distribute the bundle from the master with `--from-master`.

### 4. Why `prune-expired` can go silent

`prune-expired` with nothing expired writes nothing and publishes nothing — deliberately. Bumping the
generation over unchanged bytes would send the whole fleet back to `GET /cacerts` for no reason, and
a cron job that runs it nightly would do that every night. What it does **not** do is stay silent
about a bundle that needs attention: on that same no-op path it still checks whether the bundle is
actually published, and warns (`bundle is not vouched; run 'stamp' to publish it`) when it is
unstamped or its `Content-SHA256` is stale — so a cron log that only ever prints `nothing to prune`
is not, by itself, proof that the bundle is in good shape.

## Clocks, not files

Whether the served leaf chains to the bundle — the `503 ca_mismatch` decision, the `ca_generation`
agents are told and `remoted.server.tls.ca_matches_leaf` — is judged against the clock on every read
of the bundle, from the certificates already parsed; only the parse itself is cached by the file's
content. Two things therefore happen with no write to the file:

- A CA that **expires in place** stops being served and published at its `notAfter`: `GET /cacerts`
  answers `503` from the next request and `notify` announces `0` from the next keepalive. The WARN
  above is logged once, within a minute: the listener judges the bundle again every 60 seconds on
  its own, because agents that verify this manager fail their TLS handshake against the expired CA
  and never reach it — once the CA expires, requests are not what notices it. The daily evaluation
  then repeats its ERROR.
- When the leaf's only anchor is a CA whose `notBefore` is **still ahead** of this node's clock, the
  bundle answers `503` until that instant and is served, and published under the block's generation,
  from then on — with the INFO line above.

The notify path reads the file at most once per second, `GET /cacerts` once per request, and the
60-second recheck once a minute, off the request path. It also means a file change with no traffic is noticed, and its
event logged, within a minute rather than at the next request or the next day.

The publication record (`var/run/remoted-ca-bundle/record.json`) describes the **file**, not the
moment. A rebuild that finds a stamped bundle only a date keeps from publishing (a CA placed by hand
before its `notBefore`, or the node restarted after its CA expired) records the block's generation,
not `0`. Agents are still told `0` until the window opens; when it does, the INFO line above is
logged once, and a later restart logs nothing more.

## Exit codes

Every `wazuh-manager-certs` command that writes follows one rule: **what it could not read or parse
is exit 2; what it read fine but would not accept is exit 1.** A command run where it cannot run —
not as root, a write command on a worker, `--from-master` on a node that is not a worker — is also
exit 2. Full table and per-guard mapping:
the "Exit codes" section of `src/shared_modules/manager_certs/README.md` in the source tree.

## Enrollment tokens and a rotation

Agents already enrolled are not affected by this; only tokens still used to enroll new agents are. A
rotation that keeps the CA key does not change the pin, so pinned tokens survive it. A pinned token
(the default) trusts only the CA that signed the master's listener certificate when it was minted,
so pinned tokens minted before step 4 stop working once the leaves are replaced. An `--embed-ca`
token carries the master's whole bundle, so it stops working only if it was minted before step 1.
After step 4 has completed on every node, mint new tokens for the affected ones still in use
(install scripts, configuration management) and revoke the old ones with
`wazuh-manager-authd --revoke-enrollment-token <id>`.

Once step 5 has removed the old CA, an agent given a stale pinned token stops with `pin_mismatch --
fetched CA does not match the enrollment token's pin`. Despite its wording, during a rotation this
means the token is stale, not that the manager is being impersonated; see
[Agent Not Connecting](../client/README.md#agent-not-connecting).

## Compatibility during a rotation

- **A bundle never stamped** — the plain PEM the credential resolver writes at installation, or one
  placed by hand — is served as it is and announced as `0` with an INFO line; nothing changes until an
  operator runs `stamp` (or `add`) on the master for the first time.
- **4.x agents mid-upgrade** receive, over the legacy WPK channel, only the single CA that the
  currently served leaf chains to, re-serialized — the same anchor they would have received before
  this feature, regardless of how many CAs the bundle carries.
- **The `##` publication block** is PEM explanatory text (RFC 7468 §2): remoted and
  `wazuh-manager-certs` read it, and any other PEM consumer (OpenSSL, an agent's trust store) ignores
  it, so a stamped bundle stays an ordinary CA file. `GET /cacerts` serves only the re-serialised
  certificates, never the block.

## See also

- `wazuh-manager-certs` README (`src/shared_modules/manager_certs/README.md` in the source tree) — every
  command, guard, exit code and example (developer reference; this page assumes it).
- [HTTPS Agent API — `GET /cacerts`](https-events-api.md#ca-certificate-endpoint-get-cacerts) and
  [`POST /control` notify](https-events-api.md#notify-keepalive) — the wire contract `ca_generation`
  and `Wazuh-CA-Generation` are part of.
- [Metrics — CA distribution](metrics.md#ca-distribution--remotedcacerts) — what to watch on
  `remoted.cacerts.*` while a rotation is in flight.
- [Configuration — `https.cacerts_rate_limit`](configuration.md#httpscacerts_rate_limit) — the knob
  that paces adoption during the overlap window.
