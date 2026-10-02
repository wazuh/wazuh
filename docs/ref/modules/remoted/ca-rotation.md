# CA Bundle Rotation Runbook

How to rotate the CA that signs `wazuh-manager-remoted`'s HTTPS listener without ever taking `GET
/cacerts` down for the fleet — the order that must not change, the four ways to get it wrong, and
what the manager tells you along the way. For every command, flag, guard and exit code named here,
`wazuh-manager-certs`'s developer README (`src/shared_modules/manager_certs/README.md` in the source
tree) is the authoritative reference; this page does not repeat its command table or examples. The
tool is installed as `/var/wazuh-manager/bin/wazuh-manager-certs` (`root:wazuh-manager 0750`), runs
as root only, and serializes its writes on a lock file next to the bundle (`<bundle>.lock`).

Two things rotate on different clocks, and the whole procedure exists to keep that difference safe:

- **The CA bundle** (`remote.https.ca_certificate`, `etc/certs/root-ca.pem` by default) — hot-reloaded
  on every read, no restart needed. `wazuh-manager-certs` is its only runtime writer (the installer
  creates `root-ca.pem` when it is absent, and never touches it again).
- **The listener leaf** (`remote.https.certificate`) — loaded once, at `remoted` start. Only a
  restart makes a reissued leaf take effect.

## The procedure

Five steps, in this order. Steps 1–3 need no restart; step 4 is the only one that does; step 5 must
come after step 4 has landed everywhere, never before.

| # | Step | Restart? | What it changes |
|---|---|---|---|
| 1 | `wazuh-manager-certs add <new-ca.pem>` on the master — or place the file by hand and `wazuh-manager-certs stamp` | No | The bundle now carries **both** CAs; the old one still signs the served leaf. A CA whose `notBefore` is still ahead of this node's clock (`add` refuses one, so this is clock skew with the issuing host, or a file placed by hand) is served with the bundle at once; its window only matters once it is the leaf's sole anchor (see [Clocks, not files](#clocks-not-files)) |
| 2 | Distribute the published bundle to every other node: `wazuh-manager-certs --from-master` on each worker, or copy the file and run `check` | No | Every node advertises the same `ca_generation` and serves the same certificates |
| 3 | Wait out **the overlap window** (see below) | No | Agents catch up on their own schedule, at the pace the endpoint's rate limit allows |
| 4 | Reissue the leaf(s) under the new CA, install them, **restart `wazuh-manager-remoted`** | **Yes — the only restart in the whole procedure** | The listener now presents a leaf signed by the new CA |
| 5 | `wazuh-manager-certs remove <old-ca-identity>` on the master, only once step 4 has completed on every node that shares that leaf; then repeat step 2 (`--from-master`) on every worker | No | The old CA leaves the bundle. A worker keeps the old bundle until it pulls: `--from-master` is the only write a worker accepts |

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

## Reading `ca_generation`

Every `POST /control` `notify` response carries `ca_generation`
([full contract](https-events-api.md#notify-keepalive)), and every `GET /cacerts` `200` carries a
matching `Wazuh-CA-Generation` header
([full contract](https-events-api.md#ca-certificate-endpoint-get-cacerts)). Both come from the same
evaluation; the `notify` value re-reads the file at most once per second, so the two can differ for
up to a second after a change. Four states, not interchangeable:

| Value | Meaning | What to do |
|---|---|---|
| a timestamp (e.g. `1758150000`) | A guard vouched for the bundle at this publication; agents that see a **higher** number than the one they hold will refresh | Nothing — this is the steady state during and after a rotation |
| `0` | There is a bundle to serve, but nothing vouches for it: never `stamp`ed, or a guard refused it | Publish it — see the situation table below |
| `null` | No servable bundle at all: never readable since remoted started, or it carries no certificate (a file that becomes unreadable after a good read keeps being served from the last good copy) | Provision `remote.https.ca_certificate`, then `stamp` |
| **absent** (the key is not in the response) | The manager predates this feature | Nothing to do here — treat it as unknown, not as "no rotation happening" |

## What you see, what you do

The manager's own log lines, in operator terms. Every row is logged **once per event**, not on every
request; separately, `GET /cacerts` logs a throttled summary of the `404`/`503` answers it gave
(`GET /cacerts answered 404 to N request(s) in the last S s…`, an ERROR for `503`), and the daily
certificate evaluation repeats its ERROR while the condition lasts:

| What you see | `ca_generation` / `GET /cacerts` | What it means | What to do |
|---|---|---|---|
| INFO ``Unpublished CA bundle at '<path>'; agents are told this manager has no published bundle (0). Publish it with `wazuh-manager-certs stamp` or `add` on the master.`` | `0` / `200` | A plain PEM was placed by hand, or by the installer, and never published | `stamp` on the master (or `add` if there's a second CA to bring in at the same time) |
| WARN ``CA bundle '<path>' changed outside the tool and is not published; previous publication N; agents are told this manager has no published bundle (0) until `wazuh-manager-certs stamp` is run on the master.`` | `0` / `200` | Something edited the file without going through `wazuh-manager-certs` — the content no longer matches what was last sealed | Confirm the new content is intentional, then `stamp` on the master to reseal it |
| WARN naming a `Content-SHA256` mismatch | `0` / `200` | The `##` block is present but no longer describes the certificates that follow it (partial edit, corruption) | `stamp` on the master — it rebuilds the block from what is actually there |
| WARN naming a guard (`7 certificates (max 6)`, `8402 bytes (max 8191)`) | `0` / `200` | The bundle fails one of the guards `wazuh-manager-certs` itself enforces on write — something bypassed it | Fix the bundle with `wazuh-manager-certs` (never by hand): `remove` the offending entry |
| WARN naming the chain guard (`does not chain to any CA in it`) — when only a date is in the way, the parenthesis names it (`CA '/CN=…' not valid until <date>`) | `0` / **`503`** | Nothing in the bundle chains to the served leaf: an edit that bypassed the tool or, for a date, clock skew with the issuing host | `add` back a CA that signs the leaf, or fix the clock |
| WARN `The CA bundle '<path>' no longer chains to the served leaf certificate, and the file did not change: a validity window closed (CA '/CN=…' expired at <date>). GET /cacerts answers 503 ca_mismatch from now on …` | `0` / **`503`** | The CA that anchored the served leaf — or the leaf itself — expired in place: nothing wrote the file, the clock moved. The parenthesis names every certificate on the leaf's path that is out of its window, and since or until when: two entries in the gap between a rotation's two same-name CAs. Said once, within a minute, whether or not a request arrives | Renew: `add` the re-issued CA on the master (reissue and reinstall the leaf too if it is the one that expired), then `prune-expired` |
| INFO `The CA bundle '<path>' chains to the served leaf certificate again, and the file did not change: a validity window opened. GET /cacerts serves it from now on, published as generation N.` | timestamp / `200` | A CA whose `notBefore` was ahead of this node's clock reached it (clock skew with the issuing host is the usual cause) | Nothing — the bundle is live |
| No bundle at all (`404`) | `null` | The configured file was never readable since remoted started, or carries no certificate | Provision it and `stamp` |
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
after the `remove`, and stays that way until `wazuh-manager-remoted` is restarted.

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

### 3. Sharing one bundle file across managers with different leaves

Do not copy a single bundle file between managers whose listeners present **different** leaves —
`--from-master`, `check` and every write guard validate the bundle against *this node's own* leaf. A
bundle built for one manager can quietly fail the leaf guard on another (`0`, unpublished), or —
if literally nothing in it chains to that node's leaf — leave its `/cacerts` answering `503` outright.
Each node's bundle is distributed from its own master via `--from-master`, never copied wholesale
across managers that do not share a leaf.

### 4. Why `prune-expired` can go silent

`prune-expired` with nothing expired writes nothing and publishes nothing — deliberately. Bumping the
generation over unchanged bytes would send the whole fleet back to `GET /cacerts` for no reason, and
a cron job that runs it nightly would do that every night. What it does **not** do is stay silent
about a bundle that needs attention: on that same no-op path it still checks whether the bundle is
actually published, and warns (`bundle is not vouched; run 'stamp' to publish it`) when it is
unstamped or its `Content-SHA256` is stale — so a cron log that only ever prints `nothing to prune`
is not, by itself, proof that the bundle is in good shape.

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

- **A bundle that predates this feature** — a plain PEM placed by the installer or by hand — keeps
  being served exactly as before and is announced as `0` with an INFO line; nothing changes until an
  operator runs `stamp` on the master for the first time.
- **4.x agents mid-upgrade** receive, over the legacy WPK channel, only the single CA that the
  currently served leaf chains to, re-serialized — the same anchor they would have received before
  this feature, regardless of how many CAs the bundle carries.
- **A remoted or `wazuh-manager-certs` from a different version than the rest of the fleet** is not a
  blocker: any remoted with this feature parses the `##` block; one without it treats the block as
  ordinary PEM explanatory text and ignores it (RFC 7468 §2).

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
