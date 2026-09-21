# CA Bundle Rotation Runbook

How to rotate the CA that signs `wazuh-manager-remoted`'s HTTPS listener without ever taking `GET
/cacerts` down for the fleet — the order that must not change, the four ways to get it wrong, and
what the manager tells you along the way. For every command, flag, guard and exit code named here,
[`wazuh-manager-certs`'s README](../../../../src/shared_modules/manager_certs/README.md) is the
authoritative reference; this page does not repeat its command table or examples.

Two things rotate on different clocks, and the whole procedure exists to keep that difference safe:

- **The CA bundle** (`remote.https.ca_certificate`, `etc/certs/root-ca.pem` by default) — hot-reloaded
  on every read, no restart needed. `wazuh-manager-certs` is the only thing that ever writes it.
- **The listener leaf** (`remote.https.certificate`) — loaded once, at `remoted` start. Only a
  restart makes a reissued leaf take effect.

## The procedure

Five steps, in this order. Steps 1–3 need no restart; step 4 is the only one that does; step 5 must
come after step 4 has landed everywhere, never before.

| # | Step | Restart? | What it changes |
|---|---|---|---|
| 1 | `wazuh-manager-certs add <new-ca.pem>` on the master — or place the file by hand and `wazuh-manager-certs stamp` | No | The bundle now carries **both** CAs; the old one still signs the served leaf |
| 2 | Distribute the published bundle to every other node: `wazuh-manager-certs --from-master` on each worker, or copy the file and run `check` | No | Every node advertises the same `ca_generation` and serves the same certificates |
| 3 | Wait out **the overlap window** (see below) | No | Agents catch up on their own schedule, at the pace the endpoint's rate limit allows |
| 4 | Reissue the leaf(s) under the new CA, install them, **restart `wazuh-manager-remoted`** | **Yes — the only restart in the whole procedure** | The listener now presents a leaf signed by the new CA |
| 5 | `wazuh-manager-certs remove <old-ca-identity>` on the master, only once step 4 has completed on every node that shares that leaf | No | The old CA leaves the bundle |

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
for the whole fleet): at 10,000 agents the fleet adopts the change in roughly 200 s once every agent
has had a chance to `notify`. Raise it for the duration of the rotation and restore the default
afterward if the window would otherwise be dominated by the rate limit rather than by how often
agents check in.

## Reading `ca_generation`

Every `POST /control` `notify` response carries `ca_generation`
([full contract](https-events-api.md#notify-keepalive)), and every `GET /cacerts` `200` carries a
matching `Wazuh-CA-Generation` header
([full contract](https-events-api.md#ca-certificate-endpoint-get-cacerts)). Both come from the same
evaluation, so they never disagree. Four states, not interchangeable:

| Value | Meaning | What to do |
|---|---|---|
| a timestamp (e.g. `1758150000`) | A guard vouched for the bundle at this publication; agents that see a **higher** number than the one they hold will refresh | Nothing — this is the steady state during and after a rotation |
| `0` | There is a bundle to serve, but nothing vouches for it: never `stamp`ed, or a guard refused it | Publish it — see the situation table below |
| `null` | No servable bundle at all (missing, unreadable, or empty) | Provision `remote.https.ca_certificate`, then `stamp` |
| **absent** (the key is not in the response) | The manager predates this feature | Nothing to do here — treat it as unknown, not as "no rotation happening" |

## What you see, what you do

Translated from the manager's own error/observability table (design §4) into operator terms. Every
row is logged **once per event**, not on every request:

| What you see | `ca_generation` / `GET /cacerts` | What it means | What to do |
|---|---|---|---|
| INFO `unpublished CA bundle at <path>; publish it with wazuh-manager-certs stamp or add on the master` | `0` / `200` | A plain PEM was placed by hand, or by the installer, and never published | `stamp` on the master (or `add` if there's a second CA to bring in at the same time) |
| WARN `CA bundle at <path> changed outside the tool and is not published; previous publication N; run stamp on the master` | `0` / `200` | Something edited the file without going through `wazuh-manager-certs` — the content no longer matches what was last sealed | Confirm the new content is intentional, then `stamp` on the master to reseal it |
| WARN naming a `Content-SHA256` mismatch | `0` / `200` | The `##` block is present but no longer describes the certificates that follow it (partial edit, corruption) | `stamp` on the master — it rebuilds the block from what is actually there |
| WARN naming a guard (`7 certificates (max 6)`, `8402 bytes (max 8191)`, `no CA signs the served leaf`) | `0` / `200`, or **`503`** if literally nothing in the bundle chains to the served leaf | The bundle fails one of the guards `wazuh-manager-certs` itself enforces on write — something bypassed it | Fix the bundle with `wazuh-manager-certs` (never by hand): `remove` the offending entry, or `add` back a CA that signs the leaf |
| No bundle at all (`404`) | `null` | The configured file is missing, unreadable, or carries no certificate | Provision it and `stamp` |
| Nothing logged | `0`, same hash as last time | Steady state for an unpublished bundle nobody has touched | Nothing — this is silent by design so a hand-placed PEM doesn't spam the log on every read |

## Four things that go wrong only in the wrong order

### 1. Removing the old CA before restarting remoted (C32 / D39)

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

### 2. The monotonicity limit (E7a / C39e)

Every publication is a Unix timestamp assigned as `max(now(), previous + 1)`, and agents only ever
adopt a **strictly greater** number than the one they hold. If the system clock is set backward
**and** the `##` publication block is lost at the same time (a hand edit that stripped it, a restore
from an old backup), the tool has no record outside that block of the highest generation the fleet
has already seen — the next `add`/`stamp` can end up repeating or lowering a number agents already
adopted. Nothing errors; the rotation you meant to ship simply reaches no one.

**Before running `stamp`/`add` again after anything that could have stripped the block**, check the
system clock (NTP drift is the usual cause) and run `wazuh-manager-certs inspect` to see the
publication currently vouched for, rather than assuming a fresh write will move the fleet forward.

The mirror case, on a worker, is not a hazard but a guard: `--from-master` will not install a
generation lower than one this node already served, even if its local copy of the block is gone —
it refuses (exit 1) and asks for explicit recovery instead of silently letting the fleet's trust
regress.

### 3. Sharing one bundle file across managers with different leaves (C36j)

Do not copy a single bundle file between managers whose listeners present **different** leaves —
`--from-master`, `check` and every write guard validate the bundle against *this node's own* leaf. A
bundle built for one manager can quietly fail the leaf guard on another (`0`, unpublished), or —
if literally nothing in it chains to that node's leaf — leave its `/cacerts` answering `503` outright.
Each node's bundle is distributed from its own master via `--from-master`, never copied wholesale
across managers that do not share a leaf.

### 4. Why `prune-expired` can go silent (C35 / C36i)

`prune-expired` with nothing expired writes nothing and publishes nothing — deliberately. Bumping the
generation over unchanged bytes would send the whole fleet back to `GET /cacerts` for no reason, and
a cron job that runs it nightly would do that every night. What it does **not** do is stay silent
about a bundle that needs attention: on that same no-op path it still checks whether the bundle is
actually published, and warns (`bundle is not vouched; run 'stamp' to publish it`) when it is
unstamped or its `Content-SHA256` is stale — so a cron log that only ever prints `nothing to prune`
is not, by itself, proof that the bundle is in good shape.

## Exit codes

Every `wazuh-manager-certs` command that writes follows one rule: **what it could not read or parse
is exit 2; what it read fine but would not accept is exit 1.** Full table and per-guard mapping:
[`wazuh-manager-certs` README — Exit codes](../../../../src/shared_modules/manager_certs/README.md#exit-codes).

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

- [`wazuh-manager-certs` README](../../../../src/shared_modules/manager_certs/README.md) — every
  command, guard, exit code and example (developer reference; this page assumes it).
- [HTTPS Agent API — `GET /cacerts`](https-events-api.md#ca-certificate-endpoint-get-cacerts) and
  [`POST /control` notify](https-events-api.md#notify-keepalive) — the wire contract `ca_generation`
  and `Wazuh-CA-Generation` are part of.
- [Metrics — CA distribution](metrics.md#ca-distribution--remotedcacerts) — what to watch on
  `remoted.cacerts.*` while a rotation is in flight.
- [Configuration — `https.cacerts_rate_limit`](configuration.md#httpscacerts_rate_limit) — the knob
  that paces adoption during the overlap window.
