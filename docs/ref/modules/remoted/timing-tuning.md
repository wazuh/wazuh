# Connection Timing Tuning

How to reason about the agent↔manager timing contract — timeouts, retries, throttles and queues —
instead of cargo-culting values. Every claim here is backed by a measurement from the #38284
campaign, run on the 4-core/8 GB reference hardware (c5ad.xlarge, Amazon Linux 2023) and
cross-checked on a second architecture. Options live in
`wazuh-manager-internal-options.conf` (manager) and `local_internal_options.conf` (agent) unless
marked as XML settings.

## 1. The mental model

One request crosses two independent budgets:

- **The agent side** puts a single deadline on the whole request (`agent.https_request_timeout`,
  10 s, or `agent.https_stateful_timeout`, 90 s, for inventory sessions), then retries with an
  exponential backoff (`https_backoff_base` 1 s → `https_backoff_cap` 60 s) up to the endpoint's
  attempt budget. Attempt counts are **total tries, not retries**.
- **The manager side** spends that time in sequential phases: accept, read (idle-based, not a
  body deadline — a slow upload that keeps moving is never cut), forward downstream, and wait for
  the downstream answer (`remoted.downstream_response_timeout` 5 s for events,
  `remoted.downstream_stateful_response_timeout` 20 s for inventory sessions).

Two multiplication laws follow. Worst case for one step ≈ `attempts × timeout + backoff ladder`;
and each of the agent's HTTPS streams (control, events, each sync module) keeps its **own** backoff
ladder, so a fleet's pressure on a dead manager converges to `streams / backoff_cap` connection
attempts per agent — measured: **6.5 SYN/min per agent** once the ladders saturate.

Who gives up first matters more than either value alone: when the loser is the agent, the manager
keeps working on a request nobody waits for, and the retry duplicates it (see §4).

## 2. Invariants (check these before changing anything)

| # | Rule | What breaks when violated |
|---|---|---|
| 1 | `remoted.control_keepalive_throttle` ≤ ½ · `<global><agents_disconnection_time>` | live, answering agents flap to `disconnected` for part of every cycle (measured: ~30 s of every 120 s at 2× the threshold). remoted warns at startup from half upward |
| 2 | `agent.https_request_timeout` > the endpoint's downstream budget on the manager | the agent retries a request the engine already ingested → duplicate events, ×(1+attempts) amplification (measured ×6 with defaults against a slow engine) |
| 3 | `https_stateful_attempts × https_stateful_timeout` + backoffs < 15 min (the fixed session ceiling) | overlapping duplicate sessions and head-of-line blocking. Defaults sit at ≈8.5 min — do not raise both together |
| 4 | `inventory_sync_server_session_query_batch_size` ≤ the indexer's `max_result_window` (10000) | integrity checks fail permanently with 500. The option now refuses values outside 0 \| 100–10000 |
| 5 | throttle > the fleet's notify cadence | a throttle at or below the notify interval suppresses nothing |

## 3. Per-goal recipes

**Slow or satellite links.** Inventory bodies compress ~16:1 on the wire, so `https_stateful_timeout`
(90 s) covers surprisingly large inventories; the real casualties are: (a) WPK downloads (binary,
no compression — budget = size/rate against 90 s), and (b) the sync layer's own ~60 s deadline,
which fires *before* the 90 s budget: a full resync that cannot finish in ~60 s is deferred and
retried from zero every cycle, forever, at INFO level. If agents on a link class never converge,
this is why — the fix is reducing what one session carries, not raising the HTTPS timeout.

**Large fleets (10k+).** The keepalive throttle is your wazuh-db shield: the 60 s default cuts
keepalive writes **30×** (measured 300→10 writes for 10 agents/60 s, both architectures). Detection
latency is governed by `agents_disconnection_time` alone — monitord sweeps at that period, so
detection lands anywhere in [1×, 2×] of it; changing notify cadence does not speed it up. Budget
outage recovery as ~6.5 TLS handshakes/min per disconnected agent.

**Manager outages and event loss.** Short outages are transparent (measured: 25 s outage → every
buffered event delivered exactly once). The loss point on longer outages is **not** the HTTPS
producer (`https_producer_pause_threshold` — its pause does not propagate upstream) but
`logcollector.queue_size` (1024 lines): once full, new lines are dropped with no replay and a
single warning. Size it as `peak EPS × required outage window` — defaults tolerate ≈100 s at
20 eps (measured: 33% of a 3-minute outage's events lost).

**Overloaded /stateful.** Under sustained overload, shedding is capacity-driven and roughly
independent of `downstream_stateful_response_timeout`; what the knob bounds is the **latency
tail** (saturated p99 ≈ 0.94 × knob, measured across six values). Keep the default 20 s — it sat
at 3.4× the measured flush p99 under 3× overload — and never set it below 2× your deployment's
flush p99: shedding grows fast below that (17% at 10 s, 50% at 2 s in overload).

## 4. Symptom → knob

| Observable | Likely cause | Where to look |
|---|---|---|
| Live agents flap `disconnected` | throttle ≥ ½ disconnection time (invariant 1) | startup warning; `last_keepalive` age vs threshold |
| Duplicate events after engine slowness | invariant 2: any timeout layer aborting after the body was consumed | same-body deliveries on the engine ingress; no dedup exists on /stateless |
| Integrity check returns 500 forever | batch size above `max_result_window` | `-t` now refuses it |
| 503 with `Retry-After` on /stateful | VD feed not ready (CVE content not loaded) | content-updater log |
| 503 without `Retry-After` | downstream timeout **or** in-flight budget shed — currently indistinguishable to the agent | `server.budget.inflight.*` metrics; budget sheds do not count in endpoint metrics |
| Agent shows synced but the indexer is missing data | immediate sessions report success while the indexer is unreachable; queue is non-persistent | `Indexer node ... is no longer available` in the manager log |
| A link class never finishes its first sync | the ~60 s sync-layer deadline + retry-from-zero (§3, slow links) | `synchronization deferred` at INFO on the agent |

## 5. Operator traps

- A **misspelled** option key is silently ignored; a **present-but-invalid** value refuses daemon
  startup (and since the readiness fixes, `status` says "refused its configuration" instead of
  timing out).
- `wazuh-manager-internal-options.conf` is per node and not cluster-synced: a throttle set on one
  node only makes that agent's behavior depend on which node it lands on.
- Raising a timeout without its counterpart on the other side recreates the duplicate-window
  class of bugs this campaign measured. Change pairs together (invariant 2).
- The keepalive throttle governs 5.x agents only; 4.x keepalives are written ungated by the
  legacy path.

## 6. Measured defaults record

All shipped defaults were validated by measurement; none needed changing. The two range fixes
(batch-size ceiling, startup warning for the throttle) shipped separately. Summary of the
evidence behind each verdict, per knob family, lives in wazuh/wazuh#38284 (measurement tables)
and wazuh/wazuh#38549 (defects found on the way). Final sign-off of this table against the
product envelope (target fleet size, worst supported link) is tracked in #38284.
