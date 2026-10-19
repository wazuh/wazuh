# 24 — What the container context actually costs, measured

Roadmap item 17 (`04-findings-performance.md` P3) was filed against an **estimated** blob size of
1.5 KB, with 10 KB+ called "not unusual". Nobody had measured one. This is that measurement, taken
on the `wazuh_manager` VM against the live agent databases on 2026-10-15, before any of the
normalisation work landed.

It corrects the estimate downward by roughly 2–4×, and confirms the duplication factor — which is
the part that actually matters — directly.

## Blob size: 330–930 bytes, not 1.5 KB

| Origin | Blob size | Carries nested `kubernetes` |
| --- | --- | --- |
| Docker | **329 B** | no |
| Kubernetes | **927–928 B** | yes |
| kind control-plane (Docker runtime) | **692 B** | no |

Nothing on this node approached 1.5 KB, and no blob carried
`kubectl.kubernetes.io/last-applied-configuration` — the annotation the original finding named as
the driver of 10 KB+ blobs. That annotation remains plausible on a real cluster; it is simply
**unobserved here**, so any cap sized against it is still unvalidated. See the caveat below.

## Duplication: 79× and 84×, measured

`/var/ossec/queue/fim/db/fim.db`, `file_entry`:

| | Value |
| --- | --- |
| Container rows | 1,003 |
| Distinct containers | 8 |
| Distinct blobs | 8 |
| **Bytes stored** | **331,547** |
| **Bytes needed** (one per container) | **4,192** |
| **Duplication** | **79×**, 327 KB wasted |

`/var/ossec/queue/syscollector/db/local.db`, container rows across four tables:

| Table | Container rows | Distinct blobs | Blob size |
| --- | --- | --- | --- |
| `dbsync_groups` | 45 | 1 | 692 B |
| `dbsync_users` | 21 | 1 | 692 B |
| `dbsync_processes` | 14 | 1 | 692 B |
| `dbsync_ports` | 4 | 1 | 692 B |
| **Total** | **84** | **1** | 58,128 B stored for 692 B of information — **84×** |

The per-container multiplier is what scales, and it is set by rows-per-container, not by blob size.
The five Docker containers here hold **200 file rows each**, so each pays its blob 200 times. The
scenario the original finding modelled — 2,000 files per container — pays it 2,000 times.

## Revised projection

Re-running the original finding's own scenario with measured blob sizes:

| | Rows | × blob (measured) | Duplicated bytes | Originally claimed |
| --- | --- | --- | --- | --- |
| Syscollector, per scan | 100 × 300 = 30,000 | 692 B | **~21 MB** | ~45 MB |
| FIM, per run | 100 × 2,000 = 200,000 | 330 B | **~66 MB** | ~300 MB |

Smaller than claimed, and still worth removing — but the honest justification for item 17 is no
longer primarily the bytes. It is the two things measurement did not shrink:

1. **The MODIFIED storm.** `updateChanges()` passes only `return_old_data`, and `getRowDiff()`
   compares every supplied column, so one edited label rewrites `container_json` on every row of
   that container and re-emits its whole inventory as MODIFIED. A 330-byte blob storms exactly as
   readily as a 1.5 KB one. Filed in `03-findings-correctness.md`.
2. **Attribution on delete.** The column exists so a DELETE survives its container. Storing the
   context once per container serves that requirement at 1/79th the cost, not differently.

## On #40092 — container rows are NOT being discarded

`23-nfr3-container-limits.md:26-29` recorded that container inventory rows fail the agent's own
strict validator and are deleted inside the transaction, while `:299-303` reported 527 container
package rows surviving and left the contradiction open.

**Measured: they survive.** 84 container rows are present in `local.db` across `dbsync_processes`,
`dbsync_ports`, `dbsync_users` and `dbsync_groups`.

`dbsync_packages`, `dbsync_osinfo`, `dbsync_hwinfo`, `dbsync_services` and `dbsync_network_iface`
hold **zero** container rows while holding host rows normally (1,859 host packages, 193 host
services). Whether that is rejection, or simply nothing produced for this one container, is **not
resolved by this measurement** — one container on one node cannot tell those apart.

What it does settle is the question that gated the work: normalising syscollector's container rows
is not optimising a path whose output is thrown away.

## Caveats

- **One node, one point in time.** Eight containers, one of them a `kind` control-plane.
- **No Kubernetes annotations of consequence were present**, so the large-blob case that motivated
  a per-value cap is unobserved rather than disproved. A cap sized from this data would be sized
  from the wrong distribution.
- **The partial-table result above is not a finding**, only an observation that needs a node
  running containers that produce packages and services before it means anything.


## The legacy column was removed outright, not deprecated

The plan staged the column's removal for a later release. The reasoning was upgrade safety: leave
`container_json` in place for one cycle so that rows written by an older agent keep describing
their own container, and so no agent pays a `WITHOUT ROWID` table rebuild at upgrade time.

That reasoning depended on there being agents in the field with rows in the old shape. There are
none — none of this container work has been released. With no installed base, "one upgrade cycle"
protects nobody, and the cost of waiting is real: every reader carries a fallback path that is
unreachable by construction, and the column keeps being written as `DEFAULT ''` on every row.

So the column is gone in the same release that introduced the dimension:

- Dropped from all 14 create statements (13 syscollector tables, `file_entry`).
- Dropped from existing databases by migration — `user_version` 2 → 15 for syscollector, 2 → 3 for
  FIM. Development databases converge rather than keeping a vestigial column forever.
- Both legacy fallback readers deleted, in `ecsData()` and in the FIM bridge's two lift sites.
- The C round trip removed with it: `fim_file_data.container_json`, `FileItem`'s member, and the
  column from `DB::getFile()`'s select list.

The migration statements are spelled out one per table rather than generated from
`CONTAINER_SCOPED_TABLES`. A migration that has already run on some database has to keep meaning
what it meant when it ran, and a list that someone may later extend cannot promise that.

The checksum is unaffected, which is what keeps this from re-syncing anything: `getRowChecksum()`
already erased the column before digesting, so a row's checksum is the same before and after the
drop. The erase is now gone too — there is no column left to erase.


## Not done: the per-value metadata cap

A cap on oversized label and annotation values was planned alongside this work, to stop a single
`kubectl.kubernetes.io/last-applied-configuration` from dominating a container's context.

**It is not implemented, and this measurement is why.** The annotation that motivated it was not
present anywhere on the measured node, and nothing there came close to the proposed 512-byte
threshold. A cap sized against this data would be sized against the wrong distribution: it would
pass everything here and tell us nothing about the case it exists for.

What it needs before it is worth writing:

- Context sizes from a node running real Kubernetes workloads, not `kind`.
- Confirmation from whoever owns the index templates (#37837) that annotation values may be
  truncated at all, and at what length.
- A decision on each of: drop or truncate; bytes or characters; whether a truncation marker
  counts toward the limit; whether keys are capped as well as values; whether there is a cap on
  entry count or total size; and how discarded metadata is reported.

Note also that storing the context once already removes the *multiplicative* cost that made large
annotations alarming. What a cap would still bound is the size of a single stored row, which is a
much weaker motivation than the one originally filed.
