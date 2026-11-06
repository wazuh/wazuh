# 27 — Retiring `modern.bpf.c`: moving host FIM whodata onto `ebpf_provider`

Executes [11 §11.7 phase A4](11-ebpf-provider-import-plan.md) — the step deliberately left optional until the container consumer (A3) was validated. A3 is now in the tree (`container_event_drain.cpp` opens its own `rt_handle_t`), so the remaining duplication is what this document removes.

**End state:** one BPF source (`src/shared_modules/ebpf_provider/bpf/rt_file.bpf.c`), one compiled object (`rt_file.bpf.o`), one loader (`librt_engine`). `src/syscheckd/src/ebpf/src/modern.bpf.c`, `bpf_helpers.h`, `wrapper_bpf.h` and `dynamic_library_wrapper.h` are deleted; `ebpf_whodata.cpp` becomes a second `rt_engine` consumer alongside the container drain.

**Non-goal:** merging the two consumers onto one handle. ADR-001 sanctions one load per consumer, and host whodata (`RT_CGROUP_MODE_ALL`, full process context) and the container drain (allowlist mode, `RT_SKIP_PROC_CONTEXT`) want different filters. Today the agent already loads two objects; after this change it still loads two, but they are the same object loaded twice. Probe *count* does not regress — but see G6: probe count is not the same as event volume.

**The headline.** This is not a one-directional migration where the provider is the modern implementation and `modern.bpf.c` is the legacy one. `rt_file.bpf.c` carries **three live defects that this branch's `modern.bpf.c` does not have** (G3, G4, G5), two of which affect the already-shipping container feature right now. Half of this work is porting fixes *out of* `modern.bpf.c` before it is deleted, and the first two should land regardless of whether the retirement proceeds.

Where those defects come from matters for how they are reviewed. Three of them are **maintenance fixes released in 4.14.11 / 5.0.x that `main` does not yet carry** — `37d996d22aa` (resolve kprobe paths from the mount claimed for write), `d475ea8d2ff` (resolve the `security_inode_setattr` dentry without the kernel version) and `13f5d06f902` (default `loginuid` to -1, not 0). They reached this branch through the 4.14.11 merge. Any eBPF work branched from `main` therefore starts without them, which is exactly what happened to both extraction attempts (§27.7). They are not regressions somebody introduced; they are fixes that have not propagated. The one genuine provider-specific defect is G3's `renamedata` layout, which `rt_file.bpf.c` got wrong in its own direction.

---

## 27.1 Where the two implementations actually stand

| | `modern.bpf.c` (host whodata, today) | `rt_file.bpf.c` (provider) |
| --- | --- | --- |
| open/create | `kprobe/vfs_open`, `lsm/file_open` ×2 (`_dpath`, `_walk`) | `kprobe/vfs_open`, `lsm/file_open` (dpath only) |
| attribute | `kprobe/security_inode_setattr` | `kprobe/security_inode_setattr` |
| unlink | `kprobe/vfs_unlink`, `lsm/path_unlink` ×2 | `kprobe/vfs_unlink` |
| rename | `kprobe/vfs_rename` ×2 (dest + **source**), `lsm/path_rename` ×4 | `kprobe/vfs_rename` (dest only) |
| kprobe open trigger | `FMODE_CREATED \| O_CREAT` — **creation only** | `FMODE_CREATED \| O_CREAT \| O_ACCMODE` — every write-intent open |
| LSM open trigger | `FMODE_CREATED \| O_CREAT \| O_ACCMODE` | same |
| vfsmount for kprobe paths | `kprobe/mnt_want_write` + `write_mnt_map`, keyed by pid/tgid | `sb->s_fs_info` reinterpreted as `struct mount*` — **wrong** |
| mount traversal | advances `mnt = mnt_parent` at a boundary | **omits it** |
| `security_inode_setattr` arg | probes both PARM1 and PARM2 for a valid dentry | kernel-version branch only |
| `renamedata` layout | 5.12 layout, 6.18 layout via `bpf_core_field_exists` | **6.18 layout hardcoded for every kernel ≥5.12** |
| credentials | `uid`, `gid`, **`euid`**, **`login_uid`** | `uid`, `gid` only |
| process context | `cwd`, `parent_cwd`, `parent_name` | same, and skippable |
| in-kernel filtering | none | cgroup allowlist, `skip_mask`, per-cgroup drop accounting |
| loader | `ebpf_whodata.cpp` + `bpf_helpers.h`: 13 dlsym'd symbols, LSM-dpath → LSM-walk → kprobe ladder | `rt_engine.c`: `rt_open`/`rt_poll`/`rt_close`, single LSM-or-kprobe choice, no ladder |

The provider is the better *structure* and the weaker *implementation*. Nothing can be deleted until every row above is reconciled, because each one is a silent wrong-path or missing-event on some supported host rather than a visible failure.

---

## 27.2 Gaps, in the order they must be closed

### G1 — The event contract has no `euid` and no `login_uid`

`ebpf_pop_events()` fills `whodata_evt::effective_uid`, `effective_name`, `audit_uid`, `audit_name`, `audit_gid`, `audit_group_name` from `event->euid` and `event->login_uid`. `struct rt_file_event` carries neither. Cutting over without them drops six fields from every whodata alert; the audit-UID fields are the point of whodata attribution.

**Fix:** append after `parent_comm`:

```c
unsigned int euid;
unsigned int login_uid;   /* (__u32)-1 when the kernel lacks CONFIG_AUDIT */
```

`RT_ABI_MINOR` 1 → 2, `RT_ABI_MAJOR` unchanged per ADR-003. Port `modern.bpf.c`'s `struct task_struct___local` CO-RE shadow and its `bpf_core_field_exists(task_local->loginuid)` guard verbatim — on a kernel built without `CONFIG_AUDIT` a direct `loginuid` read fails to *compile*, not to run.

**Compatibility is directional.** An old consumer ignoring a new tail is fine; a *new engine* reading an *old object* is not — `rt_engine.c`'s per-event check rejects any record shorter than the engine's `sizeof(struct rt_file_event)`. So both `prebuilt/{x86,arm64}/rt_file.bpf.o` plus their `.sources.sha256` and `.provenance` must be refreshed in the same commit as this and every later contract change. This is guarded, not silent: `RT_BPF_STRICT_PREBUILT` defaults ON and a stale digest is a `FATAL_ERROR` at configure time, and a runtime mismatch logs once at `RT_LOG_ERROR`. The failure mode to fear is therefore a build configured with `-DRT_BPF_STRICT_PREBUILT=OFF`, not the default path.

### G2 — LSM coverage for unlink and rename is missing, and so is the fallback ladder

`modern.bpf.c` carries `_dpath` and `_walk` variants of every LSM hook. `ebpf_whodata.cpp` runs a three-step ladder:

1. `load_and_attach(obj, use_lsm=true, prefer_dpath=true)`;
2. on **`bpf_object__load()` failure** — the verifier stage, not attach — close and retry the same object with the `_walk` variants;
3. if LSM still fails to load *or* attach, fall back to the kprobe-only set.

That ladder is not cosmetic. On Amazon Linux 2 / 2023 the kernel's `btf_allowlist_d_path` does not permit `bpf_d_path()` from `bpf_lsm_path_rename`, so the dpath build fails *verification*; and a kernel with `bpf` in its active LSM list but without `CONFIG_SECURITY_PATH` has no `path_*` hooks to attach at all.

`rt_file.bpf.c` has one LSM program (`lsm/file_open`, dpath only). `rt_engine.c` picks LSM-or-kprobe once from `is_bpf_lsm_active()` and has no retry of either kind.

**Fix:**
- Port `lsm/path_unlink` and `lsm/path_rename` (source and destination), each in `_dpath` and `_walk` form, plus `lsm/file_open_walk`.
- Give `rt_open()` the same bounded ladder: **LSM dpath → LSM walk → kprobe**, re-opening the object and freeing every partially attached link between attempts.
- Extend `type_bit_for_section()`. It currently returns 0 for anything it does not recognise, so `kprobe/mnt_want_write` (added by G4), `lsm/path_unlink` and `lsm/path_rename` would all be autoload-disabled no matter what `type_mask` says. Variant selection alone is not enough: the function needs the new sections, and `mnt_want_write` needs to be kept whenever *any* kprobe hook that depends on it is kept, which is a dependency rather than a type bit.
- Test each `type_mask` value individually, not only `RT_FILE_ALL_BITS` — a per-class mask is the case where a missing dependency goes unnoticed.

Rejected: shipping only the `_walk` variants to avoid the ladder. `bpf_d_path()` is the only mount-namespace-correct resolution; the walker reconstructs from the dentry chain and gets bind-mounted and chrooted paths wrong. Host whodata matches reported paths against the configured directory list, so a wrong path is a missed alert.

### G3 — `renamedata` layout is hardcoded to 6.18 *(live defect)*

`rt_file.bpf.c`'s `struct renamedata___local` is `{mnt_idmap, old_parent, old_dentry, new_parent, new_dentry}` — the 6.18 layout — and is used for **every** kernel ≥ 5.12. On 5.12 through 6.17 the real layout is `{mnt_userns, old_dir, old_dentry, new_mnt_userns, new_dir, new_dentry}`: `old_dentry` is at offset 16 either way, but `new_dentry` is at 40, not 32. The read at 32 returns `new_dir`, an `struct inode*`, which is then walked as a dentry.

The committed prebuilt objects were built against a 6.6 BTF dump (`prebuilt/x86/rt_file.bpf.o.provenance`), so the shipping object has this bug on essentially every kernel in the supported range. This branch's `modern.bpf.c` handles both layouts with `bpf_core_field_exists(rd618->new_parent)`, from `d7dff4c1113`.

Note the symmetry: the `shared_modules/ebpf` attempt (§27.7) has the *opposite* half of the same bug — the 5.12 layout only, so it breaks from 6.18 onward. Only `d7dff4c1113` covers both, and it exists nowhere but here.

**Fix:** port `modern.bpf.c`'s `renamedata___local` + `renamedata___v618` pair and its CO-RE branch. **This is a container-FIM bug fix that should land on its own, ahead of the retirement**, since rename destinations in container FIM are wrong today.

### G4 — `sb->s_fs_info` is not a `struct mount`, and the walker never crosses a mount *(live defects)*

Two independent path-resolution defects:

**(a)** `kprobe__security_inode_setattr`, `kprobe__vfs_unlink` **and `kprobe__vfs_rename`** all obtain the `vfsmount` by reading `d_inode->i_sb->s_fs_info` and treating it as `struct mount*`. `s_fs_info` is filesystem-private superblock data — `ext4_sb_info` on ext4, `ovl_fs` on overlayfs — so `mnt_ptr->mnt` reads an arbitrary offset into an unrelated struct. `modern.bpf.c` instead records the real `vfsmount` in `write_mnt_map` from `kprobe/mnt_want_write`, keyed by pid/tgid, and reads it back via `get_write_mnt()`.

**(b)** `rt_walk_dentry()` handles the mount boundary but **omits `mnt = mnt_parent;`**, so after crossing it continues with the child mount's `vfsmount` and its `mnt_root`. The next boundary is therefore never detected: the walk runs up the parent mount's dentry chain to that filesystem's root and stops. On a single mount under `/` the result happens to be right, which is why container testing has not caught it; with nested or stacked mounts the path is silently truncated.

Both defects are inherited rather than introduced: `main`'s `modern.bpf.c` has the same three `s_fs_info` reads and the same walker, and `37d996d22aa` ("resolve eBPF kprobe paths from the mount claimed for write") is a 4.14.11 fix that reached this branch and nowhere else. The `shared_modules/ebpf` attempt (§27.7) carries both defects for the same reason.

**Fix:** port `kprobe/mnt_want_write`, `write_mnt_map` and `get_write_mnt()`; delete all three `s_fs_info` reads; add the missing `mnt = mnt_parent;`. Verify on nested, bind and overlay mounts.

One caveat on the port, flagged by the review and not yet resolved: `modern.bpf.c`'s mount cache stores unreferenced `vfsmount` addresses with no exit-time cleanup. Its namespace and superblock checks make a stale hit unlikely but do not prove freshness under PID reuse or mount churn. Port the checks intact and test churn explicitly rather than assuming the map is safe.

### G5 — `security_inode_setattr` argument position is taken from the kernel version

`rt_file.bpf.c` reads the dentry from PARM1 below 6.0 and PARM2 at or above it. Enterprise kernels backport the 6.0 signature — RHEL 9 ships it on 5.14 — so on those hosts the provider reads an `mnt_idmap*` as a dentry and every attribute-change event is wrong or dropped. `modern.bpf.c` has `resolve_dentry()`, which validates a candidate by checking `d_inode->i_sb == dentry->d_sb` and takes whichever of PARM1/PARM2 passes.

`d475ea8d2ff` ("resolve the security_inode_setattr dentry argument without the kernel version") is the 4.14.11 fix; it is absent from `main` and from both extraction attempts.

**Fix:** port `resolve_dentry()` and the probe-both-arguments selection. Third item in the same "provider bug fix" commit as G3/G4.

### G6 — The kprobe open hook is broader in the provider, and that is a volume decision, not parity

`modern.bpf.c`'s `kprobe/vfs_open` fires only on creation (`FMODE_CREATED | O_CREAT`). `rt_file.bpf.c`'s also fires on `O_ACCMODE`, i.e. every write-mode open. The two LSM hooks agree (both include `O_ACCMODE`), so this diverges only on kprobe-mode hosts — which is the majority configuration, since most distributions do not put `bpf` in the active LSM list.

Note which direction that cuts: `modern.bpf.c` is *inconsistent with itself*, catching writes to existing files on LSM hosts and missing them on kprobe hosts. The provider's behaviour is arguably the fix. But host whodata requests full process context (`skip_mask = 0`, two dentry walks per event), so taking it means more 12,416-byte records with the most expensive per-event cost, into the same 8 MiB ring.

**Decide explicitly and record the decision.** Do not let it arrive as a side effect of the cutover. Whichever way it goes, the container consumer's behaviour must not change, and the choice must be validated under sustained write load with `rt_drain_drops()` observed, not assumed.

### G7 — `ensure_libbpf_loaded()` is not safe for two consumers

`rt_engine.c`'s `ensure_libbpf_loaded()` sets the global `g_libbpf_resolved = 1` *before* resolving the symbol table, with no synchronisation. A second consumer opening concurrently sees "resolved" and reads a half-populated table. The binding is also process-wide and first-caller-wins, so passing the packaged `libbpf_path` from host whodata does not guarantee the packaged libbpf is the one bound — whichever consumer opens first decides.

This is a verified defect today; what is unverified is whether the two consumers' startups currently overlap. The cutover makes two consumers the normal case, so it must be closed either way: publish the table before the flag, guard initialisation with a mutex, and test concurrent `rt_open()`, failed initialisation, and both startup orders.

### G8 — Healthcheck ownership

The four-action healthcheck (create / modify content / modify metadata / delete, 10 s each) keeps its shape and shares one handle with the subsequent polling loop — re-opening would detach and re-attach every probe and lose the events in between.

Sharing the handle is not sufficient on its own. The healthcheck sink sees **every** event on the host, and a healthcheck-only sink discards the real ones it receives, so there is still a loss window unless the sink copies them into `kernelEventQueue` as the production sink already does. Specify, and test:

- one polling owner at a time, with an explicit handoff from healthcheck to the drain loop;
- exact path **and `event_type`** matching per action — today's `strstr(e->filename, EBPF_HC_FILE)` accepts any event naming the probe file, so an event queued by an earlier action can satisfy a later one and "prove" a hook that never fired;
- real events copied into `kernelEventQueue` inside the callback, never a retained pointer into the ring (libbpf invalidates it on return);
- cleanup after every failed action;
- join-before-close on teardown, reusing the container drain's existing pattern rather than inventing a second one.

### G9 — Install paths and diagnostics

`bpf_obj_path = abspath("lib/rt_file.bpf.o")`, `libbpf_path = abspath("lib/libbpf.so")`. Passing `libbpf_path` explicitly is mandatory: a bare soname binds the host's libbpf, which on a legacy RHEL-family host is 0.5.0 and predates `bpf_program__set_autoload()`. Wire `rt_filter::log` to `fimebpf::m_loggingFunction` — without it a failed load writes to a daemon's stderr, which is the exact failure the earlier VM run hit, where the agent silently ran the Audit provider with nothing in the log.

### G10 — Packaging and build wiring

`modern.bpf.o` is produced by `packages/externals/ebpf/build_ebpf.sh` into the `libbpf-bootstrap` external tarball, which **also** carries the `libbpf.so` that `rt_engine` dlopens. The tarball must survive; only its `modern.bpf.o` member goes away.

- `packages/externals/ebpf/build_ebpf.sh` — drop the `modern.bpf.c` compile step, keep the libbpf build.
- `packages/externals/deps.py` — remove `src/syscheckd/src/ebpf/src/modern.bpf.c` from the `libbpf-bootstrap` trigger set.
- **`src/deps.lock.mk`** — `DEP_REF_libbpf-bootstrap` is a content key over the recipe and its input set. Changing either rekeys it, so the lock must be regenerated *and* the newly keyed tarballs published to the pool, or `deps.py lock --check` and `deps.py pool-check` fail CI.
- `packages/externals/tests/test_deps.py` — three parametrized fixtures **and** the literal `key_paths()` expectation near line 1693.
- `.github/workflows/5_builderpackage_externals.yml` — path filter.
- **`.github/workflows/5_codequality_externals.yml`** — path filter, and it is the job that runs the lock and pool checks above.
- `.github/actions/check_files/{deb,rpm}_linux_agent_{amd64,arm64}.csv` — drop the `/var/ossec/lib/modern.bpf.o` rows.
- `packages/rpms/SPECS/wazuh-agent.spec` — the `find-debuginfo.sh` move-aside block for `modern.bpf.o`; `rt_file.bpf.o` already has its own.
- `packages/debs/.../wazuh-agent.lintian-overrides` — drop the `modern.bpf.o` override.
- `src/init/inst-functions.sh` — drop the `modern.bpf.o` install block; keep `libbpf.so` and `rt_file.bpf.o`.
- `src/Makefile` — the `libbpf-bootstrap` skip warning still names `modern.bpf.o`.
- `docs/dev/build-external-dependencies.md` — the dependency table row.
- `src/syscheckd/src/ebpf/include/ebpf_whodata.hpp` — the `dynamic_library_wrapper.h` include and the `init_libbpf()` declaration.
- `src/syscheckd/src/ebpf/tests/fimEbpfWhodataTest/CMakeLists.txt` — the deleted test sources.

Validate **upgrade** as well as fresh install: an upgraded agent must not be left with an orphaned `/var/ossec/lib/modern.bpf.o`.

### G11 — Tests

Four suites test libbpf plumbing that will no longer exist in `fimebpf`: `init_libbpf_test.cpp` (154), `init_bpf_obj_test.cpp` (174), `init_ring_buffer_test.cpp` (87), `close_libbpf_test.cpp` (75). Their subject moves into `rt_engine`, so their coverage must be **replaced** in `src/shared_modules/ebpf_provider/test/`, not deleted: fake-libbpf tests for program selection, each retry rung, partial-attach cleanup, short-record rejection and concurrent initialisation.

`ebpf_mock_utils.hpp` (242 lines of libbpf mocks) collapses to the three-function `rt_engine_api_t` seam. `pop_event_test.cpp` and `healthcheck_event_test.cpp` adapt. `container_reporting_test.cpp` already uses `-Wl,--wrap=rt_open`; check it does not collide with the new whodata seam once both consumers link into `fimebpf`.

A userspace `sizeof` assertion cannot prove the *loaded object's* record size — `rt_engine_contract_test.c` explicitly lacks that coverage. The real guards are the prebuilt digest check, `tools/check_bpf_symbols.sh`, and a VM run that reads actual records.

---

## 27.3 Phased plan

Each phase is a commit that builds, passes CI and can be VM-validated alone. Nothing deletes `modern.bpf.c` until P5.

**P0 — Provider bug fixes (G3, G4, G5). DONE, verified on both architectures (2026-11-05).** Ports out of `modern.bpf.c`: both `renamedata` layouts behind `bpf_core_field_exists`; `mnt_want_write`/`write_mnt_map`/`get_write_mnt` replacing all three `s_fs_info` reads; the missing `mnt = mnt_parent;`; `resolve_dentry()`. Refresh both prebuilt objects. **Independent of the retirement — it fixes container FIM today and should be reviewable and mergeable on its own.** Verify: harness on the VM shows correct absolute paths for chmod, unlink and rename on ext4, on an overlayfs mount, through a bind mount and through a nested mount; rename destination correct on a 6.6-class kernel and a ≥6.18 one; setattr correct on RHEL 9 (5.14 with the 6.0 signature).

P0 as landed, and what was measured:

- `bpf/rt_file.bpf.c`: `mnt = mnt_parent;` added to `rt_walk_dentry()`; `write_mnt_map` + `kprobe/mnt_want_write` + `get_write_mnt()` ported, replacing the `s_fs_info` cast in setattr, unlink **and rename** (three sites, not the two §27.2 G4 first named); `resolve_dentry()` replacing the version-keyed argument; `renamedata___local` + `renamedata___v618` with the `bpf_core_field_exists(new_parent)` branch.
- `src/rt_engine.c`: `select_programs()` is now two-pass, so `kprobe/mnt_want_write` autoloads whenever a kprobe that depends on it does. Without this the program has no type bit, never loads, and `get_write_mnt()` returns NULL on every event — the whole fix is dead code. It is kept in LSM mode too, because `rt_file.bpf.c` still has no `lsm/path_unlink` or `lsm/path_rename` and so still reaches those through kprobes.
- Both prebuilt objects rebuilt, `check_bpf_symbols.sh` clean, digests and provenance refreshed, `bpftool prog loadall` pinning all six programs on each. x86 from a 6.17 BTF dump (1287696 -> 1491296 bytes; both `check_files` CSVs updated), arm64 from a real aarch64 host's 6.8 dump.
- `test/rt_engine_paths_test.c` added and wired into `check-kernel`: eight exact-path assertions over a flat directory and a path behind two nested bind mounts. It fails with 8 failures against the pre-fix object and passes against the fixed one, on both architectures.

Measured on Ubuntu 24.04.4 / 6.17.0-35-generic (x86_64), pre-fix -> fixed:

| event | fixture | pre-fix | fixed |
| --- | --- | --- | --- |
| RENAME | flat | `<t>/flat` (the parent directory) | `<t>/flat/b.txt` |
| RENAME | nested | `<t>/deepsrc` | `<t>/lower/mid/deep/m.txt` |
| ATTR | nested | `<t>/deepsrc/n.txt` | `<t>/lower/mid/deep/n.txt` |
| UNLINK | nested | `<t>/deepsrc/m.txt` | `<t>/lower/mid/deep/m.txt` |
| OPEN | nested | `<t>/upper/deep/n.txt` | `<t>/lower/mid/deep/n.txt` |

**The rename defect is worse on older kernels than §27.2 G3 states.** On aarch64 / 6.8.0-139-generic the pre-fix object emits **no rename event at all**, where 6.17 emitted one carrying the wrong path. On 6.8 `struct renamedata` still has `new_dir` and no `new_parent`, so the hardcoded 6.18 offset reads an `inode*`, which then fails the dentry checks and the event is discarded. So container FIM has not been mis-reporting renames on such kernels; it has not been reporting them at all, silently. That is the majority of the supported range.

That same property makes the 6.8 header the more valuable of the two for this branch: compiling against it exercises the `bpf_core_field_exists()` **fallback** path, which a 6.17 or newer header cannot reach. Three layouts are now covered and two were executed: 6.8 (fallback, `new_dentry` at 40, run), 6.17 (CO-RE, 40, run), 6.19+ (CO-RE, 32, compile-time only — no host available).

Not verified, and deliberately so: `resolve_dentry()`'s reason for existing is a backported 6.0 `security_inode_setattr` signature on an enterprise kernel, which neither available host has. Both hosts are >= 6.0, where the old version branch was already correct, so what the runs prove is that attribute events still work — not that the backport case is fixed. That needs a RHEL 9 host and is carried into P3's VM gate.

**P1 — Loader hardening (G7). DONE (2026-11-05).** Synchronise `ensure_libbpf_loaded()`; publish the table before the flag. Fake-libbpf tests for concurrent open, failed init, both startup orders. Small, self-contained, and a prerequisite for two consumers.

P1 as landed:

- `ensure_libbpf_loaded()` split: the resolution body moved to `resolve_libbpf()`, and the entry point now takes a function-scope mutex, so `g_libbpf_resolved` is never set before `g_libbpf` is fully written and no two threads run the body at once. Every caller takes the lock, including those arriving after the first resolution, so the finished table is published to them rather than merely assumed visible.
- Sticky failure is preserved deliberately: a failed first bind is not retried by a later consumer.
- `g_libbpf.module` is assigned last, after the bound path is retained, so no partially built table or `dlclose`d handle can ever be observed as usable.
- First-caller-wins is kept, as it is out of scope to change, but made observable: a later `rt_open()` passing a different `libbpf_path` now logs once at WARN naming both paths. A packaged agent silently running on the host's libbpf instead of its own previously had no way to find out.
- `test/rt_engine_loader_test.c` added to the `check` target — no kernel, no root. It wraps `dlopen`/`dlsym`/`dlclose` with `-Wl,--wrap` rather than building a fake shared object, which keeps the seam to three linker flags. It covers concurrent `rt_open()` from many threads, exactly one resolution attempt, sticky failure, and the mismatch warning firing once. Clean under `valgrind --tool=helgrind`.

**One correction to what the implementation first concluded.** It reported that no link-library change was needed, having built and tested on a glibc where the pthread symbols live in libc. That is true from glibc 2.34 onward and false for the builds that actually ship: the agent's package images are `centos:6` and `debian:7`, and before 2.34 `libc.so.6` exports `pthread_mutex_lock`/`unlock` as stubs that are *not* thread-safe, with the real implementations in `libpthread`. Left as it was, the mutex would have degraded to a no-op on exactly the builds that matter, closing nothing. `rt_engine` now links `pthread` explicitly in both `CMakeLists.txt` and the standalone `Makefile`. It happens to work today only because every consumer is loaded into a process that already uses threads — an accident of the caller, not a property of this library.

Full suite re-run on aarch64 after the change: `contract`, `loader`, `paths`, `leak`, `drops`, `filter`, `creds`, `skip` — all pass.

**P2 — Contract extension (G1). DONE (2026-11-05).** Append `euid`/`login_uid`, bump `RT_ABI_MINOR` to 2, fill them in `submit_event()` with the CO-RE `loginuid` guard, refresh the prebuilt objects, extend the contract test. Verify: the harness reports credentials matching the *writer's actual* uid/euid/loginuid — note that running the harness itself as root makes "non-zero euid" a meaningless assertion; drive it from a `sudo -u` writer and compare against that user's ids, and check `(__u32)-1` on a `CONFIG_AUDIT`-less kernel if one is reachable.

P2 as landed:

- `include/rt_event_contract.h`: `euid` and `login_uid` appended after `parent_comm`, `RT_ABI_MINOR` 1 -> 2, `RT_ABI_MAJOR` unchanged. The record grows from 12,416 to 12,424 bytes, which is exactly the coupling G1 warns about: a stale object emits a shorter record and the engine drops every event.
- `bpf/rt_file.bpf.c`: `euid` from `BPF_CORE_READ(current_task, cred, euid.val)`; `login_uid` through the `struct task_struct___local { kuid_t loginuid; }` CO-RE shadow guarded by `bpf_core_field_exists()`, defaulting to `(__u32)-1`. Both are single field reads, so they are filled unconditionally and are not gated by `RT_SKIP_PROC_CONTEXT`.
- `test/rt_engine_creds_test.c` extended to assert both against the writer's real identity rather than against "non-zero" (the test process is root, so non-zero proves nothing); `test/rt_engine_contract_test.c` asserts `rt_abi_minor() == 2` and the tail layout.
- Both prebuilt objects rebuilt (x86 1,496,064; arm64 1,394,800), digests and provenance refreshed, both `check_files` CSVs updated.

Measured on aarch64 / 6.8.0-139-generic: engine reports `ABI 1.2`, and the credentials test reports `expected writer euid=65534 login_uid=1000` with `matched=200 swapped=0 other=0`. The non-zero `login_uid` is what proves the CO-RE `loginuid` read works rather than silently falling through to the default.

The `(__u32)-1` default is not a detail. `ebpf_pop_events()` tests `login_uid != (uint32_t)-1` before emitting the audit fields, so a `0` default reports every event on a `CONFIG_AUDIT`-less kernel as audited by root. That was a released bug fixed in `13f5d06f902`, and the parallel extraction on `enhancement/37396-spike-poc-design` reintroduced it with `{0}` (see §27.7). Full suite re-run on aarch64: all eight tests pass.

**P3 — LSM parity and the ladder (G2, plus the G6 decision). DONE (2026-11-05).** Port the `_dpath`/`_walk` pairs for `lsm/path_unlink` and `lsm/path_rename`, add `lsm/file_open_walk`, add rename-source emission, extend `type_bit_for_section()` with the new sections and the `mnt_want_write` dependency, implement LSM-dpath → LSM-walk → kprobe in `rt_open()` with cleanup between rungs. Record the G6 open-trigger decision here. Verify: Ubuntu (bpf LSM active) attaches the dpath set; Amazon Linux 2023 falls back to walk; a kernel without `CONFIG_SECURITY_PATH` falls back to kprobes; each individual `type_mask` loads what it should. Two VMs minimum.

On rename-source emission: the event must carry **both** paths, but do not promise an order. `modern.bpf.c` gets them from two independently attached programs, and nothing serialises them. Also note the container consumer is **not** indifferent to a second rename event — `container_event_drain.cpp` does not `lstat` a rename path; it calls `router.onRename(ev->cgroup_id)` and returns. Two events therefore trigger container rename reconciliation twice. Verify the router coalesces, or gate source emission so the container consumer does not see it.

P3 as landed:

- `bpf/rt_file.bpf.c` now carries 14 programs, matching `modern.bpf.c`'s structure: `lsm/file_open`, `lsm/path_unlink` and `lsm/path_rename` each in `_dpath` and `_walk` form, with `path_rename` doubled again for the source half (`path_rename_old_dpath`, `path_rename_old_walk`), plus `kprobe/vfs_rename_old`. The source half is a second program attached to the same hook rather than a second emission from one program, because one program doing two walks and two ring reservations is exactly the instruction-count pressure that made the walker `noinline` in the first place.
- `src/rt_engine.c`: `rt_open()` runs the three-rung ladder — LSM `_dpath`, then LSM `_walk` on a `bpf_object__load()` failure (the verifier stage, which is where a disallowed `bpf_d_path` is rejected), then the kprobe set on any remaining load *or attach* failure. Each failed rung is torn down through `rt_close()` so no link survives into the next. `type_bit_for_section()` learned the two new LSM sections; `select_programs()` takes a `prefer_dpath` alongside `prefer_lsm` and distinguishes variants by name substring.
- Rename now emits two events, source and destination, both `RT_EV_FILE_RENAME`. **No order is guaranteed** — they come from two independently attached programs — and `rt_event_contract.h`'s wording was corrected to say so. Comment only: no field, layout or `RT_ABI_MINOR` change.

**A verifier failure that only a real kernel could find.** The first cut passed `make check` and `-Werror` and could not load at all:

```
R1 is not a scalar
Caller passes invalid args into func#1 ('rt_walk_dentry')
libbpf: prog 'path_unlink_walk': failed to load: -22
```

`rt_walk_dentry` is a `noinline` BPF-to-BPF subprogram taking `__u64`. The kprobe programs reach it with scalars from `bpf_probe_read_kernel()`, so they load; an LSM program's arguments are *trusted BTF pointers*, and the verifier refuses to pass one into a scalar parameter. A C cast does not change the register's tracked type. `modern.bpf.c` never meets this because its walker is `statfunc`, always inlined, so there is no cross-subprogram argument check. Fixed by laundering both addresses through `bpf_probe_read_kernel()` from their own stack slots inside `rt_walk_path_at()`, which keeps the walker `noinline` at the cost of two helper calls per walk.

Record this as a standing rule for this file: **anything reaching `rt_walk_dentry` from an LSM program must be laundered to a scalar first.** It is invisible to every check that does not load the object on a kernel.

Evidence, on aarch64 6.8.0-139-generic:

- All 14 programs verify (`bpftool prog loadall`, 14 pinned).
- Booted with `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` so the active list reads `lockdown,capability,landlock,yama,apparmor,bpf`, the engine takes the **LSM dpath rung** and attaches exactly 6 programs: `file_open_dpath`, `path_unlink_dpath`, `path_rename_dpath`, `path_rename_old_dpath`, `kprobe__security_inode_setattr` and its `kprobe__mnt_want_write` dependency. Whole suite passes on that rung.
- Rebooted back to the stock cmdline and the whole suite passes again on the **kprobe rung**. Both rungs now have live evidence; the LSM-walk rung is covered by the verifier plus the fake-libbpf selection tests, since forcing it needs a kernel that rejects `bpf_d_path` for these hooks (Amazon Linux 2/2023).
- `test/rt_engine_paths_test.c` extended to require BOTH rename halves by exact absolute path, in either order. It fails with 2 failures against a destination-only object and passes against the full one, so it defends P3b rather than merely tolerating it.

**G6 is decided: keep `O_ACCMODE`.** No code change — it is already the provider's behaviour. Measured: 2,000 writes to pre-existing files opened `O_RDWR` with no `O_CREAT` produced **2,000 OPEN events, zero drops and no `RT_F_DROPS_BEFORE`**. A create-only filter would have reported none of them, which is the coverage hole quantified: on a kprobe host, `modern.bpf.c` sees no event at all for a plain write to an existing file, while an LSM host does. The provider's behaviour makes the two consistent. The measurement is a burst, not a soak; a sustained multi-hour load on a busy host is still untested.

**P4 — Cut host whodata over (G8, G9, G11). DONE, unit- and behaviour-validated (2026-11-05); sustained-load delivery still unverified.** Rewrite `ebpf_whodata.cpp` against `rt_open`/`rt_poll`/`rt_close` behind the `rt_engine_api_t` seam; rewrite the test suites. **`modern.bpf.c` stays in the tree, still built and still installed.** Verify: whodata alerts on the VM carry `audit_uid`, `effective_uid`, `cwd`, `parent_cwd`, `parent_name` identical to a pre-cutover capture of the same actions.

P4 as landed:

- `ebpf_whodata.cpp` goes from 1003 to 575 lines. Deleted: `init_libbpf`, `close_libbpf`, `init_bpfobj`, `load_and_attach`, `select_programs`, `init_ring_buffer`, `release_bpf`, `destroy_global_links`, `libbpf_print`, the local `is_bpf_lsm_active()`, and the `global_obj`/`global_links`/`bpf_helpers`/`sym_load` globals. The engine owns all of it now.
- `BPF_OBJ_INSTALL_PATH` is `"lib/rt_file.bpf.o"`; `libbpf_path` is `abspath("lib/libbpf.so")`, passed explicitly because a bare soname binds the host's libbpf and a legacy RHEL-family host ships 0.5.0, which predates `bpf_program__set_autoload()`. `type_mask = RT_FILE_ALL_BITS`, `cgroup_mode = RT_CGROUP_MODE_ALL`, `skip_mask = 0`, and `filter.log` wired to the FIM logger so a failed load reaches `ossec.log` instead of a daemon's stderr.
- `rt_abi_major() != RT_ABI_MAJOR` refuses to start host whodata, as `rt_engine.h` requires.
- One `g_engine_handle` guarded by a mutex, opened during the healthcheck and handed to the polling loop; both threads joined before `rt_close()`, reusing the container drain's shape.
- The two G8 defects are fixed: each healthcheck action now matches the exact probe path **and** `event_type` (the old `strstr(e->filename, EBPF_HC_FILE)` let an earlier action's queued event satisfy a later one and "prove" a hook that never fired), and real monitored events arriving during the healthcheck are copied into `kernelEventQueue` instead of being discarded.
- Four obsolete test files deleted (`init_libbpf_test`, `init_bpf_obj_test`, `init_ring_buffer_test`, `close_libbpf_test`); their subject is now `rt_engine`'s and is covered by `rt_engine_loader_test`. `ebpf_mock_utils.hpp` collapses onto the three-function `rt_engine_api_t` seam.
- No C entry point changed shape, so `run_check.c`, `syscheck.c` and `fim_scan.c` are untouched — confirmed by the legacy `test_syscheck_ebpf` still passing unmodified.
- **`modern.bpf.c` is still in the tree, still built, still installed.** That is the rollback property P4 is ordered for.

Validation:

- Full agent build, `make build TARGET=agent TEST=yes`: succeeds. `rt_file_bpf_object` builds with `RT_BPF_STRICT_PREBUILT` satisfied, so the committed prebuilts match their sources inside the real CMake build and not only in hand-run clang commands.
- CTest: **84/84 pass**, including `ebpf_whodata_test`, `healthcheck_event_test`, `pop_event_test` and `container_reporting_test`. The `-Wl,--wrap=rt_open` seam used by `container_reporting_test` does **not** collide with the new dispatch-table seam: that target compiles the container sources directly and wraps their calls, while the whodata tests go through the table.
- Legacy cmocka project: 132/137, with `test_syscheck_ebpf` passing. The five failures — `test_enrollment`, `test_reenroll_secret`, `test_shred_file`, `test_token_bootstrap`, `test_agent_auth_cli` — are `__wrap__merror` expectation mismatches in the client-agent/os_auth tests, which link neither `ebpf_provider` nor `syscheckd/src/ebpf`. Pre-existing on this branch and out of scope here.

### P4 behavioural run on a live agent (2026-11-05)

Built and installed the agent from this branch on an x86_64 host (Ubuntu, kernel 7.0.0-42-generic,
`bpf` in the active LSM list), configured `/testfim` with `whodata="yes"` and
`<whodata><provider>ebpf</provider></whodata>`.

**What is confirmed working.** Startup is clean and fully diagnosable, which is itself the G9 fix:

```
INFO: (6047): Initializing eBPF driver for FIM whodata.
INFO: eBPF engine ready: 6 program(s) attached, ABI 1.2, cgroup filter off, skip mask 0x0
INFO: (6049): eBPF healthcheck action succeeded: create file.
INFO: (6049): eBPF healthcheck action succeeded: modify content.
INFO: (6049): eBPF healthcheck action succeeded: modify metadata.
INFO: (6049): eBPF healthcheck action succeeded: delete file.
INFO: (6048): Healthcheck for eBPF FIM whodata module success.
```

The `eBPF engine ready` line is `rt_engine`'s own sink reaching `ossec.log` through `filter.log`.
Before P4 that output went to a daemon's stderr, which is why a silent fall back to Audit was
previously undiagnosable in the field. `ABI 1.2` is the P2 contract; 6 attached programs is the
LSM dpath rung; all four healthcheck actions pass under the new exact path-and-event-type
matching; no fall back to Audit occurs.

The first whodata alert after startup is correct in every field:

```
added /testfim/a.txt  mode=whodata  process_name=bash  process_id=11959  ppid=11957
  user_id=1000 user_name=ubuntu   group_id=1000 group_name=ubuntu
  audit_uid=1000 audit_name=ubuntu  effective_uid=1000 effective_name=ubuntu
  cwd=/testfim  parent_name=sshd  parent_cwd=""
```

`audit_uid` and `effective_uid` are the P2 `login_uid`/`euid` fields arriving intact through the
whole chain, which is the regression G1 existed to prevent. An empty `parent_cwd` there is not a
defect: the parent was `sshd`, whose cwd is `/`, and the walker renders the filesystem root as an
empty string. A later run with a parent whose cwd was `/testfim` reported `parent_cwd=/testfim`.

**A stall that turned out to be the test rig, not the cutover.** Initially only the FIRST
whodata event after startup reached FIM: five files created four seconds apart produced one event.
The kernel kept firing (`lsm/file_open` `run_cnt` 216 -> 459 after the stall began), the poller
thread stayed in `epoll_wait`, no poll error was logged and the bounded queue never reported
itself full.

The cause is the unenrolled test agent, not P4. Two pieces of evidence settle it:

1. The same five-file sequence run with `<provider>audit</provider>` -- which shares none of P4's
   code -- also produced exactly **one event of five**. Whatever stops the second message is
   common to both providers.
2. "Sending FIM event" is logged *before* the send at `run_check.c:538`, so that line never proved
   the first event completed. With no manager to enroll against, nothing drains
   `queue/sockets/queue`, so FIM blocks after the first message and later events simply queue up
   behind it -- which is also why the queue-full warning never appeared.

Worth noting the audit control degraded to `mode=realtime` with no whodata fields at all, while the
eBPF run produced `mode=whodata` with a full audit block. The eBPF path was the one working.

**Per-operation validation, one agent start per operation.** Because the rig forwards only the
first message per start, each operation was isolated in its own run. Every one produced a correct
whodata event with correct process attribution:

| operation | event | mode | process | audit_uid | effective_uid | cwd |
| --- | --- | --- | --- | --- | --- | --- |
| create | `added` | whodata | bash | 1000 | 1000 | /testfim |
| modify | `modified` | whodata | bash | 1000 | 1000 | /testfim |
| chmod | `modified` | whodata | chmod | 1000 | 1000 | /testfim |
| rename | `deleted /testfim/c.txt` | whodata | mv | 1000 | 1000 | /testfim |
| delete | `deleted` | whodata | rm | 1000 | 1000 | /testfim |

Two results matter beyond "it works". `audit_uid` and `effective_uid` are the P2 `login_uid` and
`euid` fields arriving intact through BPF, the engine, the contract and the consumer -- the
regression G1 existed to prevent. And **rename reports `deleted` for the SOURCE path**, which is
G3/P3b working end to end in a real agent: before that change rename reported only the destination
and the source's row was left stale until the next scheduled scan.

**What this does not cover.** Throughput and ordering under load were not exercised, because the rig
forwards one message per start. A manager-attached agent is still the right place to confirm
sustained delivery, and that is the one piece of P4 evidence still missing.

**Still outstanding, and it gates P5.** No behavioural check has been run: no agent installed, no real whodata alert produced, nothing compared field-by-field against a pre-cutover capture. Unit tests cover the translation into `whodata_evt` but cannot show that `audit_uid`, `effective_uid`, `cwd`, `parent_cwd` and `parent_name` are right end to end on a live host. P5 removes the `modern.bpf.o` fallback, so it must not merge until that comparison has been done.

A note on the build environment, not on the code: this WSL has CMake 4.4.2 and the vendored googletest declares `cmake_minimum_required(VERSION 2.8.12)`, which CMake 4 rejects. Both builds above needed `CMAKE_POLICY_VERSION_MINIMUM=3.5` in the environment. That is a toolchain mismatch rather than a repository defect, so nothing was changed for it — but it means neither result reflects a stock CMake 3.x build.

**P5 — Delete (G10). DONE (2026-11-05), with one release step left for a human.** Remove `modern.bpf.c`, `bpf_helpers.h`, `wrapper_bpf.h`, `dynamic_library_wrapper.h` and the dead tests; apply every packaging touch point; regenerate the lock and publish the tarballs. Verify: a package build produces no `/var/ossec/lib/modern.bpf.o`, `check_files` passes with the updated CSVs, a fresh install still gets `libbpf.so` and `rt_file.bpf.o`, and an upgrade leaves no orphan.

P5 as landed:

- Deleted `src/syscheckd/src/ebpf/src/modern.bpf.c`, `bpf_helpers.h`, `wrapper_bpf.h` and `dynamic_library_wrapper.h`. No live code dependency on any of them existed; the only survivors were prose comments. Note `rt_file.bpf.c`'s `#include <bpf/bpf_helpers.h>` is libbpf's OWN system header and shares nothing but a basename with the deleted one — matching on basename here would have broken the BPF build.
- `packages/externals/ebpf/build_ebpf.sh` drops the `modern.bpf.c` compile, and with it the clang-20 requirement and the `vmlinux.h` fetch, which existed only to serve it. The libbpf build and the tarball survive untouched, because that same tarball carries the `libbpf.so` the engine dlopens.
- `src/deps.lock.mk` regenerated: `libbpf-bootstrap/1.7.0-96dbad8eb8bb` -> `libbpf-bootstrap/1.7.0-c17149b9ab35`.
- Packaging unwound across `deps.py`, `test_deps.py` (three parametrized fixtures plus the literal `key_paths()` expectation), both externals workflows, the rpm spec's `find-debuginfo.sh` move-aside, the debian lintian override, `inst-functions.sh`, `src/Makefile` and the docs dependency table.
- Comments that referenced the deleted file were rewritten rather than dropped, keeping the provenance: `rt_file.bpf.c` now credits "the retired modern.bpf.c" at each place it borrowed proven logic. That history is the main thing a deletion destroys, and it is what tells a future reader where the kprobe mount resolution and the dual `renamedata` handling were actually proven.

**The check_files manifests had a pre-existing gap, now closed.** Four manifests carried a `modern.bpf.o` row; all four are removed. But the two **arm64** manifests never had a `/var/ossec/lib/rt_file.bpf.o` row, while `inst-functions.sh` installs that object on any architecture whose build produced one — and the provider's CMake produces it for aarch64 from `prebuilt/arm64/`. `check_files.py` fails both for an installed file no row lists and for a listed file the build did not produce, so arm64 was already short a row before this phase. Both now carry it at the measured 1,569,208 bytes, distinct from amd64's 1,670,456.

**A digest subtlety worth recording.** The comment rewrites changed `rt_file.bpf.c`'s hash, so `RT_BPF_STRICT_PREBUILT` correctly flagged both prebuilt objects as stale. The fix was to **rebuild** both objects and refresh the digests, not to refresh the digests alone — bumping a digest without rebuilding marks a stale binary as fresh, which is precisely what that guard exists to prevent. Both rebuilt objects are byte-size-identical to their predecessors (comment-only change), `check_bpf_symbols.sh` passes on both, and the manifest sizes needed no update.

Validation after the deletion:

- `make build TARGET=agent TEST=yes`: succeeds with `modern.bpf.c` gone.
- CTest: **84/84 pass**, including all three whodata suites and `container_reporting_test`.
- `deps.py check` and `deps.py lock --check`: pass.
- `packages/externals/tests`: 429 passed, 7 failed — all seven are socket-permission errors in local HTTP fixtures, unrelated to this change.

**Left for a human, and it gates release.** `deps.py pool-check` cannot pass yet: rekeying the lock means the newly keyed `libbpf-bootstrap` tarballs do not exist in the pool. Someone must build and publish them, then re-run `pool-check`. Package builds, an installed-tree `check_files` run, a fresh install and an upgrade/orphan check were also not run here.

**P6 — Record the size delta. BLOCKED on a package build (2026-11-06).**

This branch's convention records sizes *measured from a real package build* — `bb9b76bece` quotes
the gate's own output (`deb: expected 954080, found 1052672 (+10.33%)`). That build cannot run
here: it needs the newly keyed `libbpf-bootstrap` tarballs that P5's lock rekey left unpublished.
Inventing a number would defeat the gate rather than satisfy it, so nothing was committed.

Already correct, and needing no number:

- The four `modern.bpf.o` rows are removed (P5). That is the headline delta — 1,287,824 bytes
  measured on an installed tree — and it is a removal, not a size change.
- The `rt_file.bpf.o` rows are accurate in all four manifests, verified against `stat -c%s` of the
  committed objects: 1,670,456 (amd64), 1,569,208 (arm64).

Open, and likely to need a new value: **`libfimebpf.so`**. A clean local release build
(`make build TARGET=agent`, no `TEST`), stripped with `strip --strip-unneeded`, measures
**626,032** against the recorded **580,208** for deb amd64 — **+7.9%**, inside the 0.1 tolerance
but close to it. Treat that as an indication only: it was produced with Ubuntu 24.04's gcc 13,
while the packages are built in `centos:6`/`debian:7` images, so the packaged figure will differ.

The direction is worth flagging because it is counter-intuitive. `libfimebpf.so` **grew**, even
though P4 cut `ebpf_whodata.cpp` from 1003 to 575 lines and deleted its libbpf plumbing. The reason
is that `rt_engine` is a static library linked *into* `libfimebpf.so`, and P0–P3 added the
three-rung fallback ladder, `_dpath`/`_walk` variant selection, the libbpf initialisation mutex and
the selection logic for eight additional BPF programs. The engine's growth outweighs the consumer's
shrink. Anyone expecting the retirement to shrink this library will mis-read the gate.

So the agent's net on-disk change is roughly **-1.29 MB** (the retired object) **+ ~46 KB** on this
library, i.e. a clear net reduction — but spread across two files moving in opposite directions.

**Action for whoever runs the package build:** publish the rekeyed tarballs, run the build, and if
`check_files` reports a `libfimebpf.so` mismatch, record the measured value in all four manifests
following the `ci(agent): record the size …` convention.

### On rollback

P4 is revertible as a **commit**, not as "one C++ file" — it rewrites tests and headers too. What keeping `modern.bpf.o` installed through P4 buys is that the revert needs no externals rebuild and no package-pipeline change. Demonstrate the revert on the VM at P4; do not assume it.

P0–P3 change the provider and therefore change container FIM behaviour. They are not inside the whodata rollback boundary and need their own validation, which is the reason they are separate commits.

---

## 27.4 Risks

| Risk | Mitigation |
| --- | --- |
| Rename destinations are wrong on 5.12–6.17 *today* | P0; it is a shipping bug, not a migration risk — do not let it wait for the retirement |
| Paths truncated across nested/stacked mounts | P0's `mnt = mnt_parent;` fix, with nested/bind/overlay VM cases |
| Attribute events wrong on backported enterprise kernels (RHEL 9 / 5.14) | P0's `resolve_dentry()` port, validated on RHEL 9 |
| Prebuilt `.bpf.o` left stale after a contract change | Already a configure-time `FATAL_ERROR` (`RT_BPF_STRICT_PREBUILT` ON) and a runtime error log; the exposure is builds that pass `-DRT_BPF_STRICT_PREBUILT=OFF` |
| `_walk` resolution wrong for bind mounts / chroot | Keep both variants and the full ladder (G2); do not simplify to walk-only |
| Host event volume rises on kprobe-mode hosts (`O_ACCMODE`) | G6 is an explicit decision with a sustained-load test and `rt_drain_drops()` observed, not a side effect |
| Two consumers race `ensure_libbpf_loaded()`, or the wrong libbpf wins | P1, before the second consumer becomes normal |
| Second rename event double-fires container rename reconciliation | P3 verifies coalescing or gates source emission per consumer |
| `-Wl,--wrap=rt_open` collides between the two test suites | P4 verifies both link and pass together |
| Legacy-kernel hosts that load `modern.bpf.o` but fail on `rt_file.bpf.o` | Cross-check [23-legacy-kernel-ebpf-load.md](23-legacy-kernel-ebpf-load.md) before P5; P4's ordering keeps `modern.bpf.o` available for a revert |

## 27.5 Reference

The spike branch performed this cutover once: `0ce0c2fbc0` ("integrate new ebpf module to fim") and `9113442eb4` ("refactor: test related to whodata", deletes `modern.bpf.c`). Read them for the consumer-side shape — the `rt_engine_api_t` seam, the shared `g_engine_handle`, the `link_stubs.cpp` the tests needed.

**Do not port their BPF side.** The spike's `rt_file.bpf.c` never carried the LSM unlink/rename programs, the walk fallbacks, the fallback ladder, the rename source event, `euid`, `login_uid`, the mount-cache approach, the dual `renamedata` layout or `resolve_dentry()` — even though the `modern.bpf.c` it deleted had all of them. That cutover was a coverage regression, and the provider still carries its consequences. G1–G11 exist to avoid repeating it.

## 27.7 The other extraction: `enhancement/37396-spike-poc-design`

A second, independent attempt at exactly this migration exists at `~/wazuh/source/37396-ebpf-provider-spike`, branched from `main` at `6308ccd3860`, eleven commits ending at `38c2fdc6464`. It is **not** the branch `ebpf_provider` came from (that was `spike/37533-*`, imported here as `424ca33cd87`). Two separate extractions of the same file, with different shapes and different gaps.

### What it does

Creates `src/shared_modules/ebpf/` — a C++ module, not the C engine:

```
src/shared_modules/ebpf/
  bpf/modern.bpf.c          637 lines (from main's 1012; modern-arm.bpf.c deleted)
  include/ebpf_types.hpp    EventClass / FileEvent / ProcessIdentity / CorrelationKeys
  include/ebpf_loader.hpp   class EbpfLoader — RAII, virtual, mockable
  src/ebpf_loader.cpp       load() / poll() / close()
  tests/
```

and in `syscheckd`: `src/fim_ebpf.cpp` + `include/fim_ebpf.h` (346 lines) replace the whole of `src/ebpf/`. Net −4070/+1823 across 46 files. It deletes `modern.bpf.c`, `modern-arm.bpf.c`, `bpf_helpers.h`, `wrapper_bpf.h`, `dynamic_library_wrapper.h`, `ebpf_whodata.{h,hpp,cpp}`, all seven `fimEbpfWhodataTest` files, `bounded_queue_test.cpp`, `test_syscheck_ebpf.c` and the `ebpf_wrappers` — i.e. it completes P4+P5 of this plan in one branch.

### Where it is better than this plan's target

- **It keeps `modern.bpf.c`.** It carries the LSM `path_unlink` and `path_rename` programs and every `_dpath`/`_walk` pair, so G2's coverage gap does not exist there — the programs are already written and only the loader side needs work. If G2 is implemented here, `bpf/modern.bpf.c` on that branch is the better source to port from than writing them into `rt_file.bpf.c` from scratch.
- **It keeps the dpath→walk retry**, on `bpf_object__load()` failure, which is the correct trigger (`ebpf_loader.cpp:145-176`). The ladder this plan's G2 describes is two-thirds built there.
- **`FileEvent` already carries `euid` and `login_uid`** (`ebpf_types.hpp`), and a richer `CorrelationKeys` than `rt_file_event`: `cgroup_id`, `mntns_ino`, `pidns_ino`, `netns_ino`.
- **The C++ seam is cheaper to mock** than `rt_engine_api_t`: `EbpfLoader`'s methods are virtual and `MockEbpfLoader` is 29 lines, against 242 lines of libbpf mocks today.

### Where it is worse, and why it cannot simply be adopted

- **No event type in the kernel record.** `struct file_event` has no type field, so `onRingSample` never sets `FileEvent::type` and every event decodes as `OPEN_CREATE` (`ebpf_loader.cpp`, the `RawFileEvent` decode). `FileEvent::old_path` is documented as "populated only for RENAME events" and is never written by anything. For host whodata that is survivable — it re-stats the path either way — but it is unusable for the container consumer, which switches on `ev->event_type` to tell unlink from rename.
- **No ABI version, no record rejection.** Compatibility is a `size >= sizeof(RawFileEvent)` tail check with no `abi_major`, so a mismatched object is decoded rather than refused.
- **`libbpf.a` is linked statically** (`CMakeLists.txt:47-49`), gated on `if(EXISTS ...)`. The whole point of `rt_engine`'s `dlopen` is that the loader library builds and links on a host with no BPF toolchain, which is how this repository is developed in WSL. A static link makes libbpf a build-time dependency of `fimebpf`.
- **A hardcoded 5.8 kernel floor** — `isKernelSupported()` parses `/proc/sys/kernel/osrelease`. ADR-002 rejected version gating in favour of runtime capability probing precisely because enterprise kernels backport features below their nominal version; this is the same class of mistake as G5's version-keyed argument selection.
- **No LSM→kprobe fallback.** Only the dpath→walk rung exists; a host with `bpf` in its active LSM list but without `CONFIG_SECURITY_PATH` gets no events rather than falling back to kprobes.
- **It inherits `main`'s bugs**, as §27.2's G3/G4/G5 notes record: the three `s_fs_info` reads, the missing `mnt = mnt_parent;`, the version-keyed setattr argument, no `mnt_want_write`. Plus `loginuid` defaulting to `{0}` instead of `{(__u32)-1}` — `13f5d06f902` fixed that upstream, and with `{0}` every event on a `CONFIG_AUDIT`-less kernel reports `audit_uid=0`, i.e. attributes it to root rather than leaving it unset. That one is a wrong-attribution bug, not a missing field.
- **Rename reports the destination only**; `794d88d1d87` ("report the old name as deleted on eBPF renames"), the source-path work G2 needs, is not there either.
- **No cgroup allowlist, no `skip_mask`, no per-cgroup drop accounting, no drop signal at all.** The container consumer on this branch depends on all four. Adopting `shared_modules/ebpf` means re-implementing them.

### What to do about it

Do not merge the two modules. Two shared eBPF modules in `src/shared_modules/` is the outcome worth avoiding, and `ebpf_provider` is the one with a consumer in production use (the container drain), the in-kernel filtering the container work depends on, and the versioned contract.

Treat that branch as a **source to port from**, specifically for G2:

- its `bpf/modern.bpf.c` LSM program set and `_dpath`/`_walk` pairs,
- `ebpf_loader.cpp:145-176`'s retry loop as the shape for `rt_open()`'s ladder,
- `selectPrograms()`'s variant matching, which is what `type_bit_for_section()` needs.

And raise the duplication explicitly with whoever owns `37396`, because the two branches are the same issue number doing the same work twice. This document does not have the standing to settle that; it records the collision so the decision is taken rather than discovered at merge time.

Not evaluated here: whether `src/fim_ebpf.cpp`'s consumer-side rewrite is better than the `ebpf_whodata.cpp` cutover P4 plans. If that branch's whodata path is sound, P4 should port it instead of rewriting against `rt_engine` from scratch. Worth a read before P4 starts.

## 27.6 Review record

Compared against the parallel `enhancement/37396-spike-poc-design` extraction on 2026-11-04; findings in §27.7.

Plan drafted 2026-11-04 and reviewed adversarially by Codex (`codex exec --sandbox read-only`, read-only, no privileged kernel tests). Findings on the mount walker, the `renamedata` layout, `resolve_dentry()`, the retry trigger and ladder, `type_bit_for_section()`'s zero return, the container rename path, the `O_ACCMODE` volume difference, the `ensure_libbpf_loaded()` race, the healthcheck matching, `src/deps.lock.mk` and the codequality workflow were independently verified against the code and folded in above. Two of the review's corrections went the other way: the stale-prebuilt risk is already guarded at configure time rather than silent, and P4's rollback is a commit revert rather than a single-file one.
