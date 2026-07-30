/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Live container FIM (spike #37533): continuous counterpart to
 * container_baseline_fim.h's one-shot startup baseline. Where the baseline
 * only ever captures files present *before* eBPF monitoring started, this
 * handles ongoing create/modify/delete activity inside already-baselined
 * (or newly-discovered) containers, keeping wazuh-states-fim-files in sync
 * for the lifetime of the container, not just at agent startup.
 */

#ifndef CONTAINER_LIVE_FIM_H
#define CONTAINER_LIVE_FIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Handle one raw file-activity event whose path matched a configured
 * `<directories tags="container">` prefix (see ebpf_whodata.cpp's
 * matches_container_prefix()).
 *
 * Resolves `cgroup_id` to a container identity via the container_instances
 * module's query socket, translates the kernel-reported path (which is in
 * the writer's own mount-namespace view, not necessarily the host's) to a
 * host-openable path via /proc/<pid>/root/<kernel_path>, and upserts or
 * deletes exactly one wazuh-states-fim-files row for that (container_id,
 * path) — reusing the same fim_persist_baseline_row()/
 * validate_and_persist_fim_event() path the #37532 baseline already syncs
 * through, so a live container file change behaves like a normal FIM change
 * rather than a separate mechanism.
 *
 * Also emits the stateless alert (collector "file", carrying `changed_fields`
 * for modifications) that fim_persist_baseline_row() itself never produces —
 * see send_container_stateless_event() in container_live_fim.cpp, which
 * reuses file.c's own fim_attributes_json()/fim_calculate_dbsync_difference()
 * so a container file alert has the same shape as a host FIM alert, with
 * container/kubernetes enrichment attached. Sent for added/modified/deleted;
 * "modified" alerts are suppressed if the diff turns out empty (e.g. only a
 * bookkeeping column changed). Not yet implemented: report-changes/content
 * diff for container files (`owner`/`group` names are never populated either,
 * since that needs the container's own /etc/passwd — a separate, unaddressed
 * data class).
 *
 * This is intentionally called from its own worker thread (see
 * ebpf_pop_container_events() in ebpf_whodata.cpp), never from the
 * ring-buffer-draining thread: resolving container identity can block on
 * IPC to container_instances for up to ~1s on a cold cache.
 *
 * No-op (drops the event, logging at most once per condition) when:
 *  - FIM synchronization is disabled (syscheck.enable_synchronization).
 *  - container_instances can't resolve cgroup_id yet (cold cache / module
 *    not running) — matches the eBPF event contract's own "never block on
 *    a pending lookup" guidance (spike #37396 event-contract-spec).
 *  - cgroup_id resolves to "not a container" — e.g. a hostPath volume whose
 *    source directory is also monitored by regular host FIM. Deduplicating
 *    this against the host FIM path is an open question in #37533 itself;
 *    this slice always drops rather than falling back to host semantics,
 *    since the kernel-reported path can't be trusted as a host path.
 *  - the PID that triggered the hook has already exited *and* no other live
 *    PID exists in the same container anymore (falls back to
 *    wazuh::container_baseline::ResolvePidsForContainer() first — the same
 *    resolver the #37532 baseline uses — since any live PID in the container
 *    shares its mount namespace and is equally valid for /proc/<pid>/root
 *    purposes; only drops if that also comes up empty, meaning the container
 *    itself is gone). The original PID being dead by processing time turned
 *    out to be the dominant real-world case, not a rare race — see
 *    container-fim-syscollector-test-plan-and-results.md finding #3.
 *
 * @param cgroup_id cgroup-v2 unified cgroup id from the eBPF event (0 or a
 *                  cgroup-v1-ambiguous constant on cgroup-v1 hosts — see the
 *                  file_event.cgroup_id comment in modern.bpf.c).
 * @param mnt_ns Mount-namespace inode from the eBPF event. Not yet used for
 *               resolution (container_instances has no mnt_ns-based lookup
 *               yet); carried through for future use / diagnostics.
 * @param pid PID that triggered the kernel hook.
 * @param kernel_path Kernel-reported absolute path, in pid's own mount-ns view.
 * @param inode Inode number reported by the kernel hook (diagnostic only —
 *              the authoritative inode for the persisted row comes from
 *              stat()-ing the resolved host path).
 * @param dev Device number reported by the kernel hook (diagnostic only,
 *            same caveat as inode).
 */
void fim_handle_container_whodata_event(uint64_t cgroup_id,
                                        uint32_t mnt_ns,
                                        uint32_t pid,
                                        const char* kernel_path,
                                        uint64_t inode,
                                        uint64_t dev);

#ifdef __cplusplus
}
#endif

#endif /* CONTAINER_LIVE_FIM_H */
