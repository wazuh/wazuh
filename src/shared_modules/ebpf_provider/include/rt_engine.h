/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) consumer-facing API. A consumer (FIM today; IT
 * Hygiene or anything else later) only ever calls these three functions —
 * no eBPF-specific code path beyond this. Adding a new consumer, or a
 * consumer wanting a different subset of FILE event classes, requires
 * nothing here: it's driven entirely by the `rt_filter` passed to rt_open().
 */

#ifndef RT_ENGINE_H
#define RT_ENGINE_H

#include "rt_event_contract.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* rt_handle_t;

typedef void (*rt_sink_fn)(const struct rt_file_event* ev, void* user);

/* Severity passed to rt_log_fn. Deliberately its own small enum rather than
 * Wazuh's log levels: the engine is consumer-agnostic, so mapping these onto
 * mdebug1/merror/etc. is the consumer's job. */
enum rt_log_level
{
    RT_LOG_ERROR = 0,
    RT_LOG_WARN  = 1,
    RT_LOG_INFO  = 2,
    RT_LOG_DEBUG = 3,
};

/* Diagnostics sink. Without one, the engine writes to stderr — which for a
 * daemonised agent means nowhere: a failed eBPF load would never reach
 * ossec.log, so "eBPF unavailable, falling back to periodic rescan" would be
 * undiagnosable in the field. `msg` is a NUL-terminated single line with no
 * trailing newline, valid only for the duration of the call. May be called
 * from whichever thread is inside rt_open/rt_poll/rt_close. */
typedef void (*rt_log_fn)(int level, const char* msg, void* user);

struct rt_filter
{
    /* Bitmask of (1u << rt_event_type). Only the BPF programs needed to
     * satisfy the requested classes are loaded/attached for THIS handle —
     * two consumers with different masks get two independent loads, each
     * with its own ring buffer (spike #37396 ADR-001: no shared provider,
     * no cross-consumer stalling). */
    unsigned int type_mask;

    /* Absolute (or CWD-relative, caller's choice) path to the compiled BPF
     * object. NULL falls back to a bare "rt_file.bpf.o" lookup in the
     * process's CWD — fine for the standalone test harness, wrong for a
     * real service (a systemd-managed agent's CWD isn't its install dir).
     * A production consumer MUST resolve this itself (e.g. FIM already has
     * an abspath() callback for exactly this) — the engine deliberately
     * has no opinion on Wazuh's install-path layout, per the
     * consumer-agnostic constraint. */
    const char* bpf_obj_path;

    /* Optional diagnostics sink; NULL keeps the stderr behaviour. */
    rt_log_fn log;
    void* log_user;
};

#define RT_FILE_OPEN_BIT   (1u << RT_EV_FILE_OPEN)
#define RT_FILE_ATTR_BIT   (1u << RT_EV_FILE_ATTR)
#define RT_FILE_UNLINK_BIT (1u << RT_EV_FILE_UNLINK)
#define RT_FILE_RENAME_BIT (1u << RT_EV_FILE_RENAME)
#define RT_FILE_ALL_BITS   (RT_FILE_OPEN_BIT | RT_FILE_ATTR_BIT | RT_FILE_UNLINK_BIT | RT_FILE_RENAME_BIT)

/* Loads and attaches only the BPF programs needed to satisfy `filter`,
 * probing kernel capabilities at runtime (does the object load at all —
 * see rt_engine.c's doc comment on why this validation build doesn't do a
 * separate pre-flight ringbuf probe — and whether "bpf" is in the active
 * LSM list) instead of gating on a hardcoded kernel-version floor.
 *
 * Returns NULL on any failure (missing capability, load/attach error) and
 * never aborts the caller's process — the expected behavior on failure is
 * for the consumer to fall back to a non-eBPF path (e.g. FIM's existing
 * audit provider), exactly like today's eBPF-whodata failure handling.
 */
rt_handle_t rt_open(const struct rt_filter* filter);

/* Polls for up to timeout_ms milliseconds, invoking sink(event, user) once
 * per matching event delivered in that window. Returns the underlying
 * ring_buffer__poll() return code (negative on a real error; 0 or positive
 * is the event count processed, per libbpf's convention). Not thread-safe
 * to call concurrently on the same handle from two threads. */
int rt_poll(rt_handle_t handle, rt_sink_fn sink, void* user, int timeout_ms);

/* Detaches and frees everything opened by rt_open(), including every
 * bpf_link, so the programs are actually detached rather than left attached
 * for the life of the process. Safe to call with handle == NULL. */
void rt_close(rt_handle_t handle);

/* Reports one cgroup's dropped-event count. `drops` is the number lost since
 * the previous drain for that cgroup, never a running total. */
typedef void (*rt_drop_fn)(unsigned long long cgroup_id, unsigned int drops, void* user);

/* Drains per-cgroup drop accounting, invoking cb() once per cgroup that lost
 * events since the last drain, and clearing what it reports.
 *
 * Why this exists. Every event carries `dropped` and RT_F_DROPS_BEFORE, which
 * makes loss visible but NOT attributable: the in-band counter is global, so a
 * consumer seeing the flag knows only that the node lost events, not which
 * containers to re-read. Measured on a real node, 203 dropped events surfaced
 * as three flag-bearing events — a consumer treating that as "re-check
 * everything" would re-baseline every container three times for a 0.1% loss
 * belonging to one cgroup. Drain this instead, and re-read only what it names.
 *
 * Cheap enough to call on the consumer's own cadence (once per poll cycle is
 * fine): it touches only the cgroups that have actually lost events, because
 * reporting a cgroup removes its entry.
 *
 * A drop that arrives while the in-kernel map is full is still counted in the
 * global in-band counter, so loss never becomes invisible — only unattributed.
 *
 * Returns the number of cgroups reported, 0 when nothing was lost, or -1 on a
 * bad handle or a BPF object with no per-cgroup map (an object older than this
 * engine — reported once through the log sink, not on every call). Safe with
 * cb == NULL, which discards the counts and just clears the map. */
int rt_drain_drops(rt_handle_t handle, rt_drop_fn cb, void* user);

/* The ABI this engine was compiled against, for a consumer that may have been
 * built against a different copy of rt_event_contract.h than the engine it is
 * linked to. A consumer MUST refuse to use an engine whose major differs from
 * its own RT_ABI_MAJOR: the event record is exchanged by raw memory
 * reinterpretation, so a layout change is silent otherwise.
 *
 * The engine applies the same rule to the BPF object at runtime, per event,
 * since the object is a separate build artefact: a record whose abi_major does
 * not match, or which is shorter than this build's struct, is dropped rather
 * than handed to the sink, and reported once per handle. */
int rt_abi_major(void);
int rt_abi_minor(void);

/* Non-zero when this host uses cgroup v1, i.e. when bpf_get_current_cgroup_id()
 * — and therefore every event's cgroup_id — is not a usable correlation key
 * and mnt_ns must be used instead (spike #37396 ADR-002). Determined once at
 * rt_open() from the cgroup mount layout, not from the events.
 *
 * NOTE: the per-event RT_F_CGROUP_V1 flag is NOT yet set by the BPF program;
 * this accessor is currently the only reliable source. See rt_engine.c. */
int rt_host_cgroup_v1(rt_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* RT_ENGINE_H */
