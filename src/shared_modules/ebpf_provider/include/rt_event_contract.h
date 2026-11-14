/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module event contract (#37396). This header is included by BOTH the
 * BPF program (bpf/rt_file.bpf.c, compiled with `clang -target bpf`) and the
 * userspace engine/consumers (src/rt_engine.c, test harness) — one struct
 * definition, not two hand-synced copies. Deliberately avoids <stdint.h>:
 * clang's freestanding `-target bpf` mode can't resolve the glibc header
 * chain stdint.h pulls in (fails on <bits/libc-header-start.h>), so this
 * uses plain built-in integer types instead of uint16_t/uint32_t/uint64_t —
 * same size and alignment on the x86_64/arm64 targets this ships for, and
 * the struct is read via raw memory reinterpretation on both sides anyway,
 * not by typedef identity.
 *
 * Scope for this pass: FILE event classes only (open/create, attribute
 * change, unlink, rename). Process-exec and network event classes are a
 * separate issue's scope, not added here.
 *
 * Besides the event record, this header carries the rest of the contract the
 * two sides must agree on byte for byte: the filter_cfg map keys and the
 * values userspace writes into them. Those used to be duplicated in
 * bpf/rt_file.bpf.c and src/rt_engine.c with a "must stay in step" comment,
 * which is a comment and not a mechanism.
 */

#ifndef RT_EVENT_CONTRACT_H
#define RT_EVENT_CONTRACT_H

/* Versioning (spike #37396 ADR-003 rule): append fields -> bump MINOR only
 * (old consumers ignore the tail). Reorder/resize/remove a field -> bump
 * MAJOR (a consumer must refuse to open a mismatched-MAJOR engine). Every
 * event also carries abi_major so a consumer that opened the engine before
 * a live reload can still detect a mismatch. */
#define RT_ABI_MAJOR 1
#define RT_ABI_MINOR 2
/* MINOR 1: added cwd/parent_cwd/parent_comm. Purely additive (appended
 * after the existing fields) — found missing when starting the FIM
 * cutover: host FIM's existing whodata "who" attribution (dynamic_file_
 * event/whodata_evt) depends on these for its stateless alerts, and the
 * first cut of this contract dropped them. Consumers built against MINOR 0
 * still work unmodified; they just never read the new tail fields. */

/* MINOR 2: added euid/login_uid after parent_comm so host FIM whodata
 * retains effective-user and audit-user attribution. Consumers built against
 * MINOR 1 still work unmodified; they just never read the new tail fields. */

enum rt_event_type
{
    RT_EV_FILE_OPEN   = 1, /* create, or open with write intent */
    RT_EV_FILE_ATTR   = 2, /* chmod/chown/truncate/utimes */
    RT_EV_FILE_UNLINK = 3,
    /* A rename produces two events, naming source and destination in
     * unspecified order. */
    RT_EV_FILE_RENAME = 4,
};

enum rt_flags
{
    /* Reserved: rt_file.bpf.c never sets it. Whether cgroup_id identifies a
     * container is a property of the handle, so ask rt_cgroup_id_is_usable().
     * On a cgroup v1 host it does once rt_set_cgroup_v1_subsys() points the
     * program at a controller, and cgroup_id is then that controller's id. */
    RT_F_CGROUP_V1    = 1 << 0,
    /* One or more events were dropped (ring buffer full, or this consumer's
     * own queue was full) before this one — makes loss visible in-band
     * instead of only in a one-shot log line. */
    RT_F_DROPS_BEFORE = 1 << 1,
};

#define RT_PATH_MAX 4096
#define RT_COMM_MAX 32

/* Fixed-size record for every FILE_* event class. A future event class
 * (process-exec, network) would get its own struct plus a new type value
 * in rt_event_type — not a change to this one. */
struct rt_file_event
{
    unsigned short abi_major;
    unsigned short event_type;   /* enum rt_event_type */
    unsigned short flags;        /* enum rt_flags bitmask */
    unsigned short _reserved0;
    unsigned long long timestamp_ns; /* CLOCK_BOOTTIME-equivalent (bpf_ktime_get_boot_ns) */

    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;

    unsigned long long inode;
    unsigned long long dev;

    /* Correlation keys (#37533 consumes these; the engine has no idea what
     * a "container" is, per the consumer-agnostic constraint). */
    unsigned long long cgroup_id;
    unsigned int mnt_ns;
    unsigned int dropped; /* engine-side running drop counter at emit time */

    char comm[RT_COMM_MAX];
    char filename[RT_PATH_MAX];

    /* MINOR 1 additions — see the RT_ABI_MINOR comment above. */
    char cwd[RT_PATH_MAX];
    char parent_cwd[RT_PATH_MAX];
    char parent_comm[RT_COMM_MAX];

    /* MINOR 2 additions — see the RT_ABI_MINOR comment above. */
    unsigned int euid;
    unsigned int login_uid;
};

/* ---- filter contract -------------------------------------------------- *
 *
 * `filter_cfg` is a 3-entry BPF_MAP_TYPE_ARRAY: scalars in an array rather
 * than one struct value, so rt_set_cgroup_mode() can rewrite the mode on a
 * live handle without a read-modify-write of anything else. */
#define FILTER_CFG_KEY_MODE 0
#define FILTER_CFG_KEY_SKIP 1

/* Which cgroup v1 controller hierarchy to read a container's cgroup id from,
 * stored as index+1 so that an unwritten slot — array maps start zeroed —
 * means "not configured" and stays distinguishable from subsystem 0, which is
 * a real controller (cpuset).
 *
 * Unset is the normal case: on a unified or hybrid host
 * bpf_get_current_cgroup_id() already reports a usable per-cgroup id and this
 * path is never taken. */
#define FILTER_CFG_KEY_V1_SUBSYS 2

/* An upper bound for the verifier, not a kernel limit. CGROUP_SUBSYS_COUNT is
 * build-dependent (15 on the hosts measured); anything at or above this is
 * refused rather than read. */
#define RT_V1_SUBSYS_MAX 64

/* Value for FILTER_CFG_KEY_SKIP. Skip the process-context fields: cwd,
 * parent_cwd and parent_comm. They cost two full dentry walks per event,
 * which on the kprobe path — the majority configuration — is the dominant
 * per-event cost. The fields are still present in the record and still
 * null-terminated; they simply arrive empty, so a consumer that sets this
 * must not read them. `ppid` is unaffected: it is a single field read, not a
 * walk. */
#define RT_SKIP_PROC_CONTEXT (1u << 0)

/* Value for FILTER_CFG_KEY_MODE.
 *
 * A filtered-out event is NOT counted as a drop. Drops mean "the consumer
 * wanted this and lost it"; a filter miss means "the consumer never asked".
 * Conflating them would make every unfiltered container's activity look like
 * loss and trigger endless re-baselining. */
enum rt_cgroup_mode
{
    /* Submit every event. What host whodata needs: it is not container-scoped
     * and must see the whole node. The default. */
    RT_CGROUP_MODE_ALL = 0,

    /* Submit only events whose cgroup_id has been added with
     * rt_allow_cgroup(). Everything else is discarded in the kernel, before
     * the ring reservation is even attempted.
     *
     * IMPORTANT for a container consumer: in this mode an event from a cgroup
     * you have not added is invisible, not merely unattributed. That removes
     * "an event arrived for a cgroup I do not know" as a discovery path — which
     * is the fallback that otherwise covers a container created after startup,
     * or one missed by a baseline that raced its runtime's first enumeration.
     * So allowlist mode makes a create-time trigger from container_instances a
     * hard prerequisite rather than an optimisation. Start in
     * RT_CGROUP_MODE_ALL if you do not have one. */
    RT_CGROUP_MODE_ALLOWLIST = 1,
};

#endif /* RT_EVENT_CONTRACT_H */
