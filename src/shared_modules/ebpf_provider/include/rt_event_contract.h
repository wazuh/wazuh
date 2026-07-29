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
 */

#ifndef RT_EVENT_CONTRACT_H
#define RT_EVENT_CONTRACT_H

/* Versioning (spike #37396 ADR-003 rule): append fields -> bump MINOR only
 * (old consumers ignore the tail). Reorder/resize/remove a field -> bump
 * MAJOR (a consumer must refuse to open a mismatched-MAJOR engine). Every
 * event also carries abi_major so a consumer that opened the engine before
 * a live reload can still detect a mismatch. */
#define RT_ABI_MAJOR 1
#define RT_ABI_MINOR 0

enum rt_event_type
{
    RT_EV_FILE_OPEN   = 1, /* create, or open with write intent */
    RT_EV_FILE_ATTR   = 2, /* chmod/chown/truncate/utimes */
    RT_EV_FILE_UNLINK = 3,
    RT_EV_FILE_RENAME = 4, /* carries the destination path */
};

enum rt_flags
{
    /* cgroup_id is a cgroup-v1-ambiguous constant here, not a usable
     * correlation key (bpf_get_current_cgroup_id() collapses to a fixed
     * value on cgroup v1 hosts, e.g. RHEL8/AL2 — see spike #37396 ADR-002).
     * Consumers needing container correlation on such hosts must fall back
     * to mnt_ns instead. */
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
};

#endif /* RT_EVENT_CONTRACT_H */
