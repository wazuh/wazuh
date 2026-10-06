/*
 * Wazuh shared — cgroup hierarchy mode probe.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Which cgroup hierarchy a host runs is a HOST CONSTANT that several
 * components must agree on, and the cost of them disagreeing is silent:
 * the eBPF engine decides from it whether an event's cgroup_id is a usable
 * correlation key, and container_instances decides from it whether the
 * inodes it resolves mean anything. Two independent probes that drift apart
 * produce a node where one half of the feature believes it is attributing
 * events and the other half knows it is not — the failure mode ADR-001
 * raised for capability probes, applied to cgroups (#37203 O4).
 *
 * So there is one probe, here, and it is header-only on purpose: a consumer
 * must be able to ask the question without taking a link dependency on
 * whoever else asks it.
 *
 * Compiles as C and as C++.
 */

#ifndef _CGROUP_HOST_MODE_H_
#define _CGROUP_HOST_MODE_H_

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Where a Linux host mounts its cgroup hierarchy. Not configurable: a host
 * that moved it has bigger problems than this probe. */
#define WZ_CGROUP_ROOT_DEFAULT "/sys/fs/cgroup"

typedef enum
{
    /* Unified v2 hierarchy at the root. bpf_get_current_cgroup_id() returns
     * a per-cgroup id, and that id is the directory's st_ino. */
    WZ_CGROUP_MODE_UNIFIED = 0,

    /* Pure v1: numbered controller hierarchies, no unified mount anywhere.
     * bpf_get_current_cgroup_id() collapses to the root cgroup for every
     * task, so every event carries the same id (spike #37396 ADR-002).
     *
     * Deliberately the value 1, so the historical
     * `detect_cgroup_v1() -> int` contract reads across unchanged. */
    WZ_CGROUP_MODE_LEGACY = 1,

    /* v1 controllers at the root WITH a v2 hierarchy mounted at
     * <root>/unified. Classified separately from unified because an operator
     * reading a log needs to know which of the two they are on — but it
     * behaves as v2 for correlation, because the helper returns the unified
     * hierarchy's ids there. See wz_cgroup_mode_has_usable_cgroup_id(). */
    WZ_CGROUP_MODE_HYBRID = 2
} wz_cgroup_mode_t;

/* True when <root><sub>/cgroup.controllers exists — the file cgroup v2
 * creates and v1 never does, which is what makes it the discriminator. */
static inline int wz_cgroup_has_v2_marker_(const char* root, const char* sub)
{
    char path[512];
    struct stat st;

    if (root == NULL || root[0] == '\0')
    {
        return 0;
    }

    const int written = snprintf(path, sizeof(path), "%s%s/cgroup.controllers", root, sub);
    if (written < 0 || (size_t)written >= sizeof(path))
    {
        return 0;
    }

    return stat(path, &st) == 0;
}

/* The probe, against an arbitrary root.
 *
 * The root is a parameter ONLY so the three modes can be unit-tested from
 * fixture directories: every development and CI host this tree builds on is
 * unified, so without injection two of the three branches would ship having
 * never once been executed. Production callers use wz_cgroup_mode(). */
static inline wz_cgroup_mode_t wz_cgroup_mode_at(const char* root)
{
    if (wz_cgroup_has_v2_marker_(root, ""))
    {
        return WZ_CGROUP_MODE_UNIFIED;
    }
    if (wz_cgroup_has_v2_marker_(root, "/unified"))
    {
        return WZ_CGROUP_MODE_HYBRID;
    }

    /* Note the direction of the default: anything we cannot positively
     * identify as v2 is reported legacy. That is the safe way round — a
     * unified host misreported as legacy loses event-driven FIM and says so
     * loudly, where a legacy host misreported as unified attributes every
     * container's events to one bogus cgroup and says nothing. */
    return WZ_CGROUP_MODE_LEGACY;
}

static inline wz_cgroup_mode_t wz_cgroup_mode(void)
{
    return wz_cgroup_mode_at(WZ_CGROUP_ROOT_DEFAULT);
}

/* Whether an event's cgroup_id identifies a container on this host.
 *
 * The one place the hybrid-counts-as-v2 rule is written down; consumers ask
 * this rather than testing the enum, so the rule cannot be spelled three
 * different ways in three modules. */
static inline int wz_cgroup_mode_has_usable_cgroup_id(wz_cgroup_mode_t mode)
{
    return mode != WZ_CGROUP_MODE_LEGACY;
}

static inline const char* wz_cgroup_mode_name(wz_cgroup_mode_t mode)
{
    switch (mode)
    {
        case WZ_CGROUP_MODE_UNIFIED: return "unified (v2)";
        case WZ_CGROUP_MODE_LEGACY: return "legacy (v1)";
        case WZ_CGROUP_MODE_HYBRID: return "hybrid (v1 + v2 at /unified)";
        default: return "unknown";
    }
}

/* The controllers a legacy host may be keyed by, in the order they are tried.
 *
 * ONE list, because two components must reach the same answer: the resolver
 * stats a container's directory under this controller, and the eBPF engine is
 * configured to read the cgroup id from the SAME controller's hierarchy. Each
 * one works as a key provided it is the same one everywhere — two components
 * choosing differently would key on numbers drawn from unrelated hierarchies,
 * and every lookup between them would miss.
 *
 * Ordered by how reliably each is mounted and how closely it tracks the
 * container rather than the host: `memory` and `pids` are per-container on
 * every runtime, `cpuacct` is nearly always mounted, and `systemd` (the
 * `name=systemd` hierarchy) exists even where no controller does.
 *
 * BUT `systemd` IS NOT USABLE BY THE eBPF ENGINE, and the difference matters.
 * A `name=` hierarchy has no controller, so it has no entry in the kernel's
 * `enum cgroup_subsys_id` and none in css_set.subsys[] — wz_cgroup_subsys_index
 * returns -1 for it. Userspace can still stat its directories, so it remains a
 * valid key for the resolver and for inventory; what it cannot do is let the
 * BPF program read a container's cgroup id, because there is no subsystem slot
 * to read from. A host offering only `name=systemd` can therefore be
 * inventoried but not filtered in-kernel. Callers configuring the engine must
 * treat a -1 index as "no in-kernel attribution here", not as an error to
 * retry.
 */
#define WZ_CGROUP_V1_PRIORITY_COUNT 4

static inline const char* wz_cgroup_v1_priority(unsigned int rank)
{
    static const char* const order[WZ_CGROUP_V1_PRIORITY_COUNT] = {"memory", "pids", "cpuacct", "systemd"};
    return (rank < WZ_CGROUP_V1_PRIORITY_COUNT) ? order[rank] : NULL;
}

/* A controller's position in the kernel's `enum cgroup_subsys_id`, which is
 * what indexes css_set.subsys[] and therefore what the BPF program needs.
 *
 * Read from /proc/cgroups, whose rows are in enum order — verified against the
 * kernel's own BTF on the test host (`cpuset, cpu, cpuacct, blkio, memory, …`
 * against `0,1,2,3,4,…`). Deriving it this way rather than from BTF keeps it
 * working on a kernel without BTF, and handles any controller name without a
 * table of enumerators to keep in step with the kernel's.
 *
 * NOTE the enum and the file disagree on one NAME: position 3 is `io_cgrp_id`
 * in the enum and `blkio` in the file. The same subsystem under its v1 name,
 * and harmless here because the position is what matters.
 *
 * Returns the index, or -1 when the controller is not listed.
 */
static inline int wz_cgroup_subsys_index(const char* controller)
{
    char line[256];
    int index = 0;
    FILE* file;

    if (controller == NULL || controller[0] == '\0')
    {
        return -1;
    }

    file = fopen("/proc/cgroups", "re");
    if (file == NULL)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char name[64];

        if (line[0] == '#')
        {
            continue; /* the header row is not a subsystem */
        }
        if (sscanf(line, "%63s", name) != 1)
        {
            continue;
        }
        if (strcmp(name, controller) == 0)
        {
            fclose(file);
            return index;
        }
        ++index;
    }

    fclose(file);
    return -1;
}

/* Whether an eBPF consumer may read container cgroup ids from a v1 controller
 * hierarchy on this host.
 *
 * A pure decision, separated from the engine so it can be asserted without a
 * loaded BPF object, a kernel or root — none of which the dependency-free
 * contract tests have. The engine calls this; so can anything else that needs
 * to know before opening a handle.
 *
 * False on a unified or hybrid host, and that is the important direction:
 * there, css_set.subsys[i] points at the nearest ANCESTOR cgroup where
 * controller i is enabled rather than at the task's own, so the read returns a
 * real and plausible number for the WRONG cgroup — a container's events filed
 * under its parent slice, with nothing to flag it. The helper is correct on
 * those hosts and must be used instead.
 *
 * False for a negative index, which is how wz_cgroup_subsys_index() reports a
 * controller with no subsystem slot (a `name=` hierarchy). That is "no
 * in-kernel attribution here", not an error to retry.
 */
static inline int wz_cgroup_v1_subsys_read_allowed(wz_cgroup_mode_t mode, int subsys_index)
{
    if (wz_cgroup_mode_has_usable_cgroup_id(mode))
    {
        return 0;
    }
    return subsys_index >= 0;
}

#endif /* _CGROUP_HOST_MODE_H_ */
