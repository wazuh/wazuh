/*
 * Wazuh — which identifier a host files containers under.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The producer (container_instances, inside modulesd) and its consumers (the
 * FIM drain and syscollector, through the client library) live in different
 * processes and different C++ namespaces, and they exchange this value as a
 * STRING on the wire. Two copies of that string is all it takes for one side
 * to ask in a key space the other does not serve — and because both kinds are
 * plausible 64-bit inode numbers, the result is not an error but a miss, which
 * reads as "unknown container, go and resolve it" forever.
 *
 * So the vocabulary lives here, once, in a plain C header both sides can
 * include regardless of their namespace — the same reasoning that put the
 * hierarchy probe in cgroup_host_mode.h.
 */

#ifndef _CONTAINER_KEY_KIND_H_
#define _CONTAINER_KEY_KIND_H_

#include "cgroup_host_mode.h"

#include <string.h>

typedef enum
{
    /* The cgroup directory inode, which on a unified hierarchy is exactly what
     * bpf_get_current_cgroup_id() reports. */
    WZ_CONTAINER_KEY_CGROUP = 0,

    /* The mount namespace inode. Used where the cgroup id collapses to a
     * constant and therefore identifies nothing (spike #37396 ADR-002). */
    WZ_CONTAINER_KEY_MNT_NS = 1
} wz_container_key_kind_t;

/* The wire spelling. Published in the `status` reply and sent on every
 * `resolve`, so changing one of these strings is a protocol change. */
static inline const char* wz_container_key_kind_name(wz_container_key_kind_t kind)
{
    return (kind == WZ_CONTAINER_KEY_MNT_NS) ? "mnt_ns" : "cgroup";
}

/* Returns non-zero on success. A name this build does not know is REFUSED
 * rather than defaulted: defaulting picks a key space at random, and the whole
 * reason this value is sent is that it cannot be guessed. */
static inline int wz_container_key_kind_from_name(const char* name, wz_container_key_kind_t* out)
{
    if (name == NULL || out == NULL)
    {
        return 0;
    }
    if (strcmp(name, "cgroup") == 0)
    {
        *out = WZ_CONTAINER_KEY_CGROUP;
        return 1;
    }
    if (strcmp(name, "mnt_ns") == 0)
    {
        *out = WZ_CONTAINER_KEY_MNT_NS;
        return 1;
    }
    return 0;
}

/* What this host uses, from the one hierarchy probe. A host constant: read it
 * once, never per record and never inferred from an event.
 *
 * On a legacy host the helper bpf_get_current_cgroup_id() is useless, because it
 * reports the unified hierarchy and there is none -- but the KERNEL still has a
 * per-container cgroup under every mounted v1 controller, and the eBPF program
 * reads it directly. So the question is not "is the helper usable" but "is there
 * a controller both sides can agree on", which is exactly what
 * wz_cgroup_v1_select_subsys() answers. Asking it here is what keeps the
 * producer's key and the consumer's key in the same number space: the resolver
 * already stats that controller's cgroup directory, and the BPF program returns
 * that directory's inode.
 *
 * Falling back to the mount namespace only when no controller qualifies keeps
 * the previous behaviour for hosts where nothing better exists -- at the cost
 * the mount namespace has always carried, that the kernel reuses its inode for
 * the next container. */
static inline wz_container_key_kind_t wz_container_key_kind_for_host(void)
{
    const wz_cgroup_mode_t mode = wz_cgroup_mode();

    if (wz_cgroup_mode_has_usable_cgroup_id(mode))
    {
        return WZ_CONTAINER_KEY_CGROUP;
    }

    /* Legacy: usable as a cgroup key iff a controller both sides can read. */
    if (wz_cgroup_v1_select_subsys(NULL) >= 0)
    {
        return WZ_CONTAINER_KEY_CGROUP;
    }

    return WZ_CONTAINER_KEY_MNT_NS;
}

#endif /* _CONTAINER_KEY_KIND_H_ */
