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

struct rt_filter
{
    /* Bitmask of (1u << rt_event_type). Only the BPF programs needed to
     * satisfy the requested classes are loaded/attached for THIS handle —
     * two consumers with different masks get two independent loads, each
     * with its own ring buffer (spike #37396 ADR-001: no shared provider,
     * no cross-consumer stalling). */
    unsigned int type_mask;
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

/* Detaches and frees everything opened by rt_open(). Safe to call with
 * handle == NULL. */
void rt_close(rt_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* RT_ENGINE_H */
