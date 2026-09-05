/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CONTAINER_BASELINE_FIM_H
#define CONTAINER_BASELINE_FIM_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run the container file baseline (spike #37532) for every container
 * currently known to the container-connector module, over every configured
 * `<directories tags="container">` entry, and persist each resulting row
 * through the existing FIM sync-protocol handle (syscheck.sync_handle) — the
 * same persistence path a normal host-FIM stateful event already uses.
 *
 * Before this, `wazuh-states-fim-files` only reflected files that changed
 * *after* eBPF monitoring started: fim_handle_k8s_event() only ever emits a
 * stateless alert on an observed change, never a stateful baseline row, so a
 * file already present and untouched when the agent starts stayed invisible
 * to the state index. This closes that gap for the file/hash data class.
 *
 * No-op if there are no <directories tags="container"> entries configured,
 * if FIM synchronization is disabled (syscheck.enable_synchronization), or if
 * the container_instances module isn't running (its IPC socket is absent).
 *
 * This is independent of the whodata provider (audit vs eBPF): it only
 * enriches FIM state with container metadata, it doesn't affect change
 * detection. Call site: main.c, once at FIM startup right after
 * fim_initialize(), regardless of which whodata provider is configured.
 * Re-baselining on container lifecycle events / eBPF overflow signals (spike
 * Angle 6) is out of scope for this slice.
 */
void fim_run_container_baseline(void);

/**
 * @brief Start draining container file events from the eBPF engine (#37396).
 *
 * MUST be called BEFORE fim_run_container_baseline(). That ordering is the
 * whole point: events are staged from this moment on, so a file changed while
 * the baseline walk is running is reconciled afterwards instead of being missed
 * in the gap between "walk read this file" and "monitoring started". Starting
 * after the walk would leave exactly that hole.
 *
 * The consumer does NOT act on anything until fim_container_events_release().
 *
 * No-op, with a debug line, when the eBPF engine is unavailable, its ABI does
 * not match, or the host is cgroup v1 — none of which are startup failures.
 * Container FIM then relies on scheduled baselines alone, exactly as it does
 * today.
 */
void fim_container_events_start(void);

/**
 * @brief Release the reconcile consumer; call once the baseline walk has
 * committed.
 *
 * Until this point the consumer is parked. A single-row upsert racing the same
 * container's open scoped transaction silently lost 502 of 504 rows on a real
 * node, which is why the gate exists rather than relying on the two rarely
 * overlapping. Safe to call when fim_container_events_start() did nothing.
 */
void fim_container_events_release(void);

/**
 * @brief Stop the drain and close the engine. Idempotent.
 */
void fim_container_events_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* CONTAINER_BASELINE_FIM_H */
