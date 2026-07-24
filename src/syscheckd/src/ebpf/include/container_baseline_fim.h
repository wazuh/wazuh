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

#ifdef __cplusplus
}
#endif

#endif /* CONTAINER_BASELINE_FIM_H */
