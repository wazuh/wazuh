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
 * `<directories type="kubernetes">` entry, and persist each resulting row
 * through the existing FIM sync-protocol handle (syscheck.sync_handle) — the
 * same persistence path a normal host-FIM stateful event already uses.
 *
 * Before this, `wazuh-states-fim-files` only reflected files that changed
 * *after* eBPF monitoring started: fim_handle_k8s_event() only ever emits a
 * stateless alert on an observed change, never a stateful baseline row, so a
 * file already present and untouched when the agent starts stayed invisible
 * to the state index. This closes that gap for the file/hash data class.
 *
 * No-op if there are no <directories type="kubernetes"> entries configured,
 * or if FIM synchronization is disabled (syscheck.enable_synchronization).
 *
 * Intended call site: syscheck.c's check_ebpf_availability(), right after
 * fimebpf_enable_k8s_container_support() — i.e. once, at FIM startup, only
 * when K8s directories are actually configured. Re-baselining on container
 * lifecycle events / eBPF overflow signals (spike Angle 6) is out of scope
 * for this slice.
 */
void fim_run_k8s_container_baseline(void);

#ifdef __cplusplus
}
#endif

#endif /* CONTAINER_BASELINE_FIM_H */
