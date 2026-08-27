/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FIM_EBPF_H
#define FIM_EBPF_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Checks if eBPF telemetry engine is supported and available on this host.
 * If initialization fails, falls back to AUDIT_PROVIDER.
 */
void check_ebpf_availability(void);

/**
 * @brief Worker thread entrypoint for FIM eBPF Whodata real-time event processing.
 * @param arg Thread arguments (unused).
 * @return NULL on termination.
 */
void* ebpf_whodata(void* arg);

#ifdef __cplusplus
}
#endif

#endif // FIM_EBPF_H
