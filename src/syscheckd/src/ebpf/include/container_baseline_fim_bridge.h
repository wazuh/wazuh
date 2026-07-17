/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CONTAINER_BASELINE_FIM_BRIDGE_H
#define CONTAINER_BASELINE_FIM_BRIDGE_H

#include "container_baseline.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int fim_collect_k8s_monitored_paths(cb_monitored_path_t** out_paths, size_t* out_count);

void fim_free_k8s_monitored_paths(cb_monitored_path_t* paths);

/* Polls for up to ~5s for the container_instances module's IPC socket to
 * appear (it starts concurrently with syscheckd, with no ordering guarantee
 * between the two daemons), then returns 1 if it's present, 0 otherwise.
 * Logs a debug message on the negative case. May block the caller briefly. */
int fim_k8s_container_baseline_available(const char* socket_path);

/* Logs the outcome of a k8s FIM baseline run: how many containers were
 * actually baselined (see cbaseline_run_fim()'s return value contract). */
void fim_report_k8s_container_baseline_result(int baselined);

void fim_persist_baseline_row(const char* id,
                              int operation,
                              const char* index,
                              const char* json,
                              uint64_t version);

#ifdef __cplusplus
}
#endif

#endif /* CONTAINER_BASELINE_FIM_BRIDGE_H */
