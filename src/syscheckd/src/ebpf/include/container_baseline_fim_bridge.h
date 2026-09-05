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

int fim_collect_container_monitored_paths(cb_monitored_path_t** out_paths, size_t* out_count);

void fim_free_container_monitored_paths(cb_monitored_path_t* paths);

/* Polls for up to ~5s for the container_instances module's IPC socket to
 * appear (it starts concurrently with syscheckd, with no ordering guarantee
 * between the two daemons), then returns 1 if it's present, 0 otherwise.
 * Logs a debug message on the negative case. May block the caller briefly. */
int fim_container_baseline_available(const char* socket_path);

/* Logs the outcome of a container FIM baseline run: how many containers were
 * actually baselined (see cbaseline_run_fim_dbsync()'s return value contract),
 * plus how much of it was usable. */
void fim_report_container_baseline_result(int baselined,
                                          size_t rows,
                                          size_t partial,
                                          size_t stale,
                                          size_t known);

/* Logging shims. The C++ driver deliberately does not include shared.h (whose
 * macros clash with the C++ headers it needs), so it routes its messages
 * through these. */
void fim_container_baseline_log_debug(const char* message);
void fim_container_baseline_log_error(const char* message);

/* Install-relative location of the eBPF Module's compiled BPF object, mirroring
 * how ebpf_whodata.cpp names modern.bpf.o. */
#define CB_RT_BPF_OBJECT_PATH "lib/rt_file.bpf.o"

/* Resolves an install-relative path against the agent's install directory.
 * Returns 0 on success and writes a NUL-terminated absolute path into `out`.
 *
 * A shim for the same reason the logging ones are: shared.h's macros clash with
 * the C++ headers the driver needs, so a C++ translation unit cannot include it
 * to reach abspath() directly. */
int fim_container_baseline_abspath(const char* relative, char* out, size_t out_size);

/* Rate-limit hook handed to the baseline walker as its cb_rate_limit_fn:
 * applies FIM's own files-per-second budget (check_max_fps, driven by
 * syscheck.max_files_per_second). Its token bucket is process-global, so the
 * container walk shares one budget with the host walk.
 *
 * This is a shim rather than passing check_max_fps directly because
 * syscheck.h carries no extern "C" guards, so a C++ translation unit that
 * included it would take the symbol with C++ linkage and fail to link. */
void fim_container_baseline_rate_limit(void);

void fim_persist_baseline_row(const char* id,
                              int operation,
                              const char* index,
                              const char* json,
                              uint64_t version);

/* Compute SHA1 of row_json and store the 40-char hex + NUL into out_sha1[41].
 * Used by container_baseline_fim.cpp to stamp a stable checksum onto each
 * baseline row before syncing it through fim_db_transaction_sync_row_json(). */
void fim_compute_row_checksum(const char* row_json, char out_sha1[41]);

#ifdef __cplusplus
}
#endif

#endif /* CONTAINER_BASELINE_FIM_BRIDGE_H */
