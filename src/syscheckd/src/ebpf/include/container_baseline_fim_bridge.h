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

#include <cJSON.h>
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

/* Where a reconciled row came from, which is what the alert's "mode" field
 * reports.
 *
 * Named as an intent rather than passed as a fim_event_mode value because the
 * C++ driver cannot include syscheck-config.h (same reason as the logging
 * shims), and hard-coding that enum's numeric values on this side of the
 * boundary would rot silently if it ever gained a member. The bridge does the
 * mapping. */
typedef enum {
    CB_FIM_ORIGIN_SCAN  = 0, /* whole-node or per-container walk -> "scheduled" */
    CB_FIM_ORIGIN_EVENT = 1  /* driven by an eBPF file event     -> "whodata"   */
} cb_fim_origin_t;

/* Sends the FIM *stateless* alert (the thing an analyst sees) for one row the
 * container reconcile changed. This is the half container FIM was missing:
 * fim_persist_baseline_row() only ever built the stateful document, so a file
 * changing inside a container updated wazuh-states-fim-files and raised no
 * alert at all.
 *
 * @param row_data  the row as DBSync reported it: the whole result for an
 *                  INSERT/DELETE, its "new" object for a MODIFY.
 * @param old_data  DBSync's "old" object for a MODIFY (which carries exactly
 *                  the changed columns, and is what "changed_fields" is derived
 *                  from), NULL otherwise.
 * @param operation Operation_t, as fim_persist_baseline_row() takes it.
 * @param origin    cb_fim_origin_t.
 *
 * No-op while the first container baseline has not finished — see
 * fim_container_baseline_first_scan_done(). */
void fim_send_container_stateless_event(const cJSON* row_data,
                                        const cJSON* old_data,
                                        int operation,
                                        int origin);

/* Latches "the initial container baseline is done", after which reconciled rows
 * produce alerts. Mirrors host FIM's notify_scan / <notify_first_scan>: the
 * first walk of a node inserts every file it finds, and alerting on all of them
 * is a startup flood, not information.
 *
 * Call it once, after the whole-node baseline returns. */
void fim_container_baseline_first_scan_done(void);

/* Compute SHA1 of row_json and store the 40-char hex + NUL into out_sha1[41].
 * Used by container_baseline_fim.cpp to stamp a stable checksum onto each
 * baseline row before syncing it through fim_db_transaction_sync_row_json(). */
void fim_compute_row_checksum(const char* row_json, char out_sha1[41]);

#ifdef __cplusplus
}
#endif

#endif /* CONTAINER_BASELINE_FIM_BRIDGE_H */
