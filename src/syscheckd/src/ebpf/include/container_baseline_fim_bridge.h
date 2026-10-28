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
                                          size_t rows,     /* STORED, not offered */
                                          size_t refused,  /* offered and turned away */
                                          size_t partial,
                                          size_t stale,
                                          size_t known,
                                          size_t withheld); /* known but not allowed to report */

/* Logging shims. The C++ driver deliberately does not include shared.h (whose
 * macros clash with the C++ headers it needs), so it routes its messages
 * through these. */
void fim_container_baseline_log_debug(const char* message);
void fim_container_baseline_log_warn(const char* message);
void fim_container_baseline_log_error(const char* message);

/* Install-relative location of the eBPF Module's compiled BPF object, mirroring
 * how ebpf_whodata.cpp names modern.bpf.o. */
#define CB_RT_BPF_OBJECT_PATH "lib/rt_file.bpf.o"

/* Install-relative location of the libbpf the agent ships. Named here for the
 * same reason as the object above: without it the engine dlopen()s a bare
 * soname and binds the HOST's libbpf, which on a legacy RHEL-family host is too
 * old to carry the symbols the engine needs. */
#define CB_RT_LIBBPF_PATH "lib/libbpf.so"

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

/* The two row ceilings, read from the daemon's live configuration.
 *
 * Shims for the same reason the logging ones are: the C++ driver cannot include
 * syscheck.h, and this library no longer reads the daemon's configuration
 * directly -- it is handed it. Both return 0, meaning unlimited, before the
 * host API is registered. */
int fim_container_baseline_row_limit(void);       /* per container */
int fim_container_baseline_node_row_limit(void);  /* the whole file_entry table */

/**
 * @brief Release a container's per-container document count (#37532 / O10).
 *
 * Called when a container's rows are swept. Without it the count map grows with
 * every container the node has ever run, and the released budget is never
 * returned -- on a churning node that is a slow leak toward a cap that reports
 * no space while holding none.
 *
 * @param container_id The container whose count to drop. NULL/empty is a no-op.
 */
void fim_container_doc_budget_release(const char* container_id);

/**
 * @brief Seed a container's document count from what it has already reported.
 *
 * The count lives in memory, so without this a restart hands every container a
 * fresh budget while its rows are still on the manager, and the cap bounds
 * nothing across the restarts an agent actually performs.
 *
 * Reads the database, so it must be called BEFORE opening a scoped transaction
 * for that container, never from a row callback inside one. Already-seeded
 * containers are a no-op, so a caller may call it on every pass.
 *
 * @param container_id The container whose count to seed.
 */
void fim_container_doc_budget_initialize(const char* container_id);

/**
 * @brief Report, once per pass, what the document budget withheld.
 *
 * A budget that silently drops reports is indistinguishable from a quiet node,
 * which is how the original scope-blind fill stayed invisible (23.4). Logs
 * nothing when nothing was refused, and clears the tally either way.
 */
void fim_container_doc_budget_report(void);

/**
 * @brief Withdraw from the manager the rows of containers that may no longer report.
 *
 * Their rows stay in the local database and keep being walked: this retracts the
 * manager's copy only, so re-admission can report them again without re-reading
 * the filesystem. Called when the admitted set changes.
 */
void fim_container_reconcile_admission(void);

/**
 * @brief Record which containers may report to the manager (#37532).
 *
 * A different question from the document budget above: that one bounds how much
 * one container reports, this one bounds how many containers report at all.
 * A container left out of this set still exists, is still walked, and keeps its
 * stored rows -- only its reporting stops.
 *
 * Call ONLY when the connector actually answered. A failed query lists no
 * containers, and applying that would withhold every container's rows on a
 * momentary blip. Until the first call, everything reports.
 *
 * @param container_ids Ids allowed to report. Copied; the caller keeps ownership.
 * @param count         How many. Zero is a real answer -- no container reports.
 */
void fim_container_set_admitted(const char** container_ids, size_t count);

/**
 * @brief Install a listing's admission answer: what it knew, and what of that
 *        it admitted.
 *
 * Both sets come from ONE listing on purpose. Admission is read per row on the
 * storage path, so a row decided between two separate calls would be weighed
 * against a known set from one listing and an admitted set from another.
 *
 * Call ONLY when the connector actually answered -- see
 * fim_container_set_admitted(), which is this with the two sets equal.
 *
 * @param known_ids      Every container the listing reported, admitted or not.
 * @param known_count    How many.
 * @param admitted_ids   The subset allowed to report. Copied; caller keeps ownership.
 * @param admitted_count How many. Zero is a real answer -- no container reports.
 */
void fim_container_set_admission(const char** known_ids,
                                 size_t known_count,
                                 const char** admitted_ids,
                                 size_t admitted_count);

/**
 * @brief Whether a container may report. Non-zero when it may.
 *
 * True for every container until fim_container_set_admitted() has been called,
 * so an agent that has not reached the connector keeps reporting rather than
 * going silently quiet.
 */
int fim_container_is_admitted(const char* container_id);

/**
 * @brief Whether the admission snapshot predates this container. Non-zero when it does.
 *
 * A container created after the snapshot was taken is in neither set, and
 * fim_container_is_admitted() cannot tell that from the cap having refused it:
 * both read as "may not report". Left alone it stores every row sync=0 for the
 * life of the process, because nothing else retakes the listing.
 *
 * Ask this before storing a container's rows; when it says yes, take a fresh
 * listing and install it. Once installed the container is known either way, so
 * this costs one listing per container, not one per batch.
 */
int fim_container_admission_is_stale(const char* container_id);

/**
 * @brief Build one container row's stateful document and offer it to the manager.
 *
 * @return The reporting decision -- 1 reported, 0 withheld by the budget -- which
 *         the caller writes back to the row's sync column once the transaction
 *         holding it has closed. -1 when the document could not be built or did
 *         not validate, in which case nothing must be written back.
 */
int fim_persist_baseline_row(const char* id,
                             int operation,
                             const char* index,
                             const char* json,
                             uint64_t version);

/**
 * @brief Re-send one reported container row during a FIM recovery resync.
 *
 * Recovery clears the manager's FIM index and re-sends every sync=1 row. A
 * container row has to come back exactly as the live path sent it: under the
 * unhashed container_id:path id, as the normalised document with its container
 * block, and only while its container is admitted. It is skipped when no
 * <container_security><syscheck> directory covers its path any more.
 *
 * Registered with fim_recovery_set_container_row_handler(), so recovery does
 * not link against this library.
 *
 * @return 1 queued, 0 skipped (not covered, or withheld), -1 on error.
 */
int fim_container_recover_row(const cJSON* row);

/* Where a reconciled row came from, which is what the alert's "mode" field
 * reports.
 *
 * Named as an intent rather than passed as a fim_event_mode value because the
 * C++ driver cannot include syscheck-config.h (same reason as the logging
 * shims), and hard-coding that enum's numeric values on this side of the
 * boundary would rot silently if it ever gained a member. The bridge does the
 * mapping. */
typedef enum
{
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
