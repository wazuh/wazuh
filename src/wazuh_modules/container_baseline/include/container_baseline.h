/*
 * Wazuh container-baseline module — C API exported by libcontainer_baseline.so
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Baseline acquisition for containerised workloads (spike #37532): a one-time
 * host-side scan that seeds the initial FIM (file) and Syscollector
 * (process/network) state for a container, so the eBPF-driven change stream
 * (#37396) has a known prior state to diff against instead of only reporting
 * activity after the fact.
 *
 * This C API is the bridge consumed by both FIM (syscheckd, C) and
 * Syscollector (C++, via the same extern "C" surface) — all scanning logic
 * lives in the C++ impl; this header only exposes the two entry points and
 * the row-sink callback shape. Callers own persistence: this module produces
 * rows and hands them to `sink`, which the caller forwards to its own
 * AgentSyncProtocol handle (syscheck.sync_handle / Syscollector's own handle).
 * This module never touches sync_protocol directly, so it has no opinion on
 * how/when the caller batches, retries, or rate-limits the actual sync call.
 */

#ifndef _CONTAINER_BASELINE_H
#define _CONTAINER_BASELINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifdef WIN_EXPORT
#    define EXPORTED __declspec(dllexport)
#  else
#    define EXPORTED __declspec(dllimport)
#  endif
#elif __GNUC__ >= 4
#  define EXPORTED __attribute__((visibility("default")))
#else
#  define EXPORTED
#endif

/* Default IPC socket path of the container_instances module. Callers that
 * don't have a config-supplied override (e.g. the FIM/Syscollector wiring in
 * this branch) can use this literal directly instead of duplicating it. */
#define CB_DEFAULT_CONNECTOR_SOCKET_PATH "queue/sockets/container_instances"

/* Default on-disk prior-state database for the reconciler (see the reconciler
 * API below). Durable across agent restarts so container-exit deletes still fire
 * for containers that exited while the agent was down. The parent directory is
 * created on demand. */
#define CB_DEFAULT_PRIOR_STATE_DB_PATH "queue/container_baseline/prior_state.db"

#ifdef __cplusplus
extern "C" {
#endif

/* One `<directories type="kubernetes">` entry to walk, translated by the
 * caller from its own config representation (e.g. k8s_monitored_path_t). */
typedef struct cb_monitored_path_t {
    const char* internal_path;     /* In-container absolute path, e.g. "/etc". */
    int         recursion_level;   /* 0 = entry only, N = N levels deep, -1 = unlimited. */
    size_t      max_files;         /* Hard cap on rows for this path; 0 = unlimited. */
    size_t      max_hash_bytes;    /* Per-file hashing cutoff; 0 = unlimited. */
} cb_monitored_path_t;

/* Invoked once per baseline row produced. `operation` mirrors sync_protocol's
 * Operation_t (0 = CREATE); baseline rows are always creates. `version` is the
 * row's initial sync-protocol version (always 1 for a freshly-baselined row). */
typedef void (*cb_row_sink_t)(const char* id,
                              int         operation,
                              const char* index,
                              const char* json,
                              uint64_t    version,
                              void*       user_data);

/* Baseline every container currently known to the container-connector module
 * (queried via its IPC socket at `connector_socket_path`) against the given
 * set of monitored paths, emitting one row per file found through `sink`.
 *
 * Returns the number of containers that had at least one live, addressable
 * PID (and were therefore actually scanned) — containers known to the
 * connector but with no resolvable PID (e.g. already exited) are silently
 * skipped and are not counted.
 */
EXPORTED int cbaseline_run_fim(const char*                 connector_socket_path,
                               const cb_monitored_path_t*  paths,
                               int                         path_count,
                               cb_row_sink_t               sink,
                               void*                       user_data);

/* Baseline process + network inventory for every container currently known to
 * the container-connector module. See baseline_rows.hpp (C++ impl) for the
 * draft-ECS-schema caveat on the JSON shape emitted for these rows — it is not
 * yet aligned with Syscollector::ecsData()'s field contract.
 */
EXPORTED int cbaseline_run_syscollector(const char*   connector_socket_path,
                                        cb_row_sink_t  sink,
                                        void*          user_data);

/* Invoked once per raw dbsync-format baseline row (Option A: baseline through
 * the host event flow). `table` is the syscollector dbsync table name
 * ("dbsync_processes", ...); `row_json` is a flat object of that table's
 * columns, already stamped with container_id and container_json. The caller
 * (Syscollector) groups rows per container per table and syncs them through
 * per-container scoped DBSync transactions so the shared notifyChange/
 * processEvent pipeline computes the deltas and emits the events. */
typedef void (*cb_dbsync_row_sink_t)(const char* container_id,
                                     const char* table,
                                     const char* row_json,
                                     void*       user_data);

/* Same scan coverage as cbaseline_run_syscollector(), emitting raw dbsync rows
 * instead of pre-shaped sync-protocol payloads. Same return semantics. */
EXPORTED int cbaseline_run_syscollector_dbsync(const char*          connector_socket_path,
                                               cb_dbsync_row_sink_t sink,
                                               void*                user_data);

/* Invoked once per container currently known to the container-connector
 * module, independent of whether it has a resolvable live PID right now. */
typedef void (*cb_container_id_sink_t)(const char* container_id, void* user_data);

/* Lists every container currently known to the container-connector module
 * (queried via its IPC socket at `connector_socket_path`) — including a
 * container that is momentarily stopped (known, but no live PID), which the
 * cbaseline_run_* functions above silently skip. Callers that need to tell
 * "stopped" apart from "gone" (e.g. to decide what to keep vs. clean up in
 * their own database) should compare this list against the run_* functions'
 * output instead of treating "absent from a scan" as "removed".
 *
 * Returns the number of containers reported through `sink`.
 */
EXPORTED int cbaseline_list_containers(const char*            connector_socket_path,
                                       cb_container_id_sink_t sink,
                                       void*                  user_data);

/* Baseline every container's FIM files using raw file_entry dbsync rows
 * (Option A: baseline through the host FIM transaction flow). Each row is a
 * flat file_entry column set (container_id, path, hash_md5, …, container_json)
 * ready for fim_db_transaction_sync_row_json(). The caller (syscheckd's
 * container_baseline_fim.cpp) groups rows per container, opens a per-container
 * scoped fim_db_transaction_start, and lets the existing transaction_callback
 * compute deltas and emit events — no separate persist path needed.
 *
 * Same return semantics as cbaseline_run_fim(). */
EXPORTED int cbaseline_run_fim_dbsync(const char*                connector_socket_path,
                                      const cb_monitored_path_t* paths,
                                      int                        path_count,
                                      cb_dbsync_row_sink_t       sink,
                                      void*                      user_data);
/* Stateful container-inventory reconciler (#37534). Unlike the one-shot
 * cbaseline_run_syscollector() above, this drives a *reconciled state* source:
 * each run re-scans every live container and emits CREATE/MODIFY/DELETE rows by
 * diffing against durable prior state, including deletes for containers that have
 * exited. The handle must outlive individual runs (it holds the prior-state DB
 * and the first-scan-after-reload guard), so the caller creates it once and runs
 * it every scan interval.
 *
 * `sink`/`user_data` are captured at creation and used by every run. */
typedef struct cbaseline_reconciler cbaseline_reconciler_t;

/* Create a reconciler over the containers known at `connector_socket_path`,
 * persisting prior state at `prior_state_db_path` (parent dir created on demand;
 * pass CB_DEFAULT_PRIOR_STATE_DB_PATH for the default). Returns NULL on failure
 * (e.g. the prior-state DB could not be opened) — the caller should then skip
 * container inventory rather than crash. */
EXPORTED cbaseline_reconciler_t* cbaseline_reconciler_create(const char*   connector_socket_path,
                                                             const char*   prior_state_db_path,
                                                             cb_row_sink_t sink,
                                                             void*         user_data);

/* Run one reconcile pass over every live container. Returns the number of
 * containers reconciled, or -1 when the pass was skipped because the Container
 * Instances module was unreachable (never a partial delete). */
EXPORTED int cbaseline_reconciler_run(cbaseline_reconciler_t* handle);

/* Destroy a reconciler and close its prior-state DB. Safe on NULL. */
EXPORTED void cbaseline_reconciler_destroy(cbaseline_reconciler_t* handle);

#ifdef __cplusplus
}
#endif

#endif /* _CONTAINER_BASELINE_H */
