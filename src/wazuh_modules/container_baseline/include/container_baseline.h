/*
 * Wazuh container-baseline module — C API exported by libcontainer_baseline.so
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Baseline acquisition for containerised workloads (spike #37532): a host-side
 * scan that seeds the initial FIM (file) and Syscollector (inventory) state for
 * a container, so the eBPF-driven change stream (#37396) has a known prior
 * state to diff against instead of only reporting activity after the fact.
 *
 * This C API is the bridge consumed by both FIM (syscheckd) and Syscollector
 * (C++, via the same extern "C" surface) — all scanning logic lives in the C++
 * impl. Rows are emitted in syscollector/FIM dbsync column format so the
 * caller can push them through its own per-container scoped DBSync
 * transaction and let the existing delta pipeline compute
 * INSERTED/MODIFIED/DELETED. This module never touches sync_protocol directly.
 *
 * IMPORTANT for callers — "no rows" is not "removed":
 *   A container that is known but momentarily has no live PID (stopped,
 *   restarting) is SKIPPED by the run functions and produces no rows. So is a
 *   container whose configured paths are absent from its image. Deriving
 *   deletions from absent rows therefore emits false DELETEs on container
 *   restart. Use cbaseline_list_containers() to learn what still exists, and
 *   the per-container status callback to learn which scans were incomplete.
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
 * don't have a config-supplied override can use this literal directly instead
 * of duplicating it. */
#define CB_DEFAULT_CONNECTOR_SOCKET_PATH "queue/sockets/container_instances"

#ifdef __cplusplus
extern "C" {
#endif

/* One `<directories tags="container">` entry to walk, translated by the caller
 * from its own config representation. */
typedef struct cb_monitored_path_t {
    const char* internal_path;     /* In-container absolute path, e.g. "/etc". */
    int         recursion_level;   /* 0 = entry only, N = N levels deep, -1 = unlimited. */
    size_t      max_files;         /* Hard cap on rows for this path; 0 = unlimited. */

    /* Files LARGER than this are not hashed at all and their hash fields are
     * left empty — the same policy host FIM applies via syscheck.file_max_size.
     * A digest is never computed over a file prefix: such a value matches no
     * other reader's and collides for any two files sharing that prefix.
     * 0 = no size limit. */
    size_t      max_hash_bytes;

    /* Which digests to compute, mirroring FIM's CHECK_MD5SUM / CHECK_SHA1SUM /
     * CHECK_SHA256SUM. All zero is treated as "all three" so an
     * un-initialised struct keeps the previous behaviour. */
    int         hash_md5;
    int         hash_sha1;
    int         hash_sha256;
} cb_monitored_path_t;

/* Invoked once per raw dbsync-format baseline row. `table` is the dbsync table
 * name ("dbsync_processes", "file_entry", ...); `row_json` is a flat object of
 * that table's columns, already stamped with container_id and container_json.
 * The caller groups rows per container per table and syncs them through
 * per-container scoped DBSync transactions. */
typedef void (*cb_dbsync_row_sink_t)(const char* container_id,
                                     const char* table,
                                     const char* row_json,
                                     void*       user_data);

/* Per-container outcome, invoked once per SCANNED container after all of its
 * rows have been emitted.
 *
 * `partial` != 0 means the scan is known to be incomplete — a row cap was hit,
 * a configured path was absent from the image, or a namespace could not be
 * read. The caller MUST NOT derive deletions from absent rows for such a
 * container; upsert what arrived and leave the rest alone.
 *
 * `netns_host_scoped` != 0 means the container shares the host's network
 * namespace, so no ports/interfaces/addresses/routes were attributed to it (the
 * ones visible there are the node's, not the container's).
 *
 * `netns_unreadable` != 0 means its network namespace could not be entered,
 * typically for lack of CAP_SYS_ADMIN — worth logging, since interface rows are
 * then absent for an environmental reason rather than a factual one. */
typedef void (*cb_container_status_sink_t)(const char* container_id,
                                           int         partial,
                                           int         netns_host_scoped,
                                           int         netns_unreadable,
                                           void*       user_data);

/* Invoked once per file BEFORE it is hashed, so the caller can apply its own
 * files-per-second limit. FIM passes check_max_fps(), whose token bucket is
 * process-global — so the container walk shares one budget with the host walk
 * instead of competing with it. May block. NULL = no throttling. */
typedef void (*cb_rate_limit_fn)(void);

/* Baseline every container's FIM files as raw file_entry dbsync rows. Each row
 * is a flat file_entry column set (container_id, path, hash_md5, …,
 * container_json) ready for fim_db_transaction_sync_row_json().
 *
 * `status_sink` and `rate_limit` may be NULL.
 *
 * Returns the number of containers that had at least one live, addressable PID
 * (and were therefore actually scanned). Containers known to the connector but
 * with no resolvable PID are silently skipped and are not counted. */
EXPORTED int cbaseline_run_fim_dbsync(const char*                connector_socket_path,
                                      const cb_monitored_path_t* paths,
                                      int                        path_count,
                                      cb_dbsync_row_sink_t       sink,
                                      cb_container_status_sink_t status_sink,
                                      cb_rate_limit_fn           rate_limit,
                                      void*                      user_data);

/* Baseline process + network + account + package + os + interface + address +
 * route + service + hardware inventory for every container currently known to
 * the container-connector module, as raw dbsync rows.
 *
 * `status_sink` may be NULL. Same return semantics as above. */
EXPORTED int cbaseline_run_syscollector_dbsync(const char*                connector_socket_path,
                                               cb_dbsync_row_sink_t       sink,
                                               cb_container_status_sink_t status_sink,
                                               void*                      user_data);

/* Invoked once per container currently known to the container-connector
 * module, independent of whether it has a resolvable live PID right now. */
typedef void (*cb_container_id_sink_t)(const char* container_id, void* user_data);

/* Lists every container currently known to the container-connector module
 * (queried via its IPC socket at `connector_socket_path`) — including a
 * container that is momentarily stopped (known, but no live PID), which the
 * cbaseline_run_* functions above silently skip. Callers that need to tell
 * "stopped" apart from "gone" (e.g. to decide what to keep vs. clean up in
 * their own database) MUST compare this list against the run_* functions'
 * output instead of treating "absent from a scan" as "removed".
 *
 * Returns the number of containers reported through `sink`, or -1 when the
 * connector could not be reached or answered malformed.
 *
 * IMPORTANT: callers MUST check for -1 before using this list to authorise
 * deletions. A failed query reports zero containers, so treating the result as
 * authoritative would delete every container's stored rows whenever the
 * connector is momentarily unavailable (agent startup ordering, a connector
 * restart, a Docker daemon reload) and re-create them on the next cycle — a
 * mass false-delete followed by a mass re-insert, on exactly the signal that
 * must be reported accurately.
 */
EXPORTED int cbaseline_list_containers(const char*            connector_socket_path,
                                       cb_container_id_sink_t sink,
                                       void*                  user_data);

#ifdef __cplusplus
}
#endif

#endif /* _CONTAINER_BASELINE_H */
