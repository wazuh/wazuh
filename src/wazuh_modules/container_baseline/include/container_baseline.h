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
 *   container whose configured paths could not be read. Deriving
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

/* Per-container outcome, reported once per SCANNED container after all of its
 * rows have been emitted.
 *
 * A struct rather than a parameter list because D17 required the reasons a scan
 * is incomplete to be told apart, and they will keep accruing: adding a field
 * here leaves every existing consumer compiling and reading the fields it knows. */
typedef struct cb_container_status
{
    const char* container_id;

    /* != 0 means the scan is known to be incomplete, so the caller MUST NOT
     * derive deletions from absent rows for this container; upsert what arrived
     * and leave the rest alone.
     *
     * The union of `row_cap_hit`, `rootfs_unreadable` and `paths_rejected` —
     * every reason that means "we did not manage to look". Deliberately NOT
     * including `roots_missing`: a configured root that is not in the image is
     * a fact, not a failure, and because it is STATIC, folding it in here
     * suppressed delete detection for that container permanently (C24). */
    int partial;

    /* A walk stopped at its row cap. The files it did not reach do exist. */
    int row_cap_hit;

    /* A configured root could not be examined at all, or the container's rootfs
     * stopped being addressable partway through (typically its PID exited).
     * Nothing is known about what is under it. */
    int rootfs_unreadable;

    /* A supplied path failed validation and was dropped. Only reachable through
     * the single-container entry point, whose paths may come from kernel events
     * rather than from agent configuration. */
    int paths_rejected;

    /* Configured roots genuinely absent from this container's image, and roots
     * walked successfully. Together they say what any delete detection the
     * caller then performs is actually scoped to. `roots_missing` is a
     * diagnostic, never a reason to suppress — see `partial`. */
    int roots_missing;
    int roots_scanned;

    /* != 0 means the container shares the host's network namespace, so no
     * ports/interfaces/addresses/routes were attributed to it (the ones visible
     * there are the node's, not the container's). */
    int netns_host_scoped;

    /* != 0 means its network namespace could not be entered, typically for lack
     * of CAP_SYS_ADMIN — worth logging, since interface rows are then absent
     * for an environmental reason rather than a factual one. */
    int netns_unreadable;
} cb_container_status_t;

typedef void (*cb_container_status_sink_t)(const cb_container_status_t* status, void* user_data);

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

/* Baseline ONE container's FIM files, over the paths the caller supplies.
 *
 * Serves both actions an event-driven reconcile needs, differing only in what
 * is passed as `paths`:
 *   - re-walk a container: the same monitored paths as the whole-node run;
 *   - re-read specific files: one cb_monitored_path_t per file. No special mode
 *     is needed — a path naming a non-directory produces exactly one row.
 *
 * PATH VALIDATION. Unlike the whole-node entry points, whose paths come from
 * agent configuration, these may originate outside the agent — in the eBPF
 * consumer they arrive in kernel events emitted by processes running INSIDE the
 * container, so the container chooses them. Each `internal_path` must therefore
 * be lexically absolute and already canonical: no "." or ".." component, no
 * empty component (so no "//" and no trailing '/'), no embedded NUL. Paths that
 * are not are DROPPED, not normalised — rewriting "/etc/../x" into "/x" would
 * silently scan something other than what was asked for — and a drop forces the
 * scan to be reported partial, which suppresses delete detection.
 *
 * `status_sink` and `rate_limit` may be NULL, but a caller that intends to use
 * delete detection needs `status_sink`: it is the only channel reporting that a
 * scan was incomplete.
 *
 * Returns:
 *    1  the container was baselined (a live, addressable PID was found);
 *    0  nothing was baselined — unknown to the connector, no resolvable PID, or
 *       no usable path was supplied. Its stored rows MUST be kept;
 *   -1  the connector could not be reached. Its stored rows MUST be kept.
 *
 * The tri-state is the safety property, which is why this returns a status
 * rather than a count like the functions above. Those can lean on
 * cbaseline_list_containers()' own -1 to tell "stopped" from "could not ask";
 * a single-container caller has no second signal, and collapsing 0 and -1 would
 * let a momentary connector blip look exactly like "this container has no files
 * any more" — the same mass false-delete this header warns about, one container
 * at a time.
 */
EXPORTED int cbaseline_run_fim_dbsync_container(const char*                connector_socket_path,
                                                const char*                container_id,
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

/* Baseline inventory for ONLY the named containers.
 *
 * What a delta-driven caller needs: having learned that three containers
 * changed, re-scanning the other ninety-seven is exactly the cost the delta
 * exists to avoid.
 *
 * Ids the connector no longer knows are skipped silently. A container that
 * disappeared between the delta being read and this being called is an ordinary
 * race, not an error, and its removal arrives through the delta in its own right.
 *
 * Row contiguity and one-status-per-container are unchanged: this selects which
 * containers are visited, not how each is walked.
 *
 * Returns the number baselined, or -1 when the connector could not be reached —
 * which MUST NOT be read as "none of those containers exist any more". */
EXPORTED int cbaseline_run_syscollector_dbsync_for(const char*                connector_socket_path,
                                                   const char* const*         container_ids,
                                                   int                        container_count,
                                                   cb_dbsync_row_sink_t       sink,
                                                   cb_container_status_sink_t status_sink,
                                                   void*                      user_data);

/* --- container lifecycle delta ------------------------------------------- *
 *
 * Lets a caller learn what CHANGED since it last looked, instead of fetching
 * every container's record and diffing. The cost it removes is per-poll and
 * proportional to the container count; the cost it adds is a cursor the caller
 * has to carry.
 */

/* What differs about a container, as a bitmask on cb_lifecycle_event_t.changed.
 *
 * An UNKNOWN BIT MUST BE TREATED AS "re-scan everything". A newer module may
 * report a class this build has no name for, and the safe reading of "something
 * changed that I do not understand" is to do the work, not to skip it. */
#define CB_CHANGED_IDENTITY (1u << 0) /* name, restart count, state, cgroup */
#define CB_CHANGED_IMAGE    (1u << 1) /* image or its digest */
#define CB_CHANGED_MOUNTS   (1u << 2)
#define CB_CHANGED_NETWORK  (1u << 3)
#define CB_CHANGED_METADATA (1u << 4) /* labels, annotations, pod identity */

#define CB_LIFECYCLE_ADDED   0
#define CB_LIFECYCLE_CHANGED 1
#define CB_LIFECYCLE_REMOVED 2

typedef struct
{
    const char*  container_id;
    int          kind;    /* CB_LIFECYCLE_* */
    unsigned int changed; /* CB_CHANGED_* bitmask; meaningful when kind is CHANGED */
} cb_lifecycle_event_t;

typedef void (*cb_lifecycle_sink_t)(const cb_lifecycle_event_t* event, void* user_data);

/* Reads transitions after (*epoch, *seq), and updates both to the position to
 * come back with.
 *
 * Returns the number of events reported, or:
 *
 *   CB_DELTA_RESYNC       the cursor could not be served — a different module
 *                         lifetime, or a position already aged out. Every known
 *                         container is reported as ADDED, so a caller that
 *                         re-baselines what it is told about recovers by doing
 *                         what it already does. Absentees MAY then be swept.
 *   CB_DELTA_UNAVAILABLE  nothing was obtained, or this module predates deltas.
 *                         The caller MUST NOT sweep: an empty answer here is
 *                         indistinguishable from "no containers" only if the
 *                         caller lets it be, and treating it as authority
 *                         deletes every stored row on a momentary blip.
 *
 * Pass 0/0 to start from cold; that reports CB_DELTA_RESYNC with the full set,
 * which is the same shape as recovering from a gap and so needs no separate
 * handling. The cursor is advanced only after the caller has applied what it
 * was given, so a crash in between replays rather than drops. */
#define CB_DELTA_UNAVAILABLE (-1)
#define CB_DELTA_RESYNC      (-2)

EXPORTED int cbaseline_lifecycle_since(const char*         connector_socket_path,
                                       unsigned long long* epoch,
                                       unsigned long long* seq,
                                       cb_lifecycle_sink_t sink,
                                       void*               user_data);

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
