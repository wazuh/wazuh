/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_H
#define _TASK_MANAGER_H

/*
 * C-ABI bridge for the task_manager C++ module.
 *
 * modulesd resolves the two entry points below with dlopen/dlsym (see
 * wazuh_modules/src/wm_task_manager.c), so the function-pointer typedefs at the bottom are
 * load-bearing.
 *
 * WHY THERE IS A HOST-OPS TABLE AT ALL
 * ------------------------------------
 * This module is a shared object. modulesd links the STATIC libwazuh, so a .so that also linked
 * libwazuh would put a second copy of its globals in one process. No .so under wazuh_modules/
 * links it, and this one must not either.
 *
 * Almost nothing here needs it: storage is in-process SQLite, transport is
 * shared_modules/uds_http_server, and the outbound consumer calls go over libcurl. What is left is
 * the handful of operations whose implementation genuinely lives in libwazuh -- the cluster role,
 * the authd wire protocol, log rotation, and the three agent queries whose wazuh-db client
 * (wdbc_query_ex_timeout) is the only bounded one available. Those arrive as function pointers,
 * implemented by the C shim.
 *
 * The three agent queries are here rather than going through shared_modules/utils'
 * SocketDBWrapper because that class waits on a condition variable with NO timeout
 * (socketDBWrapper.hpp), and an unbounded wait on a wedged wazuh-db is exactly what the local
 * handlers must not do: they run on the shared executor and would hold a slot forever.
 *
 * ABI RULE: fields are APPENDED to these structs, never inserted or reordered. A stale .so paired
 * with a newer modulesd then reads garbage in no field -- it simply does not see the new ones.
 *
 * SENTINEL RULE: an int <= 0 and an empty string both mean "no opinion, use the module default".
 * Defaults live in exactly one place (the C++ module); the shim always passes 0 fallbacks through.
 *
 * THE EXCEPTION, and every field that takes it is marked `[-1 disables]` below. A handful of
 * options have a MEANINGFUL zero -- "log no agent by name", "cache nothing", "no admission bound",
 * "keep no rotated logs", "never rotate by size" -- and for those the rule above is not merely
 * imprecise, it is actively wrong: read as "no opinion", a configured zero hands back the very
 * default the operator was switching off, so the option cannot be turned off at all.
 *
 * Those fields therefore carry THREE states in one int, and -1 rather than 0 is the disabling one:
 *
 *     0   no opinion, use the module default      (unchanged from every other field)
 *    -1   the operator asked for zero: disabled / unbounded / nothing kept
 *    >0   the configured value
 *
 * Encoded that way round on purpose. A zero-initialised task_manager_config_t must mean "every
 * default", because that is what every embedder assumes -- the testtool memsets the struct and sets
 * four fields -- and making 0 mean "disabled" for six of them would silently turn off log rotation
 * and every admission bound in any caller that did not know better. The shim converts a configured
 * zero to -1 on the way through (wm_task_manager_zeroable), and the module resolves these with
 * valueOrAllowingZero() rather than valueOr().
 *
 * remoted_config_read is a third variant of the same problem, solved with an explicit validity flag
 * because BOTH of its values are <= 0.
 */

// Define EXPORTED for any platform
#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include "commonDefs.h" // full_log_fnc_t

#include <limits.h>

    /**
     * @brief Everything the module is configured with, as plain data.
     *
     * Paths are absolute and fully resolved by the shim -- the module does not know the install
     * directory. Every int follows the sentinel rule above.
     */
    typedef struct task_manager_config_t
    {
        /* ---- paths ---------------------------------------------------------------------- */
        char socket_path[PATH_MAX];          ///< UDS to bind (queue/sockets/task-http.sock).
        char db_path[PATH_MAX];              ///< tasks.db. The module is its sole owner.
        char inventory_sync_socket[PATH_MAX];///< Consumer socket for the two routed task types.

        /* ---- <task-manager> XML options ------------------------------------------------- */
        int task_ttl;           ///< Agent-task TTL in seconds before it expires.
        int cleanup_interval;   ///< Retention/expiry sweep period in seconds.
        int max_payload_bytes;  ///< Largest accepted task payload, serialized.
        int max_tasks_per_poll; ///< Cap on tasks returned by one pending-tasks call.

        /* ---- manager-task queue mechanics ----------------------------------------------- */
        int max_attempts;   ///< Default attempt budget before dead_letter.
        int max_defer;      ///< Default consecutive-deferral budget before dead_letter.
        int backoff_base;   ///< First retry delay, seconds; doubles from here.
        int backoff_cap;    ///< Ceiling for both ladders, seconds.
        int defer_base;     ///< First deferral delay, seconds.
        int wake_backstop;  ///< Max scheduler sleep, seconds. A safety net, not the mechanism.
        int sweep_interval; ///< Ownership sweep period, seconds.
        int claim_grace;    ///< Slack before a live owner's claimed row may be reclaimed.
        int wdb_timeout;    ///< Deadline on the host's wazuh-db calls, seconds.

        /* ---- per-type bounds ------------------------------------------------------------ */
        int vd_scan_timeout;      ///< Deadline on one vd_scan call, seconds.
        int delete_timeout;       ///< Deadline on one deletion call. MUST exceed vd_scan_timeout.
        int max_pending_deletes;  ///< Admission bound on pending agent_delete_indexer rows. [-1 disables: unbounded]
        int max_pending_scans;    ///< Admission bound on pending vd_scan rows. [-1 disables: unbounded]

        /* ---- retention ------------------------------------------------------------------ */
        int retention_days;             ///< Terminal rows older than this are removed.
        int dead_letter_retention_days; ///< Dead letters outlive ordinary terminal rows.
        int history_per_schedule;       ///< Finished runs kept per schedule.
        int max_rows;                   ///< Hard ceiling on MANAGER_TASKS.

        /* ---- recurring work ------------------------------------------------------------- */
        int disconnection_time; ///< <global><agents_disconnection_time>. Sweep interval AND window.
        int delete_old_agents;  ///< Minutes; 0 disables the retention deletion schedule.
        int monitor_agents;     ///< 0 disables the disconnection sweep schedule.
        int disconnect_log_max; ///< Cap on per-agent diagnostic lookups in one sweep. [-1 disables: name none]
        int rotate_log;         ///< 0 disables both rotations.
        int compress;           ///< gzip rotated logs.
        int keep_log_days;      ///< Days of rotated logs to keep. [-1 disables: keep none]
        int size_rotate_mb;     ///< Size-rotation threshold in MB. [-1 disables: no size rotation]
        int daily_rotations;    ///< Max rotations kept within one day.
        int day_wait;           ///< Seconds past local midnight for the daily slot.
        int delete_old_batch;   ///< Agents per agent_delete_old run.
        int delete_old_budget;  ///< Seconds of occupancy per agent_delete_old run.

        /* ---- threading ------------------------------------------------------------------ */
        int io_threads;       ///< uds_http_server I/O threads.
        int executor_threads; ///< Task executor workers.

        /* ---- agent upgrade --------------------------------------------------------------- */
        /*
         * Remote agent upgrades are served from this shared object, on this socket. There is no
         * agent-upgrade module on a manager, so their two settings are the task manager's own: they
         * come from the `task-manager` section of the effective document, alongside everything else
         * above.
         */
        int upgrade_enabled;                  ///< <task-manager><upgrade_enabled>. 0 refuses every agent.
        char wpk_repository[PATH_MAX];        ///< <task-manager><wpk_repository>, or empty.
        char upgrade_dir[PATH_MAX];           ///< Absolute var/upgrade/. Custom WPKs must live here.
        char manager_version[64];             ///< __wazuh_version, which the .so cannot link.
        int upgrade_workers;                  ///< Concurrent upgrade BATCHES, not agents.
        int upgrade_queue_depth;              ///< Queued batches before a request is shed.
        int upgrade_batch_deadline;           ///< Seconds. MUST expire before the peer's timeout.
        int upgrade_max_agents;               ///< Largest batch accepted in one request.
        int upgrade_download_attempts;        ///< Tries per WPK before giving up.
        int upgrade_download_timeout;         ///< Milliseconds per WPK download attempt.
        int upgrade_max_concurrent_downloads; ///< Global cap; WPKs are 50-100 MB.
        int upgrade_versions_ttl;             ///< Seconds a repository's `versions` file is cached.
                                              ///< [-1 disables: fetch every time]

        /*
         * remoted's delivery settings, read once pre-fork by the shim.
         *
         * remoted_config_read IS AN EXPLICIT EXCEPTION TO THE SENTINEL RULE ABOVE, and it has to be:
         * REMOTED_HTTPS_VERIFY_UNSET is -1 and REMOTED_HTTPS_VERIFY_NONE is 0, so BOTH meaningful
         * values of remoted_verification_mode are <= 0 and would otherwise read as "no opinion" --
         * while meaning two different things remoted resolves differently. The flag is what keeps
         * them apart. When it is 0 the two fields below are ignored entirely and the delivery gates
         * fail OPEN, reproducing what the retired code did when its ReadConfig() failed.
         */
        int remoted_config_read;
        int remoted_legacy_enabled;    ///< remote.legacy.enabled.
        int remoted_verification_mode; ///< remote.https.verification_mode.
    } task_manager_config_t;

    /**
     * @brief Operations the module cannot implement itself, supplied by modulesd.
     *
     * Every one of these is called at schedule cadence or from a task handler -- never on the
     * HTTP hot path. All are optional: a NULL pointer disables the feature that needs it and is
     * logged once at start, rather than crashing a handler later.
     *
     * The JSON-returning queries allocate with the host's allocator and are released through
     * free_json. The module never frees them itself.
     */
    typedef struct task_manager_host_ops_t
    {
        /** @brief Cluster role. Returns 1 worker, 0 master, -1 unknown (config unreadable).
         *         "Unknown" must NOT be treated as master -- that is the monitord bug this
         *         module was built to stop repeating. */
        int (*is_worker)(void);

        /** @brief Transition agents past keep_alive to disconnected. Writes a JSON array of the
         *         affected agent ids to *ids_json. Returns 0 on success, -1 on failure. */
        int (*disconnect_agents)(long keep_alive, const char* sync_status, char** ids_json);

        /** @brief Page agents in a connection status, starting after last_id. JSON array out. */
        int (*get_agents_by_status_from)(int last_id, const char* status, char** ids_json);

        /** @brief One agent's row, as a JSON object. Used for the retention window check and for
         *         the disconnection sweep's diagnostic lines. */
        int (*get_agent_info)(int agent_id, char** info_json);

        /** @brief Release anything the three queries above allocated. */
        void (*free_json)(char* json);

        /** @brief Ask authd to remove an agent. Returns 0 on success; on a protocol-level refusal
         *         returns -1 and writes authd's numeric code to *authd_error, which the caller
         *         maps -- three of those refusals are not failures. */
        int (*remove_agent)(int agent_id, int timeout_sec, int* authd_error);

        /** @brief Daily log rotation. Returns 0 on success. */
        int (*rotate_log_daily)(int compress, int keep_days, int max_rotations);

        /** @brief Size-triggered log rotation; a no-op when the log is under size_bytes.
         *         Returns 1 if it rotated, 0 if it did not, -1 on failure. */
        int (*rotate_log_size)(int compress, int keep_days, int max_rotations, long size_bytes);
    } task_manager_host_ops_t;

    /**
     * @brief Start the module. Binds the socket, opens the database and launches its own threads,
     *        then returns -- it does not block, and modulesd's module thread exits immediately
     *        after.
     *
     * @param callbackLog Logging callback (modulesd passes mtLoggingFunctionsWrapper).
     * @param config      Never NULL. Copied; not retained.
     * @param hostOps     Never NULL. Copied; the pointers inside must outlive the module.
     * @return 0 on success, non-zero if the socket could not be bound or the database could not be
     *         opened. modulesd treats that as fatal: a manager whose task queue silently did not
     *         start loses agent deletions.
     */
    EXPORTED int task_manager_start(full_log_fnc_t callbackLog,
                                    const task_manager_config_t* config,
                                    const task_manager_host_ops_t* hostOps);

    /**
     * @brief Stop the module: stops accepting, drains in-flight work within the shutdown budget,
     *        flushes pending writes and closes the database. Idempotent; safe if never started.
     *
     * In-flight rows are deliberately left `claimed` -- the next boot's startup sweep reclaims
     * them, and every handler is idempotent.
     */
    EXPORTED void task_manager_stop(void);

#ifdef __cplusplus
}
#endif

// Function-pointer typedefs. REQUIRED: modulesd loads this module via dlopen and resolves both
// symbols with dlsym (see wazuh_modules/src/wm_task_manager.c).
typedef int (*task_manager_start_func)(full_log_fnc_t callbackLog,
                                       const task_manager_config_t* config,
                                       const task_manager_host_ops_t* hostOps);
typedef void (*task_manager_stop_func)(void);

#endif // _TASK_MANAGER_H
