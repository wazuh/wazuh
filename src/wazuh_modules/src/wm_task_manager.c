/*
 * Wazuh Module for Task management
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "wm_task_manager.h"
#include "wmodules.h"
#include "sym_load.h"
#include "defs.h"

#include "auth_client.h"
#include "cluster_utils.h"
#include "log_rotate.h"
#include "task_manager.h"
#include "wazuhdb_queries_op.h"

#include <sys/stat.h>

/*
 * modulesd's side of the task manager.
 *
 * The module itself is C++ and lives in a shared object; this file loads it, hands it its
 * configuration, and implements the handful of operations it cannot perform for itself.
 *
 * WHY THERE IS A HOST-OPS TABLE. The .so cannot link libwazuh: modulesd links the STATIC one, and
 * a second copy of its globals in one process is the hazard every other C++ module here avoids. So
 * the operations whose implementation genuinely lives in libwazuh -- the cluster role, the three
 * agent queries, the authd protocol and log rotation -- are passed in as function pointers and
 * implemented below.
 */

static void *task_manager_module = NULL;
static task_manager_start_func task_manager_start_ptr = NULL;
static task_manager_stop_func task_manager_stop_ptr = NULL;

/* The wazuh-db socket the three agent queries share.
 *
 * One socket rather than one per call, because wazuh-db keeps the connection open and the queries
 * run at schedule cadence. The mutex is what makes it safe for the two handlers that can now run
 * CONCURRENTLY -- under the retired lane model they shared a thread and could not. */
static pthread_mutex_t task_manager_wdb_mutex = PTHREAD_MUTEX_INITIALIZER;
static int task_manager_wdb_sock = -1;

/* Socket deadlines for that connection. The wdb_* helpers below call wdbc_query_ex(), which sets
 * no timeouts of its own, so a wedged wazuh-db would otherwise hold an executor worker with
 * nothing able to interrupt it. */
#define WM_TASK_MANAGER_WDB_TIMEOUT 10

static wm_task_manager *task_config = NULL;

static void *wm_task_manager_main(wm_task_manager *data);
static void wm_task_manager_destroy(wm_task_manager *data);
static void wm_task_manager_stop(wm_task_manager *data);
static cJSON *wm_task_manager_dump(const wm_task_manager *data);

const wm_context WM_TASK_MANAGER_CONTEXT = {
    .name = TASK_MANAGER_WM_NAME,
    .start = (wm_routine)wm_task_manager_main,
    .destroy = (void (*)(void *))wm_task_manager_destroy,
    .dump = (cJSON * (*)(const void *)) wm_task_manager_dump,
    .sync = NULL,
    .stop = (void (*)(void *))wm_task_manager_stop,
    .query = NULL,
};

/* -------------------------------------------------------------------------------------------- */
/* Host operations                                                                                */
/* -------------------------------------------------------------------------------------------- */

/**
 * @brief Open the shared wazuh-db socket if it is not already open. Caller holds the mutex.
 *
 * ONE attempt, and a failure is a debug line rather than an error.
 *
 * Deliberately not wdbc_connect(): that is wdbc_connect_with_attempts(5), which sleeps 1, 2, 3
 * and 4 seconds between tries and then merror()s. Both halves are wrong here. wazuh-db is
 * signalled to stop in the same pass of the init script that signals modulesd, so it is normal
 * for it to be gone while this module is still draining -- an ordinary manager stop would print
 * an ERROR about an unreachable socket, indistinguishable from wazuh-db having actually crashed,
 * and hold an executor worker for ten seconds doing it, delaying the very shutdown that caused
 * it. The callers are scheduled sweeps with their own retry ladder; one refused attempt is all
 * they want.
 */
static bool wm_task_manager_wdb_connect(void) {
    if (task_manager_wdb_sock >= 0) {
        return true;
    }

    if (task_manager_wdb_sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144),
        task_manager_wdb_sock < 0) {
        mtdebug1(WM_TASK_MANAGER_LOGTAG, "Cannot reach wazuh-db at '%s': %s (%d). The sweep will run again later.",
                 WDB_LOCAL_SOCK, strerror(errno), errno);
        return false;
    }

    OS_SetSendTimeout(task_manager_wdb_sock, WM_TASK_MANAGER_WDB_TIMEOUT);
    OS_SetRecvTimeout(task_manager_wdb_sock, WM_TASK_MANAGER_WDB_TIMEOUT, 0);

    return true;
}

/**
 * @brief Render a -1 terminated id array as a JSON array string, freeing the array.
 *
 * @return Caller-owned string, or NULL. An allocation the module releases through free_json.
 */
static char *wm_task_manager_ids_to_json(int *ids) {
    cJSON *array = cJSON_CreateArray();
    char *text = NULL;

    if (!array) {
        os_free(ids);
        return NULL;
    }

    for (int i = 0; ids && ids[i] != -1; i++) {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(ids[i]));
    }

    os_free(ids);

    text = cJSON_PrintUnformatted(array);
    cJSON_Delete(array);

    return text;
}

static int wm_task_manager_host_is_worker(void) {
    return w_is_worker();
}

static int wm_task_manager_host_disconnect_agents(long keep_alive, const char *sync_status, char **ids_json) {
    int *ids = NULL;
    int retval = -1;

    if (!ids_json) {
        return -1;
    }

    *ids_json = NULL;

    w_mutex_lock(&task_manager_wdb_mutex);

    if (wm_task_manager_wdb_connect()) {
        /* NULL is unambiguously an error: an empty result still comes back as a one-element array
         * holding the -1 terminator, because the parser always finalises what it allocated. */
        if (ids = wdb_disconnect_agents((int)keep_alive, sync_status, &task_manager_wdb_sock), ids) {
            *ids_json = wm_task_manager_ids_to_json(ids);
            retval = *ids_json ? 0 : -1;
        } else {
            /* Drop the socket so the next call reconnects rather than reusing one that just
             * failed mid-protocol. */
            wdbc_close(&task_manager_wdb_sock);
        }
    }

    w_mutex_unlock(&task_manager_wdb_mutex);

    return retval;
}

static int wm_task_manager_host_agents_by_status(int last_id, const char *status, char **ids_json) {
    int *ids = NULL;
    int retval = -1;

    if (!ids_json) {
        return -1;
    }

    *ids_json = NULL;

    w_mutex_lock(&task_manager_wdb_mutex);

    if (wm_task_manager_wdb_connect()) {
        if (ids = wdb_get_agents_by_connection_status_from(last_id, status, &task_manager_wdb_sock), ids) {
            *ids_json = wm_task_manager_ids_to_json(ids);
            retval = *ids_json ? 0 : -1;
        } else {
            wdbc_close(&task_manager_wdb_sock);
        }
    }

    w_mutex_unlock(&task_manager_wdb_mutex);

    return retval;
}

static int wm_task_manager_host_agent_info(int agent_id, char **info_json) {
    cJSON *info = NULL;
    int retval = -1;

    if (!info_json) {
        return -1;
    }

    *info_json = NULL;

    w_mutex_lock(&task_manager_wdb_mutex);

    if (wm_task_manager_wdb_connect()) {
        if (info = wdb_get_agent_info(agent_id, &task_manager_wdb_sock), info) {
            *info_json = cJSON_PrintUnformatted(info);
            cJSON_Delete(info);
            retval = *info_json ? 0 : -1;
        } else {
            wdbc_close(&task_manager_wdb_sock);
        }
    }

    w_mutex_unlock(&task_manager_wdb_mutex);

    return retval;
}

static void wm_task_manager_host_free_json(char *json) {
    os_free(json);
}

static int wm_task_manager_host_remove_agent(int agent_id, int timeout_sec, int *authd_error) {
    char id[16] = "";
    int sock = -1;
    int retval = -1;

    if (authd_error) {
        *authd_error = 0;
    }

    snprintf(id, sizeof(id), "%03d", agent_id);

    /* auth_connect_timeout() rather than auth_connect(): the latter is OS_ConnectUnixDomain with no
     * socket deadlines, so a wedged authd would hold an executor worker indefinitely. A connection
     * per agent, not per sweep, because authd closes the socket after each request. */
    if (sock = auth_connect_timeout(timeout_sec > 0 ? timeout_sec : WM_TASK_MANAGER_WDB_TIMEOUT), sock < 0) {
        return -1;
    }

    retval = auth_remove_agent_code(sock, id, authd_error);

    auth_close(sock);

    return retval;
}

static int wm_task_manager_host_rotate_daily(int compress, int keep_days, int max_rotations) {
    /* One call covers the log and its JSON twin: with new_day set, w_rotate_log() rotates both in
     * the same pass, which is also what keeps their slot counters independent. There is
     * deliberately no sleep here -- the daily offset is expressed as the schedule's slot, not as a
     * blocking wait, so it cannot suspend the rotation group. */
    w_rotate_log(compress, keep_days, 1, 0, max_rotations);
    return 0;
}

static int wm_task_manager_host_rotate_size(int compress, int keep_days, int max_rotations, long size_bytes) {
    struct stat buffer = {0};
    int rotated = 0;

    if (size_bytes <= 0) {
        return 0;
    }

    if (w_stat(LOGFILE, &buffer) == 0 && buffer.st_size >= size_bytes) {
        w_rotate_log(compress, keep_days, 0, 0, max_rotations);
        rotated = 1;
    }

    if (w_stat(LOGJSONFILE, &buffer) == 0 && buffer.st_size >= size_bytes) {
        w_rotate_log(compress, keep_days, 0, 1, max_rotations);
        rotated = 1;
    }

    return rotated;
}

/* -------------------------------------------------------------------------------------------- */
/* Module lifecycle                                                                               */
/* -------------------------------------------------------------------------------------------- */

/**
 * @brief Fill the C-ABI config from the parsed configuration.
 *
 * Every integer is copied through unchanged, including zeros: zero is the "no opinion" sentinel and
 * the module resolves it against its own defaults. Deciding defaults here as well would put them in
 * two places.
 */
static void wm_task_manager_fill_config(const wm_task_manager *data, task_manager_config_t *config) {
    memset(config, 0, sizeof(*config));

    snprintf(config->socket_path, sizeof(config->socket_path), "%s", WM_TASK_MODULE_SOCK);
    snprintf(config->db_path, sizeof(config->db_path), "%s/%s", WDB_TASK_DIR, WDB_TASK_NAME ".db");
    snprintf(config->inventory_sync_socket, sizeof(config->inventory_sync_socket), "%s", INV_SYNC_SOCK);

    config->task_ttl = data->task_ttl;
    config->cleanup_interval = data->cleanup_interval;
    config->max_payload_bytes = data->max_payload_bytes;
    config->max_tasks_per_poll = data->max_tasks_per_poll;

    config->max_attempts = data->max_attempts;
    config->max_defer = data->max_defer;
    config->backoff_base = data->backoff_base;
    config->backoff_cap = data->backoff_cap;
    config->defer_base = data->defer_base;
    config->wake_backstop = data->wake_backstop;
    config->sweep_interval = data->sweep_interval;
    config->claim_grace = data->claim_grace;
    config->wdb_timeout = data->wdb_timeout;

    config->vd_scan_timeout = data->vd_scan_timeout;
    config->delete_timeout = data->delete_timeout;
    config->max_pending_deletes = data->max_pending_deletes;
    config->max_pending_scans = data->max_pending_scans;

    config->retention_days = data->retention_days;
    config->dead_letter_retention_days = data->dead_letter_retention_days;
    config->history_per_schedule = data->history_per_schedule;
    config->max_rows = data->max_rows;

    config->disconnection_time = data->disconnection_time;
    config->delete_old_agents = data->delete_old_agents;
    config->monitor_agents = data->monitor_agents;
    config->disconnect_log_max = data->disconnect_log_max;
    config->rotate_log = data->rotate_log;
    config->compress = data->compress;
    config->keep_log_days = data->keep_log_days;
    config->size_rotate_mb = data->size_rotate_mb;
    config->daily_rotations = data->daily_rotations;
    config->day_wait = data->day_wait;
    config->delete_old_batch = data->delete_old_batch;
    config->delete_old_budget = data->delete_old_budget;

    config->io_threads = data->io_threads;
    config->executor_threads = data->executor_threads;

    config->upgrade_workers = data->upgrade_workers;
    config->upgrade_queue_depth = data->upgrade_queue_depth;
    config->upgrade_batch_deadline = data->upgrade_batch_deadline;
    config->upgrade_max_agents = data->upgrade_max_agents;
    config->upgrade_download_attempts = data->upgrade_download_attempts;
    config->upgrade_download_timeout = data->upgrade_download_timeout;
    config->upgrade_max_concurrent_downloads = data->upgrade_max_concurrent_downloads;
    config->upgrade_versions_ttl = data->upgrade_versions_ttl;

    config->remoted_config_read = data->remoted_config_read;
    config->remoted_legacy_enabled = data->remoted_legacy_enabled;
    config->remoted_verification_mode = data->remoted_verification_mode;

    config->upgrade_enabled = data->upgrade_enabled ? 1 : 0;
    if (data->wpk_repository) {
        snprintf(config->wpk_repository, sizeof(config->wpk_repository), "%s", data->wpk_repository);
    }

    snprintf(config->upgrade_dir, sizeof(config->upgrade_dir), "%s/", UPGRADE_DIR);
    /* __wazuh_version is a libwazuh global, and the .so links none of libwazuh. It decides which
     * version an upgrade targets by default and whether a requested one outruns the manager, so it
     * has to cross the ABI rather than be looked up on the other side. */
    snprintf(config->manager_version, sizeof(config->manager_version), "%s", __wazuh_version);
}

static void *wm_task_manager_main(wm_task_manager *data) {
    task_manager_config_t config;
    task_manager_host_ops_t host_ops;

    task_config = data;

    if (!data->enabled) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, "Module disabled. Exiting.");
        return NULL;
    }

    if (task_manager_module = so_get_module_handle("task_manager"), !task_manager_module) {
        /* Names the file and reports dlerror(): the overwhelmingly likely cause is that
         * libtask_manager.so was built but never installed, and "cannot load the module" on its own
         * sends the reader looking at configuration instead of at ${INSTALLDIR}/lib.
         *
         * Read once into a local -- dlerror() clears the error, so a second call returns NULL. */
        const char *reason = dlerror();

        mterror_exit(WM_TASK_MANAGER_LOGTAG,
                     "Unable to load libtask_manager.so (%s); the installation is broken.",
                     reason ? reason : "no further detail");
    }

    task_manager_start_ptr = so_get_function_sym(task_manager_module, "task_manager_start");
    task_manager_stop_ptr = so_get_function_sym(task_manager_module, "task_manager_stop");

    if (!task_manager_start_ptr || !task_manager_stop_ptr) {
        mterror_exit(WM_TASK_MANAGER_LOGTAG,
                     "libtask_manager.so does not export task_manager_start/task_manager_stop; the "
                     "installation is broken.");
    }

    wm_task_manager_fill_config(data, &config);

    host_ops.is_worker = wm_task_manager_host_is_worker;
    host_ops.disconnect_agents = wm_task_manager_host_disconnect_agents;
    host_ops.get_agents_by_status_from = wm_task_manager_host_agents_by_status;
    host_ops.get_agent_info = wm_task_manager_host_agent_info;
    host_ops.free_json = wm_task_manager_host_free_json;
    host_ops.remove_agent = wm_task_manager_host_remove_agent;
    host_ops.rotate_log_daily = wm_task_manager_host_rotate_daily;
    host_ops.rotate_log_size = wm_task_manager_host_rotate_size;

    /* Fatal on failure, deliberately. A manager whose task queue silently did not start loses
     * agent deletions: authd records the intent and nothing ever executes it. */
    if (task_manager_start_ptr(mtLoggingFunctionsWrapper, &config, &host_ops) != 0) {
        mterror_exit(WM_TASK_MANAGER_LOGTAG, "Cannot start the task manager module.");
    }

    /* The module owns its own threads and start() does not block, so this one returns immediately
     * -- the same shape as every other C++ module here. */
    return NULL;
}

static void wm_task_manager_stop(__attribute__((unused)) wm_task_manager *data) {
    if (task_manager_stop_ptr) {
        task_manager_stop_ptr();
    }

    w_mutex_lock(&task_manager_wdb_mutex);
    if (task_manager_wdb_sock >= 0) {
        wdbc_close(&task_manager_wdb_sock);
    }
    w_mutex_unlock(&task_manager_wdb_mutex);

    mtinfo(WM_TASK_MANAGER_LOGTAG, "Module finished.");
}

static void wm_task_manager_destroy(wm_task_manager *data) {
    if (task_manager_module) {
        so_free_library(task_manager_module);
        task_manager_module = NULL;
    }

    if (data) {
        os_free(data->wpk_repository);
    }
    os_free(data);
    task_config = NULL;
}

static cJSON *wm_task_manager_dump(const wm_task_manager *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_tm = cJSON_CreateObject();

    /* A JSON boolean, not "yes"/"no": getconfig answers with the same types the effective document
     * uses, so a client reads one shape whether it asked the daemon or read the file. */
    cJSON_AddBoolToObject(wm_tm, "enabled", data->enabled ? 1 : 0);

    if (!data->enabled) {
        cJSON_AddItemToObject(root, "task-manager", wm_tm);
        return root;
    }

    cJSON_AddNumberToObject(wm_tm, "task_ttl", data->task_ttl);
    cJSON_AddNumberToObject(wm_tm, "cleanup_interval", data->cleanup_interval);
    cJSON_AddNumberToObject(wm_tm, "max_payload_bytes", data->max_payload_bytes);
    cJSON_AddNumberToObject(wm_tm, "max_tasks_per_poll", data->max_tasks_per_poll);

    /* The agent-upgrade options moved here when the manager side of that module did. Reported
     * under this module because this is the module that now serves them. */
    cJSON *upgrade = cJSON_CreateObject();
    cJSON_AddStringToObject(upgrade, "enabled", data->upgrade_enabled ? "yes" : "no");
    if (data->wpk_repository) {
        cJSON_AddStringToObject(upgrade, "wpk_repository", data->wpk_repository);
    }
    cJSON_AddItemToObject(wm_tm, "agent_upgrade", upgrade);

    cJSON *recurring = cJSON_CreateObject();
    cJSON_AddNumberToObject(recurring, "agents_disconnection_time", data->disconnection_time);
    cJSON_AddNumberToObject(recurring, "delete_old_agents", data->delete_old_agents);
    cJSON_AddNumberToObject(recurring, "monitor_agents", data->monitor_agents);
    cJSON_AddNumberToObject(recurring, "log_rotate", data->rotate_log);
    cJSON_AddNumberToObject(recurring, "log_compress", data->compress);
    cJSON_AddNumberToObject(recurring, "log_keep_days", data->keep_log_days);
    cJSON_AddNumberToObject(recurring, "log_daily_rotations", data->daily_rotations);
    cJSON_AddNumberToObject(recurring, "log_size_rotate", data->size_rotate_mb);
    cJSON_AddNumberToObject(recurring, "delete_old_batch", data->delete_old_batch);
    cJSON_AddNumberToObject(recurring, "delete_old_budget", data->delete_old_budget);
    cJSON_AddItemToObject(wm_tm, "recurring_tasks", recurring);

    cJSON_AddItemToObject(root, "task-manager", wm_tm);

    return root;
}

#endif
