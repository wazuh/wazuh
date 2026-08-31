/*
 * Wazuh Module for Task management: in-process manager task handlers.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"
#include "os_net.h"
#include "agent_op.h"
#include "auth_client.h"
#include "log_rotate.h"
#include "wazuhdb_op.h"
#include "wazuhdb_queries_op.h"
#include "wm_task_manager.h"
#include "wm_manager_task_local.h"
#include "wm_manager_task_schedules.h"

/* Defaults for the two bounds agent_delete_old carries. 200 agents is the count bound and 30
 * seconds the occupancy bound; the second is the one that binds in practice, because
 * external_socket_connect's send timeout is hardcoded to 5 seconds and 200 agents against a wedged
 * authd is a ~1000 second worst case on a depth-1 lane. */
#define WM_MANAGER_TASK_DEFAULT_DELETE_OLD_BATCH 200
#define WM_MANAGER_TASK_DEFAULT_DELETE_OLD_BUDGET 30

/* Rotation defaults. The manager ships no defaults file, so these are the whole contract. */
#define WM_MANAGER_TASK_DEFAULT_ROTATE_LOG 1
#define WM_MANAGER_TASK_DEFAULT_COMPRESS 1
#define WM_MANAGER_TASK_DEFAULT_KEEP_LOG_DAYS 31
#define WM_MANAGER_TASK_DEFAULT_SIZE_ROTATE 512
#define WM_MANAGER_TASK_DEFAULT_DAILY_ROTATIONS 12
#define WM_MANAGER_TASK_DEFAULT_WDB_TIMEOUT 10

/// Deadline on one authd round trip. Only the receive side; the send side is authd's own 5 seconds.
#define WM_MANAGER_TASK_AUTHD_TIMEOUT 10

/* Watchdog budgets, in seconds. See wm_manager_task_local_watchdog_budget() for what each one is
 * measuring and why none of them is a deadline. */
#define WM_MANAGER_TASK_DELETE_OLD_SLACK 60
#define WM_MANAGER_TASK_WATCHDOG_SWEEP 300
#define WM_MANAGER_TASK_WATCHDOG_ROTATE 900
#define WM_MANAGER_TASK_WATCHDOG_FALLBACK 300

/* authd's local-server error codes, spelled out because its enum is private to os_auth/. Each one
 * below is load-bearing in wm_manager_task_delete_old_outcome(); the rest fall to its default. */
#define WM_MANAGER_TASK_AUTHD_NO_SUCH_ID 9010
#define WM_MANAGER_TASK_AUTHD_ID_NOT_FOUND 9011
#define WM_MANAGER_TASK_AUTHD_WORKER_NODE 9015
#define WM_MANAGER_TASK_AUTHD_PENDING_PURGE 9018
#define WM_MANAGER_TASK_AUTHD_DELETE_BACKLOG 9020

STATIC wm_manager_task_local_config manager_task_local_config = {0};

/* This module's own wazuh-db socket, shared by the two handlers that need one.
 *
 * One socket is safe because all three handlers run on the depth-1 `local` lane, so only one of
 * them is ever executing. The mutex is there so that assumption is not load-bearing: raising the
 * lane's depth is a one-line change in the registry, and without it the failure would be two
 * threads interleaving on one socket -- silent, intermittent and nothing like a compile error. */
STATIC int manager_task_local_wdb_sock = -1;
STATIC pthread_mutex_t manager_task_local_wdb_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Where the last bounded agent_delete_old attempt stopped, so the next one resumes rather than
 * re-examining the same prefix.
 *
 * WITHOUT THIS THE SWEEP CAN LIVELOCK. The candidate list comes back ordered by agent id, and the
 * expensive part is one wdb_get_agent_info() per candidate. A batch bound with no cursor would
 * examine the same first 200 disconnected agents on every attempt, and if none of them is old
 * enough to delete, it would never reach the ones that are.
 *
 * Keyed on the slot rather than on the task id, because the id is not passed to a handler and the
 * slot identifies the run just as uniquely. A slot that does not match resets the walk, so a fresh
 * run always starts from the beginning of the list.
 *
 * In memory only, deliberately. A restart loses the cursor and the next run re-walks from the
 * start, which is exactly the idempotent repeat the design already requires of every handler:
 * agents deleted in the abandoned attempt are no longer in the candidate list at all. */
STATIC long long manager_task_delete_old_slot = 0;
STATIC int manager_task_delete_old_cursor = 0;

void wm_manager_task_local_init(void) {
    wm_manager_task_schedule *schedules = NULL;
    size_t loaded = 0;

    memset(&manager_task_local_config, 0, sizeof(manager_task_local_config));

    /* The disconnection window comes from the schedule table rather than being read a second time
     * here. Two readers of one option is how the sweep's window and the schedule that fires it
     * drift apart -- and they are the same quantity: the window IS the interval. */
    os_calloc(wm_manager_task_schedules_count(), sizeof(wm_manager_task_schedule), schedules);

    loaded = wm_manager_task_schedules_load(schedules);

    for (size_t i = 0; i < loaded; i++) {
        if (!schedules[i].def) {
            continue;
        }

        if (strcmp(schedules[i].def->task_type, "agent_disconnect_sweep") == 0) {
            manager_task_local_config.disconnection_time = schedules[i].interval;
        }
    }

    os_free(schedules);

    manager_task_local_config.delete_old_agents =
        getDefine_Int_default("wazuh_modules", "manager_task_delete_old_agents", 0, 9600, 0);
    manager_task_local_config.monitor_agents =
        getDefine_Int_default("wazuh_modules", "manager_task_monitor_agents", 0, 1, 1);
    manager_task_local_config.rotate_log =
        getDefine_Int_default("wazuh_modules", "manager_task_log_rotate", 0, 1,
                              WM_MANAGER_TASK_DEFAULT_ROTATE_LOG);
    manager_task_local_config.compress =
        getDefine_Int_default("wazuh_modules", "manager_task_log_compress", 0, 1,
                              WM_MANAGER_TASK_DEFAULT_COMPRESS);
    manager_task_local_config.keep_log_days =
        getDefine_Int_default("wazuh_modules", "manager_task_log_keep_days", 0, 500,
                              WM_MANAGER_TASK_DEFAULT_KEEP_LOG_DAYS);
    // Megabytes on the way in, bytes from here on: the option names a file size an operator thinks
    // about in megabytes, and every comparison below is against st_size.
    manager_task_local_config.size_rotate =
        (long)getDefine_Int_default("wazuh_modules", "manager_task_log_size_rotate", 0, 4096,
                                    WM_MANAGER_TASK_DEFAULT_SIZE_ROTATE) * 1024 * 1024;
    manager_task_local_config.daily_rotations =
        getDefine_Int_default("wazuh_modules", "manager_task_log_daily_rotations", 1, 256,
                              WM_MANAGER_TASK_DEFAULT_DAILY_ROTATIONS);

    manager_task_local_config.delete_old_batch =
        getDefine_Int_default("wazuh_modules", "manager_task_delete_old_batch", 1, 100000,
                              WM_MANAGER_TASK_DEFAULT_DELETE_OLD_BATCH);
    manager_task_local_config.delete_old_budget =
        getDefine_Int_default("wazuh_modules", "manager_task_delete_old_budget", 1, 3600,
                              WM_MANAGER_TASK_DEFAULT_DELETE_OLD_BUDGET);
    manager_task_local_config.wdb_timeout = getDefine_Int_default("wazuh_modules", "manager_task_wdb_timeout", 1, 300,
                                                                  WM_MANAGER_TASK_DEFAULT_WDB_TIMEOUT);
}

const wm_manager_task_local_config* wm_manager_task_local_config_get(void) {
    return &manager_task_local_config;
}

int wm_manager_task_local_watchdog_budget(const char *task_type) {
    if (!task_type) {
        return WM_MANAGER_TASK_WATCHDOG_FALLBACK;
    }

    if (strcmp(task_type, "agent_delete_old") == 0) {
        /* Derived from the sweep's own occupancy budget rather than fixed, because that budget is
         * configurable up to an hour: a constant would warn on every run of a deployment that raised
         * it. The budget is checked BEFORE each agent, so one attempt legitimately overruns it by
         * one agent's cost -- a wazuh-db lookup plus an authd round trip, each with its own
         * deadline -- which is what the slack covers. */
        return manager_task_local_config.delete_old_budget + WM_MANAGER_TASK_DELETE_OLD_SLACK;
    }

    if (strcmp(task_type, "agent_disconnect_sweep") == 0) {
        /* One wazuh-db sweep plus one name lookup per newly disconnected agent. Not bounded by a
         * count, so this is a judgement rather than a derivation: a sweep still running after five
         * minutes is either against a very large fleet transitioning at once or genuinely stuck, and
         * both are worth a line. */
        return WM_MANAGER_TASK_WATCHDOG_SWEEP;
    }

    if (strcmp(task_type, "log_rotate_daily") == 0) {
        // Two files, each gzipped inline at up to the configured threshold. Compression rate is the
        // unknown, so the budget is generous on purpose.
        return WM_MANAGER_TASK_WATCHDOG_ROTATE;
    }

    return WM_MANAGER_TASK_WATCHDOG_FALLBACK;
}

void wm_manager_task_local_teardown(void) {
    w_mutex_lock(&manager_task_local_wdb_mutex);
    wdbc_close(&manager_task_local_wdb_sock);
    w_mutex_unlock(&manager_task_local_wdb_mutex);
}

/**
 * @brief Connect this module's wazuh-db socket if it is not already up, with deadlines set.
 *
 * The deadlines are the point. wdbc_connect() retries with a 1+2+3+4+5 second sleep ladder and sets
 * no socket timeouts at all, so a wazuh-db that accepts the connection and then stops answering
 * parks the lane indefinitely -- and the query helpers this module calls
 * (wdb_disconnect_agents(), wdb_get_agent_info()) reach wdbc_query_ex(), which has no timeout
 * parameter to pass one through.
 *
 * Residual, stated rather than hidden: if one of those helpers hits a broken pipe mid-walk it
 * reconnects internally through the untimed path, so that one socket loses its deadlines. Every
 * caller here closes the socket on any failure, which is what keeps such a socket from becoming the
 * long-lived one.
 *
 * @return true when the socket is usable.
 */
STATIC bool wm_manager_task_local_wdb_connect(void) {
    if (manager_task_local_wdb_sock >= 0) {
        return true;
    }

    if (manager_task_local_wdb_sock = wdbc_connect(), manager_task_local_wdb_sock < 0) {
        return false;
    }

    if (OS_SetSendTimeout(manager_task_local_wdb_sock, manager_task_local_config.wdb_timeout) < 0 ||
        OS_SetRecvTimeout(manager_task_local_wdb_sock, manager_task_local_config.wdb_timeout, 0) < 0) {
        mtwarn(WM_TASK_MANAGER_LOGTAG, "Cannot set deadlines on the manager task wazuh-db socket: %s (%d)",
               strerror(errno), errno);
        wdbc_close(&manager_task_local_wdb_sock);
        return false;
    }

    return true;
}

bool wm_manager_task_delete_old_expired(long long last_keepalive,
                                        long long now,
                                        int disconnection_time,
                                        int delete_old_agents) {
    if (delete_old_agents <= 0) {
        return false;
    }

    return last_keepalive < now - ((long long)disconnection_time + (long long)delete_old_agents * 60);
}

wm_manager_task_result wm_manager_task_delete_old_outcome(bool answered,
                                                          int authd_error,
                                                          char *error,
                                                          size_t error_len) {
    if (!answered) {
        snprintf(error, error_len, "authd did not answer the removal");
        return WM_MANAGER_TASK_RETRYABLE;
    }

    switch (authd_error) {
    case 0:
    case WM_MANAGER_TASK_AUTHD_NO_SUCH_ID:
    case WM_MANAGER_TASK_AUTHD_ID_NOT_FOUND:
        // Already gone. The sweep wanted the agent removed and it is; treating a second delete of
        // a deleted agent as a failure is what would make this handler non-idempotent, and the
        // design requires it to tolerate being re-run after a lost outcome write.
        return WM_MANAGER_TASK_OK;

    case WM_MANAGER_TASK_AUTHD_PENDING_PURGE:
        // Someone already asked, and authd has journaled the intent -- so the removal will happen
        // whether or not this sweep waits for it. Nothing left for this agent.
        return WM_MANAGER_TASK_OK;

    case WM_MANAGER_TASK_AUTHD_DELETE_BACKLOG:
        // The refusal this whole mapping exists for. authd is holding as many journaled deletions
        // as its backlog bound allows, so the agent is still there and the sweep must come back.
        // Retryable rather than incomplete, deliberately: incomplete re-claims at once, which
        // would spin against a saturated authd, while retryable takes the backoff ladder.
        snprintf(error, error_len, "authd's deletion backlog is full");
        return WM_MANAGER_TASK_RETRYABLE;

    case WM_MANAGER_TASK_AUTHD_WORKER_NODE:
        // A master-scoped schedule spawned this row, so reaching here means the node was demoted
        // between the spawn and the run. No retry can help; the new master's own schedule will.
        snprintf(error, error_len, "this node is no longer the cluster master");
        return WM_MANAGER_TASK_TERMINAL;

    default:
        snprintf(error, error_len, "authd refused the removal with error %d", authd_error);
        return WM_MANAGER_TASK_RETRYABLE;
    }
}

wm_manager_task_result wm_manager_task_handler_agent_disconnect_sweep(__attribute__((unused)) const char *agent_id,
                                                                     __attribute__((unused)) const char *payload,
                                                                     char *error,
                                                                     size_t error_len) {
    int *disconnected = NULL;
    int count = 0;

    w_mutex_lock(&manager_task_local_wdb_mutex);

    if (!wm_manager_task_local_wdb_connect()) {
        w_mutex_unlock(&manager_task_local_wdb_mutex);
        snprintf(error, error_len, "cannot reach wazuh-db");
        return WM_MANAGER_TASK_RETRYABLE;
    }

    /* "synced" is the sync_status written onto the transitioned rows, not a filter on which agents
     * are considered: the master marks agents in its own database and no cluster synchronisation is
     * involved, so the rows are already in their final state. */
    disconnected = wdb_disconnect_agents((int)(time(NULL) - manager_task_local_config.disconnection_time), "synced",
                                         &manager_task_local_wdb_sock);

    if (!disconnected) {
        // NULL is unambiguously an error here: an empty result still comes back as a one-element
        // array holding the -1 terminator, because the parser always finalises what it allocated.
        wdbc_close(&manager_task_local_wdb_sock);
        w_mutex_unlock(&manager_task_local_wdb_mutex);
        snprintf(error, error_len, "wazuh-db did not complete the disconnection sweep");
        return WM_MANAGER_TASK_RETRYABLE;
    }

    for (int i = 0; disconnected[i] != -1; i++) {
        cJSON *info = NULL;
        const cJSON *name = NULL;

        count++;

        // The flag silences this line and nothing else: the DB transition above runs regardless.
        // With logging off there is no reason to pay a round trip per agent, which is the whole
        // cost of this loop.
        if (!manager_task_local_config.monitor_agents) {
            continue;
        }

        /* One lookup per NEWLY DISCONNECTED agent, once per sweep. The name is the only reason for
         * the lookup -- the id is already in hand -- and OS_AG_DISCON carries both. */
        if (info = wdb_get_agent_info(disconnected[i], &manager_task_local_wdb_sock), !info) {
            mtdebug2(WM_TASK_MANAGER_LOGTAG, "Cannot read agent '%d' data; its disconnection is not logged by name.",
                     disconnected[i]);
            continue;
        }

        if (name = cJSON_GetObjectItem(info->child, "name"), name && cJSON_IsString(name)) {
            // Level and message are unchanged from the previous implementation, so an operator's
            // existing log filters keep matching. The prefix and the trailing period are part of
            // OS_AG_DISCON.
            mtdebug1(WM_TASK_MANAGER_LOGTAG, OS_AG_DISCON, disconnected[i], name->valuestring);
        }

        cJSON_Delete(info);
    }

    w_mutex_unlock(&manager_task_local_wdb_mutex);

    os_free(disconnected);

    if (count > 0) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, "Agent disconnection sweep transitioned %d agent(s) to disconnected.", count);
    }

    return WM_MANAGER_TASK_OK;
}

/**
 * @brief Read the slot a scheduled row was spawned for, which keys the delete_old cursor.
 *
 * @param[in] payload The row's payload.
 * @return The slot, or 0 when the payload does not carry one.
 */
STATIC long long wm_manager_task_payload_slot(const char *payload) {
    cJSON *parsed = NULL;
    const cJSON *slot = NULL;
    long long value = 0;

    if (!payload || !*payload) {
        return 0;
    }

    if (parsed = cJSON_Parse(payload), !parsed) {
        return 0;
    }

    if (slot = cJSON_GetObjectItem(parsed, "scheduled_run_at"), slot && cJSON_IsNumber(slot)) {
        value = (long long)slot->valuedouble;
    }

    cJSON_Delete(parsed);

    return value;
}

/**
 * @brief Remove one agent through authd, bounded.
 *
 * @param[in] agent_id Agent to remove.
 * @param[out] error Short reason, written on any non-OK result.
 * @param[in] error_len Size of that buffer.
 * @return What this agent's outcome means for the sweep.
 */
STATIC wm_manager_task_result wm_manager_task_remove_agent(int agent_id, char *error, size_t error_len) {
    char id[16];
    int sock = -1;
    int authd_error = 0;
    bool answered = false;

    snprintf(id, sizeof(id), "%03d", agent_id);

    /* auth_connect_timeout() rather than auth_connect(): the latter is OS_ConnectUnixDomain with no
     * socket deadlines, so a wedged authd would hold this lane with nothing able to interrupt it.
     * A connection per agent, not per sweep, because authd closes the socket after each request. */
    if (sock = auth_connect_timeout(WM_MANAGER_TASK_AUTHD_TIMEOUT), sock < 0) {
        snprintf(error, error_len, "cannot reach authd");
        return WM_MANAGER_TASK_RETRYABLE;
    }

    answered = auth_remove_agent_code(sock, id, &authd_error) == 0;

    auth_close(sock);

    return wm_manager_task_delete_old_outcome(answered, authd_error, error, error_len);
}

wm_manager_task_result wm_manager_task_handler_agent_delete_old(__attribute__((unused)) const char *agent_id,
                                                                const char *payload,
                                                                char *error,
                                                                size_t error_len) {
    int *candidates = NULL;
    long long slot = wm_manager_task_payload_slot(payload);
    time_t started = time(NULL);
    int examined = 0;
    int removed = 0;
    bool exhausted = true;
    wm_manager_task_result result = WM_MANAGER_TASK_OK;

    if (manager_task_local_config.delete_old_agents <= 0) {
        // Reachable only through a row that outlived the option being turned off. Completing it is
        // right: the work it asked for is no longer wanted, and failing it would dead-letter a row
        // over a configuration change.
        return WM_MANAGER_TASK_OK;
    }

    // A different slot is a different run, so the walk starts over. Equal slots are attempts at one
    // run, which is what the cursor is for.
    if (slot != manager_task_delete_old_slot) {
        manager_task_delete_old_slot = slot;
        manager_task_delete_old_cursor = 0;
    }

    w_mutex_lock(&manager_task_local_wdb_mutex);

    if (!wm_manager_task_local_wdb_connect()) {
        w_mutex_unlock(&manager_task_local_wdb_mutex);
        snprintf(error, error_len, "cannot reach wazuh-db");
        return WM_MANAGER_TASK_RETRYABLE;
    }

    /* The whole candidate list, every attempt. It is a single indexed column walk that wazuh-db
     * already pages internally, so re-reading it is cheap next to one wdb_get_agent_info() per
     * candidate -- and re-reading is what keeps the cursor honest, because agents removed by the
     * previous attempt are simply no longer in it. */
    candidates = wdb_get_agents_by_connection_status("disconnected", &manager_task_local_wdb_sock);

    if (!candidates) {
        wdbc_close(&manager_task_local_wdb_sock);
        w_mutex_unlock(&manager_task_local_wdb_mutex);
        snprintf(error, error_len, "wazuh-db did not return the disconnected agents");
        return WM_MANAGER_TASK_RETRYABLE;
    }

    for (int i = 0; candidates[i] != -1; i++) {
        cJSON *info = NULL;
        const cJSON *last_keepalive = NULL;
        const cJSON *name = NULL;

        // Resume. The list is ordered by agent id, which is what makes a single integer a valid
        // cursor over it.
        if (candidates[i] <= manager_task_delete_old_cursor) {
            continue;
        }

        if (examined >= manager_task_local_config.delete_old_batch ||
            (long long)(time(NULL) - started) >= manager_task_local_config.delete_old_budget) {
            // Bound reached with candidates left. Neither success nor failure: completing would end
            // the row with the sweep half done, and consuming an attempt would dead-letter a fleet
            // that simply needs more batches than the budget allows.
            exhausted = false;
            break;
        }

        if (wm_shutdown_requested) {
            exhausted = false;
            break;
        }

        examined++;

        if (info = wdb_get_agent_info(candidates[i], &manager_task_local_wdb_sock), !info) {
            // Not fatal to the sweep and not retried for this agent: the next run reads it again.
            mtdebug2(WM_TASK_MANAGER_LOGTAG, "Cannot read agent '%d' data; skipping it this run.", candidates[i]);
            manager_task_delete_old_cursor = candidates[i];
            continue;
        }

        last_keepalive = cJSON_GetObjectItem(info->child, "last_keepalive");
        name = cJSON_GetObjectItem(info->child, "name");

        if (last_keepalive && cJSON_IsNumber(last_keepalive) &&
            wm_manager_task_delete_old_expired((long long)last_keepalive->valuedouble, (long long)time(NULL),
                                               manager_task_local_config.disconnection_time,
                                               manager_task_local_config.delete_old_agents)) {
            /* BY ID. The id has been in hand since the candidate query, so nothing round-trips
             * through a name -- which would be ambiguous for duplicate names and would have to be
             * split back out of a composite string. */
            result = wm_manager_task_remove_agent(candidates[i], error, error_len);

            if (result == WM_MANAGER_TASK_OK) {
                removed++;

                if (name && cJSON_IsString(name)) {
                    mtdebug1(WM_TASK_MANAGER_LOGTAG, OS_AG_REMOVED, candidates[i], name->valuestring);
                }
            } else {
                /* A refusal that is not "already gone" stops the sweep here rather than walking on.
                 * The two reachable causes -- a full deletion backlog and an unreachable authd --
                 * are both about authd's capacity, not about this agent, so the next candidate
                 * would answer the same way and each attempt costs a connect. The cursor stays
                 * where it is, so the retry resumes at this agent. */
                cJSON_Delete(info);
                exhausted = false;
                break;
            }
        }

        manager_task_delete_old_cursor = candidates[i];

        cJSON_Delete(info);
    }

    w_mutex_unlock(&manager_task_local_wdb_mutex);

    os_free(candidates);

    if (removed > 0) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, "Agent retention sweep removed %d agent(s) disconnected for longer than %d "
               "minute(s).", removed, manager_task_local_config.delete_old_agents);
    }

    if (result != WM_MANAGER_TASK_OK) {
        return result;
    }

    if (exhausted) {
        // The walk reached the end of the list, so this run is done and the next one starts over.
        manager_task_delete_old_cursor = 0;
        return WM_MANAGER_TASK_OK;
    }

    return WM_MANAGER_TASK_INCOMPLETE;
}

wm_manager_task_result wm_manager_task_handler_log_rotate_daily(__attribute__((unused)) const char *agent_id,
                                                               __attribute__((unused)) const char *payload,
                                                               __attribute__((unused)) char *error,
                                                               __attribute__((unused)) size_t error_len) {
    if (!manager_task_local_config.rotate_log) {
        // Only reachable through a row that outlived the option being turned off, since the
        // schedule stops spawning when it is. Completing is right: the row asked for work nobody
        // wants any more.
        return WM_MANAGER_TASK_OK;
    }

    /* One call for both files: with new_day set, w_rotate_log() rotates the log and its JSON twin
     * in the same pass, which is also what keeps their slot counters independent.
     *
     * THERE IS NO sleep(day_wait) HERE. The offset is the schedule's slot, so the delay is expressed
     * as a time to run at rather than as a blocking call -- which matters because this handler
     * shares its lane with size-based rotation, and a sleep would suspend that for its whole
     * duration.
     *
     * IDEMPOTENCY, since the dispatcher may re-run this after a lost outcome write: a second
     * rotation of an already-rotated log moves a nearly empty file into the next free daily slot.
     * Harmless, and specifically not destructive, because the slot probe now looks for both the
     * compressed and the uncompressed form of each slot -- before that fix it would have renamed
     * straight over the first rotation's output. */
    w_rotate_log(manager_task_local_config.compress, manager_task_local_config.keep_log_days, 1, 0,
                 manager_task_local_config.daily_rotations);

    return WM_MANAGER_TASK_OK;
}

void wm_manager_task_log_rotate_size(void) {
    struct stat buffer = {0};

    if (!manager_task_local_config.rotate_log || manager_task_local_config.size_rotate <= 0) {
        return;
    }

    if (w_stat(LOGFILE, &buffer) == 0 && buffer.st_size >= manager_task_local_config.size_rotate) {
        w_rotate_log(manager_task_local_config.compress, manager_task_local_config.keep_log_days, 0, 0,
                     manager_task_local_config.daily_rotations);
    }

    if (w_stat(LOGJSONFILE, &buffer) == 0 && buffer.st_size >= manager_task_local_config.size_rotate) {
        w_rotate_log(manager_task_local_config.compress, manager_task_local_config.keep_log_days, 0, 1,
                     manager_task_local_config.daily_rotations);
    }
}
