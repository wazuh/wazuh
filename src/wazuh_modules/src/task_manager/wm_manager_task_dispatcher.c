/*
 * Wazuh Module for Task management: manager task dispatcher.
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
#include "http_op.h"
#include "manager_task_op.h"
#include "wm_task_manager.h"
#include "wm_manager_task_dispatcher.h"
#include "wm_manager_task_local.h"

#define WM_MANAGER_TASK_DEFAULT_POLL_INTERVAL 5
#define WM_MANAGER_TASK_DEFAULT_SWEEP_INTERVAL 60
#define WM_MANAGER_TASK_DEFAULT_CLAIM_GRACE 30

/* How often the size-rotation direct action is signalled. Not an operator knob: it is the interval
 * at which two w_stat() calls decide whether a log has crossed its threshold, and the threshold is
 * the option that governs rotation. A minute of extra log growth cannot meaningfully overshoot that
 * boundary, so checking more often only spends stat calls. */
#define WM_MANAGER_TASK_SIZE_ROTATE_INTERVAL 60

/* Where an unknown schedule's slot is pushed to. Not a real cadence -- nothing in this build can
 * run the row -- only far enough out that a stranded schedule is polled once a day instead of
 * every five seconds, while still being visible in the log. */
#define WM_MANAGER_TASK_UNKNOWN_SCHEDULE_BACKOFF 86400

/// Slack over a call's own deadline before the watchdog calls it a stall rather than a slow call.
#define WM_MANAGER_TASK_WATCHDOG_MARGIN 30

/* How long an idle lane worker parks before claiming unprompted.
 *
 * A lost-wakeup net, NOT the poll mechanism: discovery is the scheduler's one grouped
 * poll_manager_tasks per poll_interval, which signals only the lanes that have work actually due.
 * Waking every worker on a short timer instead makes every worker issue its own claim, which is
 * the cost the grouped poll exists to avoid -- on an idle manager with no manager task ever
 * created, that is one wazuh-db query per worker per tick, forever.
 *
 * Long enough to be negligible, short enough that a lane cannot sit idle indefinitely if a signal
 * is ever missed. A missed signal otherwise self-heals on the next scheduler poll anyway, since a
 * row that is still due is signalled again. */
#define WM_MANAGER_TASK_LANE_IDLE_FALLBACK 60

/// Longest error text carried into LAST_ERROR.
#define WM_MANAGER_TASK_ERROR_LEN 256

/* The direct actions. One entry today; the table is what keeps a second one from becoming a second
 * ad-hoc flag threaded through the lane loop. */
STATIC const wm_manager_task_direct_def manager_task_direct_actions[] = {
    {
        .name = "log_rotate_size",
        .lane = WM_MANAGER_TASK_LANE_LOCAL,
        .interval = WM_MANAGER_TASK_SIZE_ROTATE_INTERVAL,
        .run = wm_manager_task_log_rotate_size,
    },
};

#define DIRECT_COUNT (sizeof(manager_task_direct_actions) / sizeof(*manager_task_direct_actions))

size_t wm_manager_task_direct_count(void) {
    return DIRECT_COUNT;
}

const wm_manager_task_direct_def* wm_manager_task_direct_at(size_t index) {
    return index < DIRECT_COUNT ? &manager_task_direct_actions[index] : NULL;
}

wm_manager_task_spawn_decision wm_manager_task_spawn_decide(bool known,
                                                            bool node_allows,
                                                            bool overlap_known,
                                                            bool has_active) {
    if (!known) {
        // Nothing here can run it, so holding would poll a row this build cannot act on forever.
        return WM_MANAGER_TASK_SPAWN_SKIP;
    }

    if (!node_allows) {
        return WM_MANAGER_TASK_SPAWN_SKIP;
    }

    if (!overlap_known) {
        // An unanswered overlap check is not the same as "no instance". Advancing on it would skip
        // this run outright; holding costs one query on the next poll.
        return WM_MANAGER_TASK_SPAWN_HOLD;
    }

    if (has_active) {
        // The previous instance is still pending or claimed. Advancing rather than holding is what
        // makes the schedule's own long run suppress its next slot instead of queueing one behind
        // it, so a sweep that outlives its interval never accumulates a backlog of itself.
        return WM_MANAGER_TASK_SPAWN_SKIP;
    }

    return WM_MANAGER_TASK_SPAWN;
}

/**
 * @brief Whether the threads this dispatcher owns should stop.
 *
 * Two sources, and both are needed. `wm_shutdown_requested` is the module's, set when modulesd is
 * coming down. `dispatcher->stopping` is this struct's own, and covers the case the module flag
 * cannot: a start() that failed partway has to bring down the workers it already created while
 * modulesd carries on running. It also makes stop() self-contained rather than only correct when
 * the caller happens to have set the module flag first.
 */
STATIC bool wm_manager_task_stopping(const wm_manager_task_dispatcher *dispatcher) {
    return wm_shutdown_requested || (dispatcher && dispatcher->stopping);
}

const wm_manager_task_descriptor* wm_manager_task_rotate(wm_manager_task_lane lane, size_t *rotation, size_t offset) {
    size_t count = 0;
    const wm_manager_task_descriptor **types = wm_manager_task_registry_lane(lane, &count);

    if (!types || count == 0 || !rotation || offset >= count) {
        return NULL;
    }

    return types[(*rotation + offset) % count];
}

bool wm_manager_task_worker_stalled(bool inflight, time_t last_progress_at, long request_timeout_ms, time_t now) {
    long long deadline = 0;

    if (!inflight || last_progress_at <= 0) {
        return false;
    }

    // The margin keeps a call that is merely close to its own deadline from being reported as a
    // hang, which would make the warning meaningless on any lane whose work legitimately runs
    // for minutes.
    deadline = (request_timeout_ms > 0 ? request_timeout_ms / 1000 : 0) + WM_MANAGER_TASK_WATCHDOG_MARGIN;

    return (long long)(now - last_progress_at) > deadline;
}

bool wm_manager_task_worker_inflight(const wm_manager_task_dispatcher *dispatcher,
                                     const char *owner,
                                     char *task_id,
                                     size_t len) {
    if (!task_id || !len) {
        return false;
    }

    *task_id = '\0';

    if (!dispatcher || !owner) {
        return false;
    }

    for (size_t i = 0; i < dispatcher->worker_count; i++) {
        wm_manager_task_worker *worker = &dispatcher->workers[i];

        if (strcmp(worker->owner, owner) != 0) {
            continue;
        }

        w_mutex_lock(&worker->published_mutex);

        if (worker->inflight) {
            strncpy(task_id, worker->inflight_task_id, len - 1);
            task_id[len - 1] = '\0';
        }

        w_mutex_unlock(&worker->published_mutex);

        return true;
    }

    return false;
}

/**
 * @brief Publish what a worker is executing, for the sweep and the watchdog to read.
 */
STATIC void wm_manager_task_publish(wm_manager_task_worker *worker, const char *task_id, long request_timeout_ms) {
    w_mutex_lock(&worker->published_mutex);

    if (task_id) {
        strncpy(worker->inflight_task_id, task_id, sizeof(worker->inflight_task_id) - 1);
        worker->inflight_task_id[sizeof(worker->inflight_task_id) - 1] = '\0';
        worker->inflight = true;
        worker->last_progress_at = time(NULL);
        worker->request_timeout_ms = request_timeout_ms;
    } else {
        worker->inflight_task_id[0] = '\0';
        worker->inflight = false;
        worker->last_progress_at = 0;
        worker->request_timeout_ms = 0;
    }

    w_mutex_unlock(&worker->published_mutex);
}

/**
 * @brief Run one task, either over its consumer's socket or in this process.
 *
 * @param[out] error Short reason, written on any non-OK result.
 * @return The outcome of this attempt.
 */
STATIC wm_manager_task_result wm_manager_task_execute(wm_manager_task_worker *worker,
                                                      const wm_manager_task_descriptor *desc,
                                                      const char *agent_id,
                                                      const char *payload,
                                                      char *error,
                                                      size_t error_len) {
    uhttp_result_t result = {0};
    char url[PATH_MAX];
    int rc = 0;

    if (!desc->path) {
        return desc->handler(agent_id, payload, error, error_len);
    }

    if (!worker->http) {
        snprintf(error, error_len, "no HTTP client for this lane");
        return WM_MANAGER_TASK_TERMINAL;
    }

    snprintf(url, sizeof(url), "http://localhost%s", desc->path);

    if (uhttp_client_set_url(worker->http, url) != 0 ||
        uhttp_client_set_unix_sock(worker->http, desc->socket_path) != 0) {
        snprintf(error, error_len, "cannot target %s on %s", desc->path, desc->socket_path);
        return WM_MANAGER_TASK_TERMINAL;
    }

    uhttp_client_set_response_buffer(worker->http, worker->response, sizeof(worker->response));

    rc = uhttp_post(worker->http, payload, payload ? strlen(payload) : 0, &result);

    // The result struct is zeroed above, before every call. The "request was never sent"
    // sentinel is a return of -1 with it still untouched, so a struct carrying the previous
    // call's values would present that call's outcome as this one's.
    return wm_manager_task_classify_response(rc, &result, worker->response, sizeof(worker->response),
                                             desc->allow_terminal_failure, error, error_len);
}

/**
 * @brief Claim, run and record one task of one type.
 *
 * @return true when a task was claimed, whatever its outcome.
 */
STATIC bool wm_manager_task_run_one(wm_manager_task_dispatcher *dispatcher,
                                    wm_manager_task_worker *worker,
                                    const wm_manager_task_descriptor *desc) {
    cJSON *task = NULL;
    cJSON *item = NULL;
    wm_manager_task_transition_t transition = {0};
    wm_manager_task_result result = WM_MANAGER_TASK_RETRYABLE;
    char error[WM_MANAGER_TASK_ERROR_LEN] = "";
    char task_id[WM_MANAGER_TASK_ID_LEN] = "";
    char *agent_id = NULL;
    const char *payload = "";
    int attempts = 0;
    int defer_count = 0;

    if (wm_manager_task_client_claim(&worker->client, desc->name, worker->owner, &task) != 0 || !task) {
        return false;
    }

    if (item = cJSON_GetObjectItem(task, "task_id"), item && cJSON_IsString(item)) {
        strncpy(task_id, item->valuestring, sizeof(task_id) - 1);
    }

    if (item = cJSON_GetObjectItem(task, "agent_id"), item && cJSON_IsString(item)) {
        os_strdup(item->valuestring, agent_id);
    }

    if (item = cJSON_GetObjectItem(task, "payload"), item && cJSON_IsString(item)) {
        payload = item->valuestring;
    }

    if (item = cJSON_GetObjectItem(task, "attempts"), item && cJSON_IsNumber(item)) {
        attempts = item->valueint;
    }

    if (item = cJSON_GetObjectItem(task, "defer_count"), item && cJSON_IsNumber(item)) {
        defer_count = item->valueint;
    }

    // Published before the handler runs and cleared after the outcome is written. Between the
    // claim landing and this line there is a window in which the sweep would see this lane
    // running something else; the CLAIM_TIME grace is what covers it.
    wm_manager_task_publish(worker, task_id, desc->request_timeout_ms);

    if (wm_manager_task_stopping(dispatcher)) {
        // Checked here rather than only at the top of the loop: the row stays claimed and the
        // next boot's startup sweep reclaims it, which is cheaper than starting work that a
        // thirty second shutdown budget will not let finish.
        wm_manager_task_publish(worker, NULL, 0);
        cJSON_Delete(task);
        os_free(agent_id);
        return true;
    }

    result = wm_manager_task_execute(worker, desc, agent_id, payload, error, sizeof(error));

    wm_manager_task_apply_result(desc, &dispatcher->policy, result, attempts, defer_count, (long long)time(NULL),
                                 &transition);

    if (transition.status && strcmp(transition.status, "dead_letter") == 0) {
        // Carrying the id is half of what makes a dead letter reachable: an operator who did not
        // catch this line has no id to look up and no way to list what failed.
        mterror(WM_TASK_MANAGER_LOGTAG, "Manager task '%s' of type '%s' dead-lettered after %d attempts: %s",
                task_id, desc->name, transition.attempts, error[0] ? error : "no detail");
    } else if (result == WM_MANAGER_TASK_NOT_READY || result == WM_MANAGER_TASK_BUSY) {
        if (transition.defer_count >= 20) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Manager task '%s' deferred %d times in a row: %s", task_id,
                    transition.defer_count, error[0] ? error : "no detail");
        } else if (transition.defer_count >= 3) {
            mtwarn(WM_TASK_MANAGER_LOGTAG, "Manager task '%s' deferred %d times in a row: %s", task_id,
                   transition.defer_count, error[0] ? error : "no detail");
        }
    }

    if (wm_manager_task_client_apply(&worker->client, desc, task_id, agent_id, &transition, error) != 0) {
        // The one case where ATTEMPTS and LAST_ERROR cannot record what happened, so it is said
        // out loud. The row stays claimed, the sweep reclaims it, and the handler runs again --
        // which every manager task handler is required to tolerate.
        mterror(WM_TASK_MANAGER_LOGTAG, "Cannot record the outcome of manager task '%s'; it will be re-run.",
                task_id);
    }

    wm_manager_task_publish(worker, NULL, 0);

    cJSON_Delete(task);
    os_free(agent_id);

    return true;
}

/**
 * @brief Block until this lane is signalled, a second passes, or shutdown is requested.
 *
 * The one second ceiling is what makes the shutdown flag observable: a lane parked on an
 * untimed wait would only notice a SIGTERM when the scheduler next woke it, which under an idle
 * queue is the poll interval away.
 */
STATIC void wm_manager_task_lane_wait(wm_manager_task_dispatcher *dispatcher, wm_manager_task_lane lane) {
    struct timespec deadline;

    w_mutex_lock(&dispatcher->lane_mutex[lane]);

    if (!dispatcher->lane_signalled[lane] && !wm_manager_task_stopping(dispatcher)) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += WM_MANAGER_TASK_LANE_IDLE_FALLBACK;

        pthread_cond_timedwait(&dispatcher->lane_cond[lane], &dispatcher->lane_mutex[lane], &deadline);
    }

    dispatcher->lane_signalled[lane] = false;

    w_mutex_unlock(&dispatcher->lane_mutex[lane]);
}

/**
 * @brief Mark a lane as having work to do and wake one of its workers.
 */
STATIC void wm_manager_task_lane_signal(wm_manager_task_dispatcher *dispatcher, wm_manager_task_lane lane) {
    w_mutex_lock(&dispatcher->lane_mutex[lane]);
    dispatcher->lane_signalled[lane] = true;
    pthread_cond_signal(&dispatcher->lane_cond[lane]);
    w_mutex_unlock(&dispatcher->lane_mutex[lane]);
}

/**
 * @brief Wake every worker of a lane, not just one of them.
 *
 * For shutdown only. One signal wakes one waiter, so on a lane of depth 4 the other three would
 * sleep out the idle fallback before noticing the flag, and stop() joins them.
 */
STATIC void wm_manager_task_lane_wake_all(wm_manager_task_dispatcher *dispatcher, wm_manager_task_lane lane) {
    w_mutex_lock(&dispatcher->lane_mutex[lane]);
    dispatcher->lane_signalled[lane] = true;
    pthread_cond_broadcast(&dispatcher->lane_cond[lane]);
    w_mutex_unlock(&dispatcher->lane_mutex[lane]);
}

/**
 * @brief Mark a direct action as due and wake the lane that performs it.
 */
STATIC void wm_manager_task_direct_signal(wm_manager_task_dispatcher *dispatcher, size_t index) {
    const wm_manager_task_direct_def *action = wm_manager_task_direct_at(index);

    if (!action || !dispatcher->direct_pending) {
        return;
    }

    w_mutex_lock(&dispatcher->lane_mutex[action->lane]);
    dispatcher->direct_pending[index] = true;
    dispatcher->lane_signalled[action->lane] = true;
    pthread_cond_signal(&dispatcher->lane_cond[action->lane]);
    w_mutex_unlock(&dispatcher->lane_mutex[action->lane]);
}

/**
 * @brief Perform any direct action this lane owes, before it looks for a task.
 *
 * BETWEEN TASKS, never mid-handler. The flag is read and cleared under the lane's mutex and the
 * action runs outside it, so a signal arriving during the action sets the flag again and the next
 * pass performs it -- rather than being lost, or extending this one.
 */
STATIC void wm_manager_task_direct_run(wm_manager_task_dispatcher *dispatcher, wm_manager_task_lane lane) {
    for (size_t i = 0; i < wm_manager_task_direct_count(); i++) {
        const wm_manager_task_direct_def *action = wm_manager_task_direct_at(i);
        bool pending = false;

        if (!action || action->lane != lane || !action->run) {
            continue;
        }

        w_mutex_lock(&dispatcher->lane_mutex[lane]);
        pending = dispatcher->direct_pending[i];
        dispatcher->direct_pending[i] = false;
        w_mutex_unlock(&dispatcher->lane_mutex[lane]);

        if (pending) {
            action->run();
        }
    }
}

/**
 * @brief A lane worker: wait to be woken, then take one task.
 */
STATIC void* wm_manager_task_lane_thread(void *arg) {
    wm_manager_task_worker *worker = (wm_manager_task_worker *)arg;
    wm_manager_task_dispatcher *dispatcher = worker->dispatcher;
    size_t lane_types = 0;

    wm_manager_task_registry_lane(worker->lane, &lane_types);

    while (!wm_manager_task_stopping(dispatcher)) {
        bool claimed = false;

        wm_manager_task_lane_wait(dispatcher, worker->lane);

        if (wm_manager_task_stopping(dispatcher)) {
            break;
        }

        /* Before the claim, so a lane that always has a task queued still performs it. After the
         * wait, so the action is never taken while a handler is running. With agent_delete_old
         * bounded at its own budget, the worst case latency here is one bounded local task -- which
         * is stated rather than implied, because "every 60 s" would otherwise read as a guarantee. */
        wm_manager_task_direct_run(dispatcher, worker->lane);

        if (wm_manager_task_stopping(dispatcher)) {
            break;
        }

        // One pass over this lane's types, taking the first that yields a row. The claim stays
        // scoped to a single type throughout: an IN clause over several would give up the
        // single-seek property the claim index exists for.
        for (size_t offset = 0; offset < lane_types && !wm_manager_task_stopping(dispatcher); offset++) {
            const wm_manager_task_descriptor *desc = wm_manager_task_rotate(worker->lane, &worker->rotation, offset);

            if (!desc) {
                break;
            }

            if (wm_manager_task_run_one(dispatcher, worker, desc)) {
                // Next pass starts at the type after this one, so a busy type cannot starve its
                // siblings on a lane that carries several.
                worker->rotation = (worker->rotation + offset + 1) % lane_types;
                claimed = true;
                break;
            }
        }

        // A lane that found work asks again at once rather than waiting to be woken, so a backlog
        // drains at lane speed instead of one row per poll interval.
        if (claimed) {
            wm_manager_task_lane_signal(dispatcher, worker->lane);
        }
    }

    wm_manager_task_client_close(&worker->client);

    return NULL;
}

/**
 * @brief Return every claimed row this process may reclaim to the pending state.
 *
 * @param[in] owner Restrict to one lane, or NULL for every claimed row.
 * @return Number of rows reclaimed, or -1 on error.
 */
STATIC int wm_manager_task_sweep(wm_manager_task_dispatcher *dispatcher, const char *owner) {
    char cursor[WM_MANAGER_TASK_ID_LEN] = "";
    char page_start[WM_MANAGER_TASK_ID_LEN] = "";
    int reclaimed = 0;
    bool more = true;

    while (more && !wm_manager_task_stopping(dispatcher)) {
        cJSON *rows = NULL;
        cJSON *row = NULL;
        int seen = 0;

        if (wm_manager_task_client_claimed(&dispatcher->scheduler_client, owner, *cursor ? cursor : NULL, &rows) != 0) {
            return -1;
        }

        cJSON_ArrayForEach(row, rows) {
            const cJSON *row_id = cJSON_GetObjectItem(row, "task_id");
            const cJSON *row_owner = cJSON_GetObjectItem(row, "owner");
            const cJSON *claim_time = cJSON_GetObjectItem(row, "claim_time");
            const cJSON *task_type = cJSON_GetObjectItem(row, "task_type");
            const cJSON *agent_id = cJSON_GetObjectItem(row, "agent_id");
            const cJSON *attempts = cJSON_GetObjectItem(row, "attempts");
            const cJSON *defer_count = cJSON_GetObjectItem(row, "defer_count");
            const wm_manager_task_descriptor *desc = NULL;
            wm_manager_task_transition_t transition = {0};
            char inflight[WM_MANAGER_TASK_ID_LEN] = "";

            seen++;

            if (!row_id || !cJSON_IsString(row_id) || !row_owner || !cJSON_IsString(row_owner)) {
                continue;
            }

            strncpy(cursor, row_id->valuestring, sizeof(cursor) - 1);
            cursor[sizeof(cursor) - 1] = '\0';

            wm_manager_task_worker_inflight(dispatcher, row_owner->valuestring, inflight, sizeof(inflight));

            if (!wm_manager_task_owner_reclaimable(row_owner->valuestring,
                                                   claim_time && cJSON_IsNumber(claim_time)
                                                       ? (long long)claim_time->valuedouble : 0,
                                                   (long long)time(NULL), dispatcher->claim_grace,
                                                   &dispatcher->self, *inflight ? inflight : NULL,
                                                   row_id->valuestring)) {
                continue;
            }

            desc = task_type && cJSON_IsString(task_type) ? wm_manager_task_registry_get(task_type->valuestring)
                                                          : NULL;

            if (!desc) {
                // An orphaned type: the row would never be claimed, never be expired by age, and
                // would count against the row ceiling forever. Retiring it is the reaper's job
                // and it runs after this sweep, so leave it be for now.
                continue;
            }

            // Reclaimed exactly as it was. The attempt is not charged to the row: a crashed lane
            // is not the task failing, and charging it would spend the budget on the process
            // rather than on the work.
            transition.status = NULL;
            transition.attempts = attempts && cJSON_IsNumber(attempts) ? attempts->valueint : 0;
            transition.defer_count = defer_count && cJSON_IsNumber(defer_count) ? defer_count->valueint : 0;
            transition.next_attempt_at = (long long)time(NULL);

            if (wm_manager_task_client_apply(&dispatcher->scheduler_client, desc, row_id->valuestring,
                                             agent_id && cJSON_IsString(agent_id) ? agent_id->valuestring : NULL,
                                             &transition, "reclaimed from a lane that is no longer running it") == 0) {
                reclaimed++;
                wm_manager_task_lane_signal(dispatcher, desc->lane);
            }
        }

        // Page until one comes back empty, rather than until one comes back short. That costs a
        // final round trip per sweep and saves both sides having to agree on a page size.
        // Paging on the task id rather than an offset is what makes this safe while lanes are
        // writing rows concurrently: an offset walk would skip or repeat as the set shifts.
        more = seen > 0;

        // A page whose rows all failed to parse would leave the cursor where it was and page
        // forever, so the cursor having moved is the real termination condition.
        more = more && strcmp(cursor, page_start) != 0;

        strncpy(page_start, cursor, sizeof(page_start) - 1);
        page_start[sizeof(page_start) - 1] = '\0';

        cJSON_Delete(rows);
    }

    return reclaimed;
}

/**
 * @brief Retire pending rows whose task type this build does not know.
 *
 * Runs after the ownership sweep, and the ordering is the whole rule: a claimed orphan only
 * becomes pending once the sweep has reclaimed it, so a reaper that ran first would miss it --
 * and would miss it again on every subsequent boot.
 */
STATIC void wm_manager_task_reap_orphans(wm_manager_task_dispatcher *dispatcher) {
    cJSON *response = NULL;
    cJSON *types = NULL;
    cJSON *type = NULL;

    if (wm_manager_task_client_call(&dispatcher->scheduler_client, "get_pending_manager_task_types", NULL,
                                    &response) != 0) {
        return;
    }

    types = cJSON_GetObjectItem(response, "types");

    cJSON_ArrayForEach(type, types) {
        cJSON *parameters = NULL;

        if (!cJSON_IsString(type) || wm_manager_task_registry_get(type->valuestring)) {
            continue;
        }

        mtwarn(WM_TASK_MANAGER_LOGTAG, "Retiring pending manager tasks of unknown type '%s'.", type->valuestring);

        parameters = cJSON_CreateObject();
        cJSON_AddStringToObject(parameters, "task_type", type->valuestring);
        cJSON_AddStringToObject(parameters, "last_error", "unknown task type");

        wm_manager_task_client_call(&dispatcher->scheduler_client, "fail_manager_tasks_by_type", parameters, NULL);
    }

    cJSON_Delete(response);
}

/**
 * @brief Find a loaded schedule by id.
 */
STATIC const wm_manager_task_schedule* wm_manager_task_schedule_find(const wm_manager_task_dispatcher *dispatcher,
                                                                     const char *schedule_id) {
    for (size_t i = 0; i < dispatcher->schedule_count; i++) {
        if (dispatcher->schedules[i].def && strcmp(dispatcher->schedules[i].def->schedule_id, schedule_id) == 0) {
            return &dispatcher->schedules[i];
        }
    }

    return NULL;
}

/**
 * @brief Write the built-in schedules into MANAGER_TASK_SCHEDULES, deciding each one's next run.
 *
 * Runs once, before the lanes start. Two writes rather than a read followed by a write, because the
 * upsert reports the row it replaced: the decision needs the PREVIOUS enabled flag, and that is the
 * only thing that makes a disabled-to-enabled transition observable across a restart.
 */
STATIC void wm_manager_task_schedules_upsert(wm_manager_task_dispatcher *dispatcher) {
    long long now = (long long)time(NULL);

    for (size_t i = 0; i < dispatcher->schedule_count; i++) {
        const wm_manager_task_schedule *schedule = &dispatcher->schedules[i];
        cJSON *previous = NULL;
        const cJSON *stored_next = NULL;
        const cJSON *stored_enabled = NULL;
        long long provisional = 0;
        long long decided = 0;

        if (!schedule->def) {
            continue;
        }

        provisional = wm_manager_task_schedule_next(schedule, 0, now);

        if (wm_manager_task_client_schedule_upsert(&dispatcher->scheduler_client, schedule->def->schedule_id,
                                                   provisional, schedule->enabled, &previous) != 0) {
            mtwarn(WM_TASK_MANAGER_LOGTAG, "Cannot register the '%s' schedule; it will not run until the next restart.",
                   schedule->def->schedule_id);
            continue;
        }

        stored_next = previous ? cJSON_GetObjectItem(previous, "next_run_at") : NULL;
        stored_enabled = previous ? cJSON_GetObjectItem(previous, "enabled") : NULL;

        decided = wm_manager_task_schedule_startup_next_run(
            schedule, previous != NULL,
            stored_next && cJSON_IsNumber(stored_next) ? (long long)stored_next->valuedouble : 0,
            stored_enabled && cJSON_IsNumber(stored_enabled) ? stored_enabled->valueint : 0, now);

        cJSON_Delete(previous);

        // Correct the provisional value only when the decision differs from it, which is the case
        // for every schedule that already had a row and kept its cadence.
        if (decided != provisional &&
            wm_manager_task_client_schedule_advance(&dispatcher->scheduler_client, schedule->def->schedule_id,
                                                    decided) != 0) {
            mtwarn(WM_TASK_MANAGER_LOGTAG, "Cannot restore the '%s' schedule's next run; it may run early once.",
                   schedule->def->schedule_id);
            continue;
        }

        mtdebug1(WM_TASK_MANAGER_LOGTAG, "Schedule '%s' is %s; next run at %lld.", schedule->def->schedule_id,
                 schedule->enabled ? "enabled" : "disabled", decided);
    }
}

/**
 * @brief Spawn an instance of every schedule whose slot has come due, and advance the slot.
 *
 * NO TRANSACTION ACROSS THE TWO WRITES, and none is needed: the instance's id is derived from the
 * schedule and its slot, so a crash between the insert and the advance leaves the slot still due,
 * and the retry re-derives the same id and collides on the primary key. The double spawn is a
 * no-op rather than a duplicate run.
 */
STATIC void wm_manager_task_spawn_due(wm_manager_task_dispatcher *dispatcher) {
    cJSON *due = NULL;
    cJSON *entry = NULL;
    long long now = (long long)time(NULL);
    /* This node's role, resolved at most once per pass and only if a due schedule needs it.
     * w_is_worker() re-parses ossec.conf from disk, and after downtime spanning a slot of each
     * schedule the loop would otherwise read the file once per schedule for one answer. */
    int worker_state = 0;
    bool worker_state_known = false;

    if (wm_manager_task_client_schedule_due(&dispatcher->scheduler_client, now, &due) != 0) {
        return;
    }

    cJSON_ArrayForEach(entry, due) {
        const cJSON *id = cJSON_GetObjectItem(entry, "schedule_id");
        const cJSON *slot_item = cJSON_GetObjectItem(entry, "next_run_at");
        const wm_manager_task_schedule *schedule = NULL;
        const wm_manager_task_descriptor *desc = NULL;
        long long slot = 0;
        long long advance = 0;
        bool node_allows = false;
        bool overlap_known = false;
        bool has_active = false;
        char *task_id = NULL;
        char *outcome = NULL;

        if (wm_manager_task_stopping(dispatcher)) {
            // Nothing spawned here would be claimed before the lanes are joined, and the slot stays
            // due for the next start.
            break;
        }

        if (!id || !cJSON_IsString(id) || !slot_item || !cJSON_IsNumber(slot_item)) {
            continue;
        }

        slot = (long long)slot_item->valuedouble;

        schedule = wm_manager_task_schedule_find(dispatcher, id->valuestring);
        desc = schedule && schedule->def ? wm_manager_task_registry_get(schedule->def->task_type) : NULL;

        if (desc) {
            /* Read at spawn time rather than at startup, because a node can be promoted or demoted
             * while the manager runs -- and only when a schedule is actually due, which keeps the
             * file read at schedule cadence instead of the five second poll's. */
            if (!worker_state_known) {
                worker_state = w_is_worker();
                worker_state_known = true;
            }

            node_allows = wm_manager_task_schedule_node_allows(schedule->def->scope, worker_state);

            if (node_allows) {
                overlap_known = wm_manager_task_client_schedule_active(&dispatcher->scheduler_client,
                                                                       id->valuestring, &has_active) == 0;
            }
        }

        switch (wm_manager_task_spawn_decide(desc != NULL, node_allows, overlap_known, has_active)) {
        case WM_MANAGER_TASK_SPAWN_HOLD:
            continue;

        case WM_MANAGER_TASK_SPAWN_SKIP:
            if (!desc) {
                // A schedule id this build does not know, or one whose task type was removed. It
                // cannot be run and it cannot be advanced by its own cadence, so it is pushed a day
                // out: visible in the log, and not re-read every five seconds until then.
                mtwarn(WM_TASK_MANAGER_LOGTAG, "Schedule '%s' is not known to this manager; ignoring its due run.",
                       id->valuestring);
                advance = now + WM_MANAGER_TASK_UNKNOWN_SCHEDULE_BACKOFF;
            } else {
                if (has_active) {
                    mtdebug1(WM_TASK_MANAGER_LOGTAG,
                             "Schedule '%s' still has an instance in flight; skipping the run due at %lld.",
                             id->valuestring, slot);
                }

                advance = wm_manager_task_schedule_next(schedule, slot, now);
            }
            break;

        case WM_MANAGER_TASK_SPAWN:
        default:
            task_id = manager_task_id_schedule(id->valuestring, slot);

            if (!task_id) {
                continue;
            }

            if (wm_manager_task_client_spawn(&dispatcher->scheduler_client, desc, task_id, id->valuestring, slot,
                                             &outcome) != 0) {
                // Not advanced. The slot stays due and the next poll tries again, which is the
                // whole reason the id is derived rather than random.
                os_free(task_id);
                continue;
            }

            mtdebug1(WM_TASK_MANAGER_LOGTAG, "Schedule '%s' spawned '%s' for the run due at %lld (%s).",
                     id->valuestring, task_id, slot, outcome ? outcome : "created");

            os_free(task_id);
            os_free(outcome);

            // Straight to the lane, so a scheduled run does not wait out a poll interval it has
            // already earned.
            wm_manager_task_lane_signal(dispatcher, desc->lane);

            advance = wm_manager_task_schedule_next(schedule, slot, now);
            break;
        }

        if (advance <= slot) {
            // A next slot that did not move would leave the schedule permanently due and spin the
            // spawn loop. Only reachable through a misconfigured interval, but the consequence is
            // bad enough to guard rather than reason about.
            advance = now + WM_MANAGER_TASK_UNKNOWN_SCHEDULE_BACKOFF;
        }

        wm_manager_task_client_schedule_advance(&dispatcher->scheduler_client, id->valuestring, advance);
    }

    cJSON_Delete(due);
}

/**
 * @brief The scheduler: find work, wake the lanes that can do it, and sweep.
 */
STATIC void* wm_manager_task_scheduler_thread(void *arg) {
    wm_manager_task_dispatcher *dispatcher = (wm_manager_task_dispatcher *)arg;
    time_t next_poll = 0;
    time_t next_sweep = time(NULL) + dispatcher->sweep_interval;
    time_t *next_direct = NULL;

    // Each direct action keeps its own next-due stamp, so adding one with a different cadence needs
    // nothing here. Seeded to fire on the first pass: a manager that has been down may well have a
    // log that grew past its threshold while nothing was watching.
    if (wm_manager_task_direct_count() > 0) {
        os_calloc(wm_manager_task_direct_count(), sizeof(time_t), next_direct);
    }

    while (!wm_manager_task_stopping(dispatcher)) {
        time_t now = time(NULL);

        for (size_t i = 0; next_direct && i < wm_manager_task_direct_count(); i++) {
            const wm_manager_task_direct_def *action = wm_manager_task_direct_at(i);

            if (action && now >= next_direct[i]) {
                wm_manager_task_direct_signal(dispatcher, i);
                next_direct[i] = now + (action->interval > 0 ? action->interval : 1);
            }
        }

        if (now >= next_poll) {
            cJSON *types = NULL;

            /* On the poll's own tick, not the loop's: the spawn loop doubles as the poller because
             * both are timer work on one thread, and running it every second instead would put a
             * wazuh-db query per second on an idle manager to watch three rows that move at most
             * once every fifteen minutes.
             *
             * Before the poll, so a row it creates is discovered by the same pass rather than five
             * seconds later -- though the spawn signals the lane directly too, so the poll is only
             * the fallback. */
            wm_manager_task_spawn_due(dispatcher);

            // One grouped command per interval, not one claim per lane on a timer.
            if (wm_manager_task_client_poll(&dispatcher->scheduler_client, &types) == 0) {
                cJSON *entry = NULL;

                cJSON_ArrayForEach(entry, types) {
                    const cJSON *name = cJSON_GetObjectItem(entry, "task_type");
                    const cJSON *due = cJSON_GetObjectItem(entry, "next_attempt_at");
                    const wm_manager_task_descriptor *desc = NULL;

                    if (!name || !cJSON_IsString(name)) {
                        continue;
                    }

                    if (desc = wm_manager_task_registry_get(name->valuestring), !desc) {
                        continue;
                    }

                    // Only wake a lane for work that is actually due. A row backing off is
                    // pending but not eligible, and waking its lane for it would spin the claim.
                    if (due && cJSON_IsNumber(due) && (long long)due->valuedouble > (long long)now) {
                        continue;
                    }

                    wm_manager_task_lane_signal(dispatcher, desc->lane);
                }

                cJSON_Delete(types);
            }

            next_poll = now + dispatcher->poll_interval;
        }

        if (now >= next_sweep) {
            // Only this process's own lanes on the periodic pass. Every claimed row, whoever owns
            // it, is the startup form, which has already run by now.
            for (size_t i = 0; i < dispatcher->worker_count; i++) {
                wm_manager_task_sweep(dispatcher, dispatcher->workers[i].owner);
            }

            next_sweep = now + dispatcher->sweep_interval;
        }

        wm_sleep_interruptible(1);
    }

    os_free(next_direct);

    wm_manager_task_client_close(&dispatcher->scheduler_client);

    return NULL;
}

int wm_manager_task_dispatcher_start(wm_manager_task_dispatcher *dispatcher, const char *consumer_socket) {
    size_t worker_index = 0;

    if (!dispatcher) {
        return -1;
    }

    memset(dispatcher, 0, sizeof(*dispatcher));

    /* STRICTLY BEFORE THE REGISTRY. The registry derives each local type's watchdog budget from the
     * bounds resolved here, so a registry built first would stamp every local descriptor with the
     * budget of a zeroed configuration.
     *
     * It is also where the local handlers pick up their disconnection window -- from the schedule
     * that fires them, rather than reading the option a second time, so the two cannot disagree. */
    wm_manager_task_local_init();

    /* Both unwind through fail: as well, even though no thread or allocation exists yet -- it is
     * what runs wm_manager_task_local_teardown() for the init above, and it keeps every exit from
     * this function on one path. */
    if (wm_manager_task_registry_init(consumer_socket) != 0) {
        goto fail;
    }

    if (wm_manager_task_owner_self(&dispatcher->self) != 0) {
        goto fail;
    }

    wm_manager_task_policy_load(&dispatcher->policy);

    if (wm_manager_task_schedules_count() > 0) {
        os_calloc(wm_manager_task_schedules_count(), sizeof(wm_manager_task_schedule), dispatcher->schedules);
        dispatcher->schedule_count = wm_manager_task_schedules_load(dispatcher->schedules);
    }

    if (wm_manager_task_direct_count() > 0) {
        os_calloc(wm_manager_task_direct_count(), sizeof(bool), dispatcher->direct_pending);
    }

    dispatcher->poll_interval = getDefine_Int_default("wazuh_modules", "manager_task_poll_interval", 1, 3600,
                                                      WM_MANAGER_TASK_DEFAULT_POLL_INTERVAL);
    dispatcher->sweep_interval = getDefine_Int_default("wazuh_modules", "manager_task_sweep_interval", 1, 3600,
                                                       WM_MANAGER_TASK_DEFAULT_SWEEP_INTERVAL);
    dispatcher->claim_grace = getDefine_Int_default("wazuh_modules", "manager_task_claim_grace", 1, 3600,
                                                    WM_MANAGER_TASK_DEFAULT_CLAIM_GRACE);

    for (wm_manager_task_lane lane = 0; lane < WM_MANAGER_TASK_LANE_COUNT; lane++) {
        size_t lane_types = 0;

        w_mutex_init(&dispatcher->lane_mutex[lane], NULL);
        w_cond_init(&dispatcher->lane_cond[lane], NULL);

        // A lane with no registered types gets no threads. Task types arrive over several
        // releases, and a lane whose types have not landed yet would otherwise hold a worker
        // alive to wait on a queue that can never have anything in it.
        wm_manager_task_registry_lane(lane, &lane_types);

        if (lane_types > 0) {
            dispatcher->worker_count += wm_manager_task_lane_depth(lane);
        }
    }

    // From here on stop() has objects to destroy, whether or not any thread ever starts.
    dispatcher->primed = true;

    os_calloc(dispatcher->worker_count, sizeof(wm_manager_task_worker), dispatcher->workers);

    for (wm_manager_task_lane lane = 0; lane < WM_MANAGER_TASK_LANE_COUNT; lane++) {
        size_t registered = 0;

        wm_manager_task_registry_lane(lane, &registered);

        for (int index = 0; registered > 0 && index < wm_manager_task_lane_depth(lane); index++) {
            wm_manager_task_worker *worker = &dispatcher->workers[worker_index++];
            uhttp_options_t options = {.url = "http://localhost/", .content_type = "application/json"};

            worker->dispatcher = dispatcher;
            worker->lane = lane;
            worker->index = index;
            w_mutex_init(&worker->published_mutex, NULL);
            wm_manager_task_client_init(&worker->client);

            if (wm_manager_task_owner_format(worker->owner, sizeof(worker->owner), &dispatcher->self, lane, index) !=
                0) {
                mterror(WM_TASK_MANAGER_LOGTAG, "Cannot build the owner string for lane '%s'.",
                        wm_manager_task_lane_name(lane));
                goto fail;
            }

            // One client per thread: a uhttp_client_t is not thread-safe. The local lane needs
            // none at all, because none of its types is routed.
            size_t lane_type_count = 0;
            const wm_manager_task_descriptor **lane_types = wm_manager_task_registry_lane(lane, &lane_type_count);

            if (lane_type_count > 0 && lane_types[0]->path) {
                // uhttp carries its deadlines on the client rather than on the request, so a lane
                // whose types wanted different ones could not honour both. Routed lanes therefore
                // carry exactly one type, and that is checked rather than assumed: a second one
                // added later would otherwise silently inherit the first one's timeouts.
                if (lane_type_count != 1) {
                    mterror(WM_TASK_MANAGER_LOGTAG,
                            "Lane '%s' carries %zu routed task types; a routed lane must carry exactly one.",
                            wm_manager_task_lane_name(lane), lane_type_count);
                    goto fail;
                }

                options.timeout_ms = lane_types[0]->request_timeout_ms;
                options.connect_timeout_ms = lane_types[0]->connect_timeout_ms;
                options.unix_socket_path = lane_types[0]->socket_path;

                worker->http = uhttp_client_new(&options);

                if (!worker->http) {
                    mterror(WM_TASK_MANAGER_LOGTAG, "Cannot create the HTTP client for lane '%s'.",
                            wm_manager_task_lane_name(lane));
                    goto fail;
                }
            }
        }
    }

    wm_manager_task_client_init(&dispatcher->scheduler_client);

    // Once, before any lane starts, and over every claimed row rather than only this process's:
    // the rows worth reclaiming here are the ones the previous process left behind.
    if (wm_manager_task_sweep(dispatcher, NULL) < 0) {
        mtwarn(WM_TASK_MANAGER_LOGTAG, "The startup ownership sweep did not complete.");
    }

    // Strictly after the sweep. A claimed orphan only becomes pending once the sweep has
    // reclaimed it, so a reaper that ran first would miss it on this boot and every one after.
    wm_manager_task_reap_orphans(dispatcher);

    /* And strictly after the reaper, for the same reason in reverse: a schedule that upserted
     * before the reaper ran could spawn an instance of a type the reaper is about to retire rows
     * of, and the fresh row would be caught in the same pass it was created for. */
    wm_manager_task_schedules_upsert(dispatcher);

    for (size_t i = 0; i < dispatcher->worker_count; i++) {
        /* Joinable, deliberately. w_create_thread wraps CreateThread, which calls pthread_detach
         * unconditionally, and a detached thread cannot be joined at shutdown.
         *
         * CreateThreadJoinable rather than a bare pthread_create: it is what applies the
         * `wazuh.thread_stack_size` internal option, so these threads are sized like every other
         * daemon thread instead of silently taking the platform default. */
        if (CreateThreadJoinable(&dispatcher->workers[i].thread, wm_manager_task_lane_thread,
                                 &dispatcher->workers[i]) != 0) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Cannot start lane thread '%s'.", dispatcher->workers[i].owner);
            goto fail;
        }

        dispatcher->workers[i].started = true;
    }

    if (CreateThreadJoinable(&dispatcher->scheduler, wm_manager_task_scheduler_thread, dispatcher) != 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Cannot start the manager task scheduler.");
        goto fail;
    }

    dispatcher->scheduler_started = true;

    return 0;

fail:
    /* Every failure exit lands here, including the ones that already have live threads: this call
     * adds seven of them to modulesd, so a pthread_create that fails under RLIMIT_NPROC or memory
     * pressure is reachable, not theoretical. Returning -1 with workers still running left them
     * claiming and executing tasks while the caller logged that manager tasks would not run, and
     * nobody would ever join them -- stop() is only called when start() succeeded.
     *
     * stop() is the whole unwind: it signals, wakes, joins whatever has `started`, frees the HTTP
     * clients and the arrays, and destroys what was initialised. It is safe on a partial start
     * because every step is guarded by the flag that records whether that step happened. */
    wm_manager_task_dispatcher_stop(dispatcher);

    return -1;
}

void wm_manager_task_dispatcher_stop(wm_manager_task_dispatcher *dispatcher) {
    if (!dispatcher) {
        return;
    }

    /* Set here rather than relied upon from the module's stop callback. On shutdown the module flag
     * is already set and this is redundant; on a failed start it is the only thing that makes the
     * workers exit, and without it the joins below would wait forever on threads that go straight
     * back to claiming after being woken. */
    dispatcher->stopping = true;

    // Waking every lane is what stops its workers sleeping out the idle fallback before noticing
    // the flag. Broadcast, not signal: the joins that follow wait for all of them, not for one per
    // lane. Only when the mutexes exist -- a start() that failed before priming them has no
    // threads either.
    if (dispatcher->primed) {
        for (wm_manager_task_lane lane = 0; lane < WM_MANAGER_TASK_LANE_COUNT; lane++) {
            wm_manager_task_lane_wake_all(dispatcher, lane);
        }
    }

    if (dispatcher->scheduler_started) {
        pthread_join(dispatcher->scheduler, NULL);
        dispatcher->scheduler_started = false;
    }

    for (size_t i = 0; i < dispatcher->worker_count; i++) {
        if (dispatcher->workers[i].started) {
            pthread_join(dispatcher->workers[i].thread, NULL);
            dispatcher->workers[i].started = false;
        }

        if (dispatcher->workers[i].http) {
            uhttp_client_free(dispatcher->workers[i].http);
            dispatcher->workers[i].http = NULL;
        }

        // Initialised per worker in start(), so destroyed per worker here: after the join, when
        // nothing can be publishing through it.
        w_mutex_destroy(&dispatcher->workers[i].published_mutex);
    }

    // After the joins, so nothing is holding the socket the local handlers share.
    wm_manager_task_local_teardown();

    // Rows still claimed here stay claimed. The next boot's startup sweep reclaims them, which is
    // why that pass covers every owner rather than only this process's.
    os_free(dispatcher->workers);
    dispatcher->worker_count = 0;

    os_free(dispatcher->schedules);
    dispatcher->schedule_count = 0;

    os_free(dispatcher->direct_pending);

    /* Last, and only once: after this, wake_all() would be operating on destroyed objects. Making
     * stop() the inverse of start() matters less for the process lifetime -- the module starts once
     * -- than for the failed-start path, which now runs stop() while modulesd keeps running. */
    if (dispatcher->primed) {
        for (wm_manager_task_lane lane = 0; lane < WM_MANAGER_TASK_LANE_COUNT; lane++) {
            w_mutex_destroy(&dispatcher->lane_mutex[lane]);
            w_cond_destroy(&dispatcher->lane_cond[lane]);
        }

        dispatcher->primed = false;
    }
}

void wm_manager_task_dispatcher_watchdog(wm_manager_task_dispatcher *dispatcher, time_t now) {
    if (!dispatcher) {
        return;
    }

    for (size_t i = 0; i < dispatcher->worker_count; i++) {
        wm_manager_task_worker *worker = &dispatcher->workers[i];
        char task_id[WM_MANAGER_TASK_ID_LEN] = "";
        bool stalled = false;

        w_mutex_lock(&worker->published_mutex);

        stalled = wm_manager_task_worker_stalled(worker->inflight, worker->last_progress_at,
                                                 worker->request_timeout_ms, now);

        if (stalled) {
            strncpy(task_id, worker->inflight_task_id, sizeof(task_id) - 1);
        }

        w_mutex_unlock(&worker->published_mutex);

        if (stalled) {
            mtwarn(WM_TASK_MANAGER_LOGTAG, "Lane '%s' has been executing manager task '%s' past its deadline.",
                   worker->owner, task_id);
        }
    }
}
