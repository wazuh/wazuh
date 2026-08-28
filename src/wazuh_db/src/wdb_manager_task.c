/*
 * Wazuh DB layer for manager-side tasks.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * MANAGER_TASKS holds work the manager owes itself, tracked to an outcome rather than to a
 * hand-off. Three properties of this file are load-bearing and easy to undo by accident:
 *
 *   - TASK_TYPE is opaque. Nothing here knows which types exist, so adding one is a change to
 *     the Task Manager's handler registry alone.
 *
 *   - Each operation is one wazuh-db command, and the per-database mutex is held for exactly one
 *     command. That is what makes the read-then-write pairs below atomic against every other
 *     tasks.db caller without a RETURNING clause, which the precompiled SQLite branch of the
 *     build cannot be assumed to provide.
 *
 *   - Only wdb_manager_task_create() and wdb_manager_task_claim() commit. Everything else leaves
 *     its write in the deferred transaction for wazuh-db's background loop, because a rollback
 *     of those writes is recovered by the ownership sweep re-running an idempotent handler,
 *     while a rolled-back claim would let a second lane run work that is already in flight.
 */

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

#include "wdb.h"

/// Largest payload accepted, measured after JSON escaping.
#define WDB_MANAGER_TASK_MAX_PAYLOAD 16384

const char* wdb_manager_task_result_name(int result) {
    switch (result) {
    case WDB_MANAGER_TASK_CREATED:
        return "created";
    case WDB_MANAGER_TASK_COALESCED:
        return "coalesced";
    case WDB_MANAGER_TASK_COLLIDED:
        return "collided";
    case WDB_MANAGER_TASK_QUEUE_FULL:
        return "queue_full";
    case WDB_MANAGER_TASK_REQUEUED:
        return "requeued";
    case WDB_MANAGER_TASK_SUPERSEDED:
        return "superseded";
    default:
        return "unknown";
    }
}

bool wdb_manager_task_payload_fits(const char *payload) {
    size_t escaped = 0;

    if (!payload) {
        return false;
    }

    // Counted rather than measured on a serialised copy, so the check costs no allocation on the
    // creation path. The bound is on the escaped form because that is what the claim response
    // carries back, and escaping can approach twice the raw length.
    for (const char *c = payload; *c; c++) {
        switch (*c) {
        case '"':
        case '\\':
        case '\b':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
            escaped += 2;
            break;
        default:
            escaped += ((unsigned char)*c < 0x20) ? 6 : 1;
            break;
        }

        if (escaped > WDB_MANAGER_TASK_MAX_PAYLOAD) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Bind a text value, or SQL NULL when the value is absent.
 */
STATIC void wdb_manager_task_bind_text(sqlite3_stmt *stmt, int index, const char *value) {
    if (value) {
        sqlite3_bind_text(stmt, index, value, -1, NULL);
    } else {
        sqlite3_bind_null(stmt, index);
    }
}

/**
 * @brief Bind an integer value, or SQL NULL when the value is unset (zero).
 */
STATIC void wdb_manager_task_bind_optional_int(sqlite3_stmt *stmt, int index, long long value) {
    if (value > 0) {
        sqlite3_bind_int64(stmt, index, value);
    } else {
        sqlite3_bind_null(stmt, index);
    }
}

/**
 * @brief Open the deferred transaction and fetch a cached statement.
 *
 * The statement is returned through an out parameter rather than as the return value: whether it
 * is NULL is not a failure signal, only whether the transaction opened and the cache was primed.
 *
 * @param[out] stmt Set to the cached statement on success.
 * @return OS_SUCCESS on success, OS_INVALID on failure.
 */
STATIC int wdb_manager_task_prepare(wdb_t *wdb, wdb_stmt index, sqlite3_stmt **stmt) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, index) < 0) {
        mdebug1(DB_CACHE_ERROR);
        return OS_INVALID;
    }

    *stmt = wdb->stmt[index];

    return OS_SUCCESS;
}

/**
 * @brief Read the single TEXT column of a statement expected to yield at most one row.
 *
 * @param[out] value Set to a newly allocated copy of the column when a row is found.
 * @return 1 when a row was found, 0 when none was, OS_INVALID on error.
 */
STATIC int wdb_manager_task_step_single_text(wdb_t *wdb, sqlite3_stmt *stmt, char **value) {
    int result = wdb_step(stmt);
    int retval = OS_INVALID;

    switch (result) {
    case SQLITE_ROW:
        if (value) {
            const char *column = (const char *)sqlite3_column_text(stmt, 0);
            os_strdup(column ? column : "", *value);
        }
        retval = 1;
        break;

    case SQLITE_DONE:
        retval = 0;
        break;

    default:
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        break;
    }

    // Release the read cursor before the caller writes to the same table in this transaction.
    sqlite3_reset(stmt);

    return retval;
}

int wdb_manager_task_create(wdb_t *wdb, const wdb_manager_task_create_t *task, char **surviving_task_id) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !task || !task->task_id || !task->task_type || !task->payload) {
        return OS_INVALID;
    }

    if (surviving_task_id) {
        *surviving_task_id = NULL;
    }

    // (a) Coalescing is a per-type policy, not a property of the table. Deduplicating every
    // (AGENT_ID, TASK_TYPE) pair would collapse two genuinely distinct deletions of one agent
    // into one, which is why this is a flag the caller sets rather than a unique index.
    if (task->coalesce && task->agent_id) {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_FIND_PENDING_BY_AGENT, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        sqlite3_bind_text(stmt, 1, task->agent_id, -1, NULL);
        sqlite3_bind_text(stmt, 2, task->task_type, -1, NULL);

        // The surviving row's id must be returned, or the caller holds an id with no row behind
        // it and any later lookup on it comes back empty.
        result = wdb_manager_task_step_single_text(wdb, stmt, surviving_task_id);

        if (result == OS_INVALID) {
            return OS_INVALID;
        } else if (result == 1) {
            return WDB_MANAGER_TASK_COALESCED;
        }
    }

    // (b) The admission bound. It is exact rather than advisory because it shares this command
    // with the insert below, so no other creator can slip a row in between the two.
    if (task->max_pending > 0) {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_COUNT_PENDING_BY_TYPE, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        sqlite3_bind_text(stmt, 1, task->task_type, -1, NULL);

        if (wdb_step(stmt) != SQLITE_ROW) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
            sqlite3_reset(stmt);
            return OS_INVALID;
        }

        int pending = sqlite3_column_int(stmt, 0);

        sqlite3_reset(stmt);

        if (pending >= task->max_pending) {
            return WDB_MANAGER_TASK_QUEUE_FULL;
        }
    }

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_INSERT, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, task->task_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, task->task_type, -1, NULL);
    sqlite3_bind_text(stmt, 3, task->payload, -1, NULL);
    sqlite3_bind_int64(stmt, 4, task->create_time);
    wdb_manager_task_bind_text(stmt, 5, task->agent_id);

    // NEXT_ATTEMPT_AT is seeded by the caller and never left to default to zero: ordering the
    // claim by this column would otherwise put every never-attempted row ahead of every retried
    // one, whose value is a real past timestamp, starving retries under sustained admission.
    sqlite3_bind_int64(stmt, 6, task->next_attempt_at > 0 ? task->next_attempt_at : task->create_time);

    wdb_manager_task_bind_text(stmt, 7, task->schedule_id);
    wdb_manager_task_bind_optional_int(stmt, 8, task->scheduled_run_at);

    result = wdb_step(stmt);

    if (result == SQLITE_CONSTRAINT) {
        // A primary key collision. For deterministic-id types this is the expected idempotent
        // path: two creators recorded the same logical event. For random-id types it means the
        // generator is broken, which is why the distinction is left to the caller to log.
        if (surviving_task_id) {
            os_strdup(task->task_id, *surviving_task_id);
        }
        return WDB_MANAGER_TASK_COLLIDED;
    }

    if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Creation commits inside this command, so the "ok" the caller receives is a durability
    // acknowledgement. authd depends on that: it drops its intent journal lines on this reply,
    // and a merely buffered write would move the orphan window one process to the right.
    if (wdb_commit2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        return OS_INVALID;
    }

    if (surviving_task_id) {
        os_strdup(task->task_id, *surviving_task_id);
    }

    return WDB_MANAGER_TASK_CREATED;
}

int wdb_manager_task_claim(wdb_t *wdb, const char *task_type, const char *owner, long long now, cJSON **task) {
    sqlite3_stmt *stmt = NULL;
    char *task_id = NULL;
    int result = 0;

    if (!wdb || !task_type || !owner || !task) {
        return OS_INVALID;
    }

    *task = NULL;

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SELECT_CLAIMABLE, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, task_type, -1, NULL);
    sqlite3_bind_int64(stmt, 2, now);

    result = wdb_step(stmt);

    // An empty queue is the common answer here, and this runs on every lane at every poll, so
    // the cursor is released on that path too rather than left for the next cache hit.
    if (result != SQLITE_ROW) {
        if (result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        }

        sqlite3_reset(stmt);

        return result == SQLITE_DONE ? OS_SUCCESS : OS_INVALID;
    }

    *task = cJSON_CreateObject();

    const char *column = (const char *)sqlite3_column_text(stmt, 0);
    os_strdup(column ? column : "", task_id);
    cJSON_AddStringToObject(*task, "task_id", task_id);

    column = (const char *)sqlite3_column_text(stmt, 1);
    cJSON_AddStringToObject(*task, "task_type", column ? column : "");

    if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
        column = (const char *)sqlite3_column_text(stmt, 2);
        cJSON_AddStringToObject(*task, "agent_id", column ? column : "");
    }

    column = (const char *)sqlite3_column_text(stmt, 3);
    cJSON_AddStringToObject(*task, "payload", column ? column : "");

    cJSON_AddNumberToObject(*task, "attempts", sqlite3_column_int(stmt, 4));
    cJSON_AddNumberToObject(*task, "defer_count", sqlite3_column_int(stmt, 5));

    // Release the read cursor before updating the row it is sitting on.
    sqlite3_reset(stmt);

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_CLAIM, &stmt) != OS_SUCCESS) {
        goto error;
    }

    sqlite3_bind_text(stmt, 1, owner, -1, NULL);
    sqlite3_bind_int64(stmt, 2, now);
    sqlite3_bind_text(stmt, 3, task_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        goto error;
    }

    // The claim must be durable before the handler runs. Winning the UPDATE is not enough: if
    // wazuh-db dies while the write is still in the deferred transaction, the row reverts to
    // pending while this lane is still executing it, and another lane can claim it. No liveness
    // check can see that, because the owning process is alive.
    if (wdb_commit2(wdb) < 0) {
        mdebug1(DB_TRANSACTION_ERROR);
        goto error;
    }

    os_free(task_id);
    return OS_SUCCESS;

error:
    os_free(task_id);
    cJSON_Delete(*task);
    *task = NULL;
    return OS_INVALID;
}

int wdb_manager_task_requeue(wdb_t *wdb, const wdb_manager_task_requeue_t *requeue) {
    sqlite3_stmt *stmt = NULL;
    char *survivor_id = NULL;
    int survivor_attempts = 0;
    int survivor_defer_count = 0;
    bool superseded = false;
    int result = 0;

    if (!wdb || !requeue || !requeue->task_id) {
        return OS_INVALID;
    }

    // Only coalescing types can have a competing row: for every other type the id is the only
    // thing that identifies the work, so nothing can have taken this row's slot.
    if (requeue->coalesce && requeue->agent_id && requeue->task_type) {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_FIND_COMPETING_PENDING, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        sqlite3_bind_text(stmt, 1, requeue->agent_id, -1, NULL);
        sqlite3_bind_text(stmt, 2, requeue->task_type, -1, NULL);
        sqlite3_bind_text(stmt, 3, requeue->task_id, -1, NULL);

        result = wdb_step(stmt);

        if (result == SQLITE_ROW) {
            const char *column = (const char *)sqlite3_column_text(stmt, 0);
            os_strdup(column ? column : "", survivor_id);
            survivor_attempts = sqlite3_column_int(stmt, 1);
            survivor_defer_count = sqlite3_column_int(stmt, 2);
            superseded = true;
        } else if (result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
            sqlite3_reset(stmt);
            return OS_INVALID;
        }

        sqlite3_reset(stmt);
    }

    if (superseded) {
        // No "which row is newer" rule is needed. This row was claimed before the competing one
        // could exist, because creation skips the insert whenever a pending row is already
        // there, so the row still pending is always the survivor.
        //
        // It inherits the higher of the two counters. Without that, a coalescing type can never
        // reach dead_letter under load: against a broken consumer with requests still arriving,
        // every timed-out row is superseded by a fresh row starting at zero, no row ever
        // accumulates a budget, and the failure stays invisible.
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_INHERIT_COUNTERS, &stmt) != OS_SUCCESS) {
            os_free(survivor_id);
            return OS_INVALID;
        }

        sqlite3_bind_int(stmt, 1, requeue->attempts > survivor_attempts ? requeue->attempts : survivor_attempts);
        sqlite3_bind_int(stmt, 2, requeue->defer_count > survivor_defer_count ? requeue->defer_count : survivor_defer_count);
        sqlite3_bind_text(stmt, 3, survivor_id, -1, NULL);

        if (wdb_step(stmt) != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
            os_free(survivor_id);
            return OS_INVALID;
        }

        os_free(survivor_id);

        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SUPERSEDE, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        wdb_manager_task_bind_text(stmt, 1, requeue->last_error);
        sqlite3_bind_text(stmt, 2, requeue->task_id, -1, NULL);
    } else {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_REQUEUE, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        sqlite3_bind_int64(stmt, 1, requeue->next_attempt_at);
        sqlite3_bind_int(stmt, 2, requeue->attempts);
        sqlite3_bind_int(stmt, 3, requeue->defer_count);
        wdb_manager_task_bind_text(stmt, 4, requeue->last_error);
        sqlite3_bind_text(stmt, 5, requeue->task_id, -1, NULL);
    }

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return superseded ? WDB_MANAGER_TASK_SUPERSEDED : WDB_MANAGER_TASK_REQUEUED;
}

int wdb_manager_task_set_result(wdb_t *wdb,
                                const char *task_id,
                                const char *status,
                                const char *last_error,
                                int attempts,
                                int defer_count) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb || !task_id || !status) {
        return OS_INVALID;
    }

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SET_RESULT, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, status, -1, NULL);
    wdb_manager_task_bind_text(stmt, 2, last_error);
    sqlite3_bind_int(stmt, 3, attempts);
    sqlite3_bind_int(stmt, 4, defer_count);
    sqlite3_bind_text(stmt, 5, task_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Deliberately no commit. If wazuh-db dies before this lands, the row stays claimed, the
    // ownership sweep reclaims it and the handler runs again -- which every manager task handler
    // is required to tolerate anyway, since no two-process write can be made atomic. Committing
    // here would double the fsync budget to buy nothing idempotency is not already paying for.
    return OS_SUCCESS;
}

int wdb_manager_task_get(wdb_t *wdb, const char *task_id, cJSON **task) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !task_id || !task) {
        return OS_INVALID;
    }

    *task = NULL;

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_GET, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, task_id, -1, NULL);

    result = wdb_step(stmt);

    if (result != SQLITE_ROW) {
        if (result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        }

        sqlite3_reset(stmt);

        return result == SQLITE_DONE ? OS_SUCCESS : OS_INVALID;
    }

    *task = wdb_manager_task_row_to_json(stmt);

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

cJSON* wdb_manager_task_row_to_json(sqlite3_stmt *stmt) {
    // Column order matches WDB_STMT_MANAGER_TASK_GET. Every reader of a MANAGER_TASKS row goes
    // through here so that adding a column is a change in two places, the statement and this
    // function, rather than in every caller.
    static const char *TEXT_COLUMNS[] = {
        [0] = "task_id",
        [1] = "task_type",
        [2] = "agent_id",
        [3] = "payload",
        [5] = "status",
        [6] = "owner",
        [10] = "last_error",
        [12] = "schedule_id",
    };
    static const char *NUMBER_COLUMNS[] = {
        [4] = "create_time",
        [7] = "claim_time",
        [8] = "attempts",
        [9] = "defer_count",
        [11] = "next_attempt_at",
        [13] = "scheduled_run_at",
        [14] = "end_time",
    };
    const int COLUMN_COUNT = 15;
    cJSON *task = cJSON_CreateObject();

    for (int column = 0; column < COLUMN_COUNT; column++) {
        // A NULL column is omitted rather than emitted as JSON null, so a consumer can test for
        // presence without distinguishing the two.
        if (sqlite3_column_type(stmt, column) == SQLITE_NULL) {
            continue;
        }

        if (column < (int)(sizeof(TEXT_COLUMNS) / sizeof(*TEXT_COLUMNS)) && TEXT_COLUMNS[column]) {
            const char *value = (const char *)sqlite3_column_text(stmt, column);
            cJSON_AddStringToObject(task, TEXT_COLUMNS[column], value ? value : "");
        } else if (column < (int)(sizeof(NUMBER_COLUMNS) / sizeof(*NUMBER_COLUMNS)) && NUMBER_COLUMNS[column]) {
            cJSON_AddNumberToObject(task, NUMBER_COLUMNS[column], sqlite3_column_int64(stmt, column));
        }
    }

    return task;
}

int wdb_manager_task_get_by_agent(wdb_t *wdb, const char *agent_id, const char *task_type, cJSON **task) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !agent_id || !task_type || !task) {
        return OS_INVALID;
    }

    *task = NULL;

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_GET_BY_AGENT, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, agent_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, task_type, -1, NULL);

    result = wdb_step(stmt);

    if (result != SQLITE_ROW) {
        if (result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        }

        sqlite3_reset(stmt);

        return result == SQLITE_DONE ? OS_SUCCESS : OS_INVALID;
    }

    // Newest first: an agent id can carry several rows over its lifetime, and the caller asking
    // "is a task outstanding for this agent" means the current one.
    *task = wdb_manager_task_row_to_json(stmt);

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_poll(wdb_t *wdb, cJSON **types) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !types) {
        return OS_INVALID;
    }

    *types = cJSON_CreateArray();

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_POLL_DUE, &stmt) != OS_SUCCESS) {
        cJSON_Delete(*types);
        *types = NULL;
        return OS_INVALID;
    }

    while (result = wdb_step(stmt), result == SQLITE_ROW) {
        const char *task_type = (const char *)sqlite3_column_text(stmt, 0);
        cJSON *entry = cJSON_CreateObject();

        cJSON_AddStringToObject(entry, "task_type", task_type ? task_type : "");
        cJSON_AddNumberToObject(entry, "next_attempt_at", sqlite3_column_int64(stmt, 1));
        cJSON_AddItemToArray(*types, entry);
    }

    if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_reset(stmt);
        cJSON_Delete(*types);
        *types = NULL;
        return OS_INVALID;
    }

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_get_claimed(wdb_t *wdb, const char *owner, const char *last_task_id, int limit, cJSON **tasks) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int index = 1;

    if (!wdb || !tasks || limit <= 0) {
        return OS_INVALID;
    }

    *tasks = cJSON_CreateArray();

    // A NULL owner enumerates every claimed row, whoever holds it. That is the startup form,
    // whose result set is bounded by nothing after repeated crashes, which is why both forms page.
    if (wdb_manager_task_prepare(wdb,
                                 owner ? WDB_STMT_MANAGER_TASK_SELECT_CLAIMED_BY_OWNER
                                       : WDB_STMT_MANAGER_TASK_SELECT_CLAIMED_ANY,
                                 &stmt) != OS_SUCCESS) {
        cJSON_Delete(*tasks);
        *tasks = NULL;
        return OS_INVALID;
    }

    if (owner) {
        sqlite3_bind_text(stmt, index++, owner, -1, NULL);
    }

    sqlite3_bind_text(stmt, index++, last_task_id ? last_task_id : "", -1, NULL);
    sqlite3_bind_int(stmt, index, limit);

    while (result = wdb_step(stmt), result == SQLITE_ROW) {
        cJSON *entry = cJSON_CreateObject();
        const char *column = (const char *)sqlite3_column_text(stmt, 0);

        cJSON_AddStringToObject(entry, "task_id", column ? column : "");

        column = (const char *)sqlite3_column_text(stmt, 1);
        cJSON_AddStringToObject(entry, "task_type", column ? column : "");

        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            column = (const char *)sqlite3_column_text(stmt, 2);
            cJSON_AddStringToObject(entry, "agent_id", column ? column : "");
        }

        // OWNER is parsed in C -- process id, process start time and lane id -- so the predicate
        // deciding whether a row may be reclaimed cannot be expressed in SQL. CLAIM_TIME comes
        // with it because reclaiming also requires the claim to be older than the grace period.
        column = (const char *)sqlite3_column_text(stmt, 3);
        cJSON_AddStringToObject(entry, "owner", column ? column : "");

        cJSON_AddNumberToObject(entry, "claim_time", sqlite3_column_int64(stmt, 4));
        cJSON_AddNumberToObject(entry, "attempts", sqlite3_column_int(stmt, 5));
        cJSON_AddNumberToObject(entry, "defer_count", sqlite3_column_int(stmt, 6));

        cJSON_AddItemToArray(*tasks, entry);
    }

    if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_reset(stmt);
        cJSON_Delete(*tasks);
        *tasks = NULL;
        return OS_INVALID;
    }

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_list(wdb_t *wdb,
                          const char *task_type,
                          const char *status,
                          const char *last_task_id,
                          int limit,
                          cJSON **tasks) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    int index = 1;

    if (!wdb || !task_type || !tasks || limit <= 0) {
        return OS_INVALID;
    }

    *tasks = cJSON_CreateArray();

    if (wdb_manager_task_prepare(wdb,
                                 status ? WDB_STMT_MANAGER_TASK_LIST_BY_TYPE_STATUS
                                        : WDB_STMT_MANAGER_TASK_LIST_BY_TYPE,
                                 &stmt) != OS_SUCCESS) {
        cJSON_Delete(*tasks);
        *tasks = NULL;
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, index++, task_type, -1, NULL);

    if (status) {
        sqlite3_bind_text(stmt, index++, status, -1, NULL);
    }

    sqlite3_bind_text(stmt, index++, last_task_id ? last_task_id : "", -1, NULL);
    sqlite3_bind_int(stmt, index, limit);

    while (result = wdb_step(stmt), result == SQLITE_ROW) {
        cJSON *entry = cJSON_CreateObject();
        const char *column = (const char *)sqlite3_column_text(stmt, 0);

        cJSON_AddStringToObject(entry, "task_id", column ? column : "");

        if (sqlite3_column_type(stmt, 1) != SQLITE_NULL) {
            column = (const char *)sqlite3_column_text(stmt, 1);
            cJSON_AddStringToObject(entry, "agent_id", column ? column : "");
        }

        column = (const char *)sqlite3_column_text(stmt, 2);
        cJSON_AddStringToObject(entry, "status", column ? column : "");

        cJSON_AddNumberToObject(entry, "create_time", sqlite3_column_int64(stmt, 3));

        // Carried so that a dead-letter listing is self-explanatory: an operator who never saw
        // the log line has no other way to learn why a row failed.
        if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
            column = (const char *)sqlite3_column_text(stmt, 4);
            cJSON_AddStringToObject(entry, "last_error", column ? column : "");
        }

        cJSON_AddItemToArray(*tasks, entry);
    }

    if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_reset(stmt);
        cJSON_Delete(*tasks);
        *tasks = NULL;
        return OS_INVALID;
    }

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_count(wdb_t *wdb, const char *task_type, const char *status, int *count) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb || !task_type || !status || !count) {
        return OS_INVALID;
    }

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_COUNT_BY_TYPE_STATUS, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, task_type, -1, NULL);
    sqlite3_bind_text(stmt, 2, status, -1, NULL);

    if (wdb_step(stmt) != SQLITE_ROW) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_reset(stmt);
        return OS_INVALID;
    }

    *count = sqlite3_column_int(stmt, 0);

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_pending_types(wdb_t *wdb, cJSON **types) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !types) {
        return OS_INVALID;
    }

    *types = cJSON_CreateArray();

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_PENDING_TYPES, &stmt) != OS_SUCCESS) {
        cJSON_Delete(*types);
        *types = NULL;
        return OS_INVALID;
    }

    while (result = wdb_step(stmt), result == SQLITE_ROW) {
        const char *task_type = (const char *)sqlite3_column_text(stmt, 0);
        cJSON_AddItemToArray(*types, cJSON_CreateString(task_type ? task_type : ""));
    }

    if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_reset(stmt);
        cJSON_Delete(*types);
        *types = NULL;
        return OS_INVALID;
    }

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_fail_type(wdb_t *wdb, const char *task_type, const char *last_error) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb || !task_type) {
        return OS_INVALID;
    }

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_FAIL_BY_TYPE, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    wdb_manager_task_bind_text(stmt, 1, last_error);
    sqlite3_bind_text(stmt, 2, task_type, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

/**
 * @brief Run a prepared DELETE and report how many rows it removed.
 *
 * @param[out] removed Incremented by the number of rows deleted.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
STATIC int wdb_manager_task_step_delete(wdb_t *wdb, sqlite3_stmt *stmt, int *removed) {
    if (wdb_step(stmt) != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    *removed += sqlite3_changes(wdb->db);

    return OS_SUCCESS;
}

int wdb_manager_task_retention(wdb_t *wdb, const wdb_manager_task_retention_t *retention, cJSON **stats) {
    sqlite3_stmt *stmt = NULL;
    cJSON *schedule_ids = NULL;
    int by_age = 0;
    int by_schedule = 0;
    int by_ceiling = 0;
    int remaining = 0;
    int result = 0;

    if (!wdb || !retention) {
        return OS_INVALID;
    }

    if (stats) {
        *stats = NULL;
    }

    // Age, for the three ordinary terminal states.
    if (retention->terminal_before > 0) {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_DELETE_TERMINAL_OLD, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        sqlite3_bind_int64(stmt, 1, retention->terminal_before);

        if (wdb_manager_task_step_delete(wdb, stmt, &by_age) != OS_SUCCESS) {
            return OS_INVALID;
        }
    }

    // Age, for dead_letter, on its own longer window.
    if (retention->dead_letter_before > 0) {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_DELETE_DEAD_LETTER_OLD, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        sqlite3_bind_int64(stmt, 1, retention->dead_letter_before);

        if (wdb_manager_task_step_delete(wdb, stmt, &by_age) != OS_SUCCESS) {
            return OS_INVALID;
        }
    }

    // Per-schedule history cap. The schedule ids are collected before any deletion rather than
    // deleted while the cursor walks them, because both statements read MANAGER_TASKS.
    if (retention->history_per_schedule > 0) {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SCHEDULE_IDS, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        schedule_ids = cJSON_CreateArray();

        while (result = wdb_step(stmt), result == SQLITE_ROW) {
            const char *schedule_id = (const char *)sqlite3_column_text(stmt, 0);
            cJSON_AddItemToArray(schedule_ids, cJSON_CreateString(schedule_id ? schedule_id : ""));
        }

        if (result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
            sqlite3_reset(stmt);
            cJSON_Delete(schedule_ids);
            return OS_INVALID;
        }

        sqlite3_reset(stmt);

        cJSON *schedule_id = NULL;

        cJSON_ArrayForEach(schedule_id, schedule_ids) {
            if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_TRIM_SCHEDULE_HISTORY, &stmt) != OS_SUCCESS) {
                cJSON_Delete(schedule_ids);
                return OS_INVALID;
            }

            sqlite3_bind_text(stmt, 1, schedule_id->valuestring, -1, NULL);
            sqlite3_bind_text(stmt, 2, schedule_id->valuestring, -1, NULL);
            sqlite3_bind_int(stmt, 3, retention->history_per_schedule);

            if (wdb_manager_task_step_delete(wdb, stmt, &by_schedule) != OS_SUCCESS) {
                cJSON_Delete(schedule_ids);
                return OS_INVALID;
            }
        }

        cJSON_Delete(schedule_ids);
    }

    // The hard ceiling, last, so it only ever sees what the other two rules left behind.
    if (retention->max_rows > 0) {
        if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_COUNT_ALL, &stmt) != OS_SUCCESS) {
            return OS_INVALID;
        }

        if (wdb_step(stmt) != SQLITE_ROW) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
            sqlite3_reset(stmt);
            return OS_INVALID;
        }

        remaining = sqlite3_column_int(stmt, 0);

        sqlite3_reset(stmt);

        if (remaining > retention->max_rows) {
            if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_EVICT, &stmt) != OS_SUCCESS) {
                return OS_INVALID;
            }

            sqlite3_bind_int(stmt, 1, remaining - retention->max_rows);

            if (wdb_manager_task_step_delete(wdb, stmt, &by_ceiling) != OS_SUCCESS) {
                return OS_INVALID;
            }

            remaining -= by_ceiling;
        }
    }

    if (stats) {
        *stats = cJSON_CreateObject();
        cJSON_AddNumberToObject(*stats, "by_age", by_age);
        cJSON_AddNumberToObject(*stats, "by_schedule", by_schedule);
        cJSON_AddNumberToObject(*stats, "by_ceiling", by_ceiling);

        // Reported so the caller can tell that the ceiling was reached and could not be met,
        // which means only dead_letter rows are left and is worth an error rather than silence.
        cJSON_AddNumberToObject(*stats, "remaining", remaining);
    }

    return OS_SUCCESS;
}

int wdb_manager_task_schedule_get(wdb_t *wdb, const char *schedule_id, cJSON **schedule) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !schedule_id || !schedule) {
        return OS_INVALID;
    }

    *schedule = NULL;

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SCHEDULE_GET, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, schedule_id, -1, NULL);

    result = wdb_step(stmt);

    if (result != SQLITE_ROW) {
        if (result != SQLITE_DONE) {
            merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        }

        sqlite3_reset(stmt);

        return result == SQLITE_DONE ? OS_SUCCESS : OS_INVALID;
    }

    *schedule = cJSON_CreateObject();

    const char *column = (const char *)sqlite3_column_text(stmt, 0);

    cJSON_AddStringToObject(*schedule, "schedule_id", column ? column : "");
    cJSON_AddNumberToObject(*schedule, "next_run_at", sqlite3_column_int64(stmt, 1));
    cJSON_AddNumberToObject(*schedule, "enabled", sqlite3_column_int(stmt, 2));

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_schedule_upsert(wdb_t *wdb,
                                     const char *schedule_id,
                                     long long next_run_at,
                                     int enabled,
                                     cJSON **previous) {
    sqlite3_stmt *stmt = NULL;
    cJSON *existing = NULL;

    if (!wdb || !schedule_id) {
        return OS_INVALID;
    }

    if (previous) {
        *previous = NULL;
    }

    // The previous row is read and handed back rather than acted on here. Whether a
    // disabled-to-enabled transition should reset NEXT_RUN_AT is a policy the dispatcher owns;
    // wazuh-db only has to make the transition observable across a restart.
    if (wdb_manager_task_schedule_get(wdb, schedule_id, &existing) != OS_SUCCESS) {
        return OS_INVALID;
    }

    if (wdb_manager_task_prepare(wdb,
                                 existing ? WDB_STMT_MANAGER_TASK_SCHEDULE_UPDATE
                                          : WDB_STMT_MANAGER_TASK_SCHEDULE_INSERT,
                                 &stmt) != OS_SUCCESS) {
        cJSON_Delete(existing);
        return OS_INVALID;
    }

    if (existing) {
        sqlite3_bind_int64(stmt, 1, next_run_at);
        sqlite3_bind_int(stmt, 2, enabled);
        sqlite3_bind_text(stmt, 3, schedule_id, -1, NULL);
    } else {
        sqlite3_bind_text(stmt, 1, schedule_id, -1, NULL);
        sqlite3_bind_int64(stmt, 2, next_run_at);
        sqlite3_bind_int(stmt, 3, enabled);
    }

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        cJSON_Delete(existing);
        return OS_INVALID;
    }

    if (previous) {
        *previous = existing;
    } else {
        cJSON_Delete(existing);
    }

    return OS_SUCCESS;
}

int wdb_manager_task_schedule_set_next_run(wdb_t *wdb, const char *schedule_id, long long next_run_at) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb || !schedule_id) {
        return OS_INVALID;
    }

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SCHEDULE_SET_NEXT_RUN, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_int64(stmt, 1, next_run_at);
    sqlite3_bind_text(stmt, 2, schedule_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Deliberately uncommitted. A crash between the instance insert and this advance re-derives
    // the same deterministic task id on the next attempt, so the primary key collision makes the
    // double spawn a no-op and no cross-table transaction is needed.
    return OS_SUCCESS;
}

int wdb_manager_task_schedule_list_due(wdb_t *wdb, long long now, cJSON **schedules) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !schedules) {
        return OS_INVALID;
    }

    *schedules = cJSON_CreateArray();

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SCHEDULE_LIST_DUE, &stmt) != OS_SUCCESS) {
        cJSON_Delete(*schedules);
        *schedules = NULL;
        return OS_INVALID;
    }

    sqlite3_bind_int64(stmt, 1, now);

    while (result = wdb_step(stmt), result == SQLITE_ROW) {
        const char *schedule_id = (const char *)sqlite3_column_text(stmt, 0);
        cJSON *entry = cJSON_CreateObject();

        cJSON_AddStringToObject(entry, "schedule_id", schedule_id ? schedule_id : "");
        cJSON_AddNumberToObject(entry, "next_run_at", sqlite3_column_int64(stmt, 1));
        cJSON_AddItemToArray(*schedules, entry);
    }

    if (result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_reset(stmt);
        cJSON_Delete(*schedules);
        *schedules = NULL;
        return OS_INVALID;
    }

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}

int wdb_manager_task_schedule_has_active(wdb_t *wdb, const char *schedule_id, bool *active) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (!wdb || !schedule_id || !active) {
        return OS_INVALID;
    }

    if (wdb_manager_task_prepare(wdb, WDB_STMT_MANAGER_TASK_SCHEDULE_HAS_ACTIVE, &stmt) != OS_SUCCESS) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, schedule_id, -1, NULL);

    result = wdb_step(stmt);

    if (result != SQLITE_ROW && result != SQLITE_DONE) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_reset(stmt);
        return OS_INVALID;
    }

    // A pending or claimed instance suppresses the next spawn. Under a multi-batch handler that
    // means the effective interval becomes "however long the run takes", which is intended: a
    // sweep should not start again while the previous one is still walking.
    *active = (result == SQLITE_ROW);

    sqlite3_reset(stmt);

    return OS_SUCCESS;
}
