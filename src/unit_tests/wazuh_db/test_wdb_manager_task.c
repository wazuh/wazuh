/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>

#include "wdb.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

// Setup/teardown

static int test_setup(void **state) {
    wdb_t *wdb = NULL;
    os_calloc(1, sizeof(wdb_t), wdb);
    os_calloc(1, sizeof(sqlite3 *), wdb->db);
    // Most tests exercise several statements in one operation; opening the transaction is
    // covered on its own in test_wdb_manager_task_create_begin_fail.
    wdb->transaction = 1;
    // wdb_manager_task_stmt() returns wdb->stmt[index] and treats NULL as a cache failure, so the
    // slots need a non-NULL placeholder. Every function that receives it is wrapped, so it is
    // never dereferenced.
    for (int i = 0; i < WDB_STMT_SIZE; i++) {
        wdb->stmt[i] = (sqlite3_stmt *)1;
    }
    *state = wdb;
    return 0;
}

static int test_teardown(void **state) {
    wdb_t *wdb = *state;
    os_free(wdb->db);
    os_free(wdb);
    return 0;
}

/* wdb_manager_task_payload_fits */

void test_wdb_manager_task_payload_fits_small(void **state) {
    assert_true(wdb_manager_task_payload_fits("{\"agent_id\":\"001\"}"));
}

void test_wdb_manager_task_payload_fits_null(void **state) {
    assert_false(wdb_manager_task_payload_fits(NULL));
}

void test_wdb_manager_task_payload_fits_at_the_bound(void **state) {
    char payload[16385];

    memset(payload, 'a', 16384);
    payload[16384] = '\0';

    assert_true(wdb_manager_task_payload_fits(payload));
}

void test_wdb_manager_task_payload_fits_one_over(void **state) {
    char payload[16386];

    memset(payload, 'a', 16385);
    payload[16385] = '\0';

    assert_false(wdb_manager_task_payload_fits(payload));
}

void test_wdb_manager_task_payload_fits_counts_escaping(void **state) {
    // Half the bound in raw characters, but every one of them doubles under JSON escaping, so
    // 8192 quotes land exactly on the limit and one more goes over. A check on the raw length
    // would pass both.
    char payload[8194];

    memset(payload, '"', 8192);
    payload[8192] = '\0';

    assert_true(wdb_manager_task_payload_fits(payload));

    payload[8192] = '"';
    payload[8193] = '\0';

    assert_false(wdb_manager_task_payload_fits(payload));
}

/* wdb_manager_task_result_name */

void test_wdb_manager_task_result_name(void **state) {
    assert_string_equal(wdb_manager_task_result_name(WDB_MANAGER_TASK_CREATED), "created");
    assert_string_equal(wdb_manager_task_result_name(WDB_MANAGER_TASK_COALESCED), "coalesced");
    assert_string_equal(wdb_manager_task_result_name(WDB_MANAGER_TASK_COLLIDED), "collided");
    assert_string_equal(wdb_manager_task_result_name(WDB_MANAGER_TASK_QUEUE_FULL), "queue_full");
    assert_string_equal(wdb_manager_task_result_name(WDB_MANAGER_TASK_REQUEUED), "requeued");
    assert_string_equal(wdb_manager_task_result_name(WDB_MANAGER_TASK_SUPERSEDED), "superseded");
    assert_string_equal(wdb_manager_task_result_name(OS_INVALID), "unknown");
}

/* wdb_manager_task_create */

/**
 * @brief Queue the bindings of one INSERT into MANAGER_TASKS.
 */
static void expect_manager_task_insert_bindings(void) {
    expect_sqlite3_bind_text_call(1, "task-id", SQLITE_OK);
    expect_sqlite3_bind_text_call(2, "vd_scan", SQLITE_OK);
    expect_sqlite3_bind_text_call(3, "{}", SQLITE_OK);
    expect_sqlite3_bind_int64_call(4, 1000, SQLITE_OK);
    expect_sqlite3_bind_text_call(5, "001", SQLITE_OK);
    expect_sqlite3_bind_int64_call(6, 1200, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_null, index, 8);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
}

static wdb_manager_task_create_t sample_task(void) {
    wdb_manager_task_create_t task = {0};

    task.task_id = "task-id";
    task.task_type = "vd_scan";
    task.payload = "{}";
    task.agent_id = "001";
    task.create_time = 1000;
    task.next_attempt_at = 1200;

    return task;
}

void test_wdb_manager_task_create_success(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    char *surviving_task_id = NULL;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_manager_task_insert_bindings();
    will_return(__wrap_wdb_step, SQLITE_DONE);

    // Creation commits inside its own command, so the reply is a durability acknowledgement.
    will_return(__wrap_wdb_commit2, 0);

    int result = wdb_manager_task_create(wdb, &task, &surviving_task_id);

    assert_int_equal(result, WDB_MANAGER_TASK_CREATED);
    assert_string_equal(surviving_task_id, "task-id");
    os_free(surviving_task_id);
}

void test_wdb_manager_task_create_begin_fail(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();

    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "(5212): Cannot begin transaction.");

    assert_int_equal(wdb_manager_task_create(wdb, &task, NULL), OS_INVALID);
}

void test_wdb_manager_task_create_commit_fail(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    char *surviving_task_id = NULL;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_manager_task_insert_bindings();
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_commit2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "(5212): Cannot begin transaction.");

    // A row that could not be committed must not be reported as created: authd would drop its
    // intent journal line on the strength of that reply.
    assert_int_equal(wdb_manager_task_create(wdb, &task, &surviving_task_id), OS_INVALID);
    assert_null(surviving_task_id);
}

void test_wdb_manager_task_create_collided(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    char *surviving_task_id = NULL;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_manager_task_insert_bindings();
    will_return(__wrap_wdb_step, SQLITE_CONSTRAINT);

    int result = wdb_manager_task_create(wdb, &task, &surviving_task_id);

    // The expected idempotent path for a deterministic id: the row is already recorded. Note no
    // commit is queued, so the operation reaching one would fail this test.
    assert_int_equal(result, WDB_MANAGER_TASK_COLLIDED);
    assert_string_equal(surviving_task_id, "task-id");
    os_free(surviving_task_id);
}

void test_wdb_manager_task_create_coalesced(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    char *surviving_task_id = NULL;

    task.coalesce = true;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "001", SQLITE_OK);
    expect_sqlite3_bind_text_call(2, "vd_scan", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "older-task-id");
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    int result = wdb_manager_task_create(wdb, &task, &surviving_task_id);

    // The surviving row's id, not the one that was asked for: a caller handed its own id back
    // would look up a row that was never inserted.
    assert_int_equal(result, WDB_MANAGER_TASK_COALESCED);
    assert_string_equal(surviving_task_id, "older-task-id");
    os_free(surviving_task_id);
}

void test_wdb_manager_task_create_coalesce_miss_inserts(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    char *surviving_task_id = NULL;

    task.coalesce = true;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "001", SQLITE_OK);
    expect_sqlite3_bind_text_call(2, "vd_scan", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_manager_task_insert_bindings();
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_commit2, 0);

    assert_int_equal(wdb_manager_task_create(wdb, &task, &surviving_task_id), WDB_MANAGER_TASK_CREATED);
    os_free(surviving_task_id);
}

void test_wdb_manager_task_create_queue_full(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();

    task.max_pending = 64;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "vd_scan", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 64);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    assert_int_equal(wdb_manager_task_create(wdb, &task, NULL), WDB_MANAGER_TASK_QUEUE_FULL);
}

void test_wdb_manager_task_create_under_bound_inserts(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    char *surviving_task_id = NULL;

    task.max_pending = 64;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "vd_scan", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 63);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_manager_task_insert_bindings();
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_commit2, 0);

    assert_int_equal(wdb_manager_task_create(wdb, &task, &surviving_task_id), WDB_MANAGER_TASK_CREATED);
    os_free(surviving_task_id);
}

void test_wdb_manager_task_create_next_attempt_defaults_to_create_time(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    char *surviving_task_id = NULL;

    task.next_attempt_at = 0;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "task-id", SQLITE_OK);
    expect_sqlite3_bind_text_call(2, "vd_scan", SQLITE_OK);
    expect_sqlite3_bind_text_call(3, "{}", SQLITE_OK);
    expect_sqlite3_bind_int64_call(4, 1000, SQLITE_OK);
    expect_sqlite3_bind_text_call(5, "001", SQLITE_OK);
    // Never zero: ordering the claim by this column would then put every fresh row ahead of
    // every retried one, whose value is a real past timestamp.
    expect_sqlite3_bind_int64_call(6, 1000, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_null, index, 8);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_commit2, 0);

    assert_int_equal(wdb_manager_task_create(wdb, &task, &surviving_task_id), WDB_MANAGER_TASK_CREATED);
    os_free(surviving_task_id);
}

/* wdb_manager_task_claim */

void test_wdb_manager_task_claim_no_eligible_row(void **state) {
    wdb_t *wdb = *state;
    cJSON *task = NULL;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "vd_scan", SQLITE_OK);
    expect_sqlite3_bind_int64_call(2, 5000, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    // An empty queue is the common answer, not an error.
    assert_int_equal(wdb_manager_task_claim(wdb, "vd_scan", "10:20:scan-0", 5000, &task), OS_SUCCESS);
    assert_null(task);
}

void test_wdb_manager_task_claim_success(void **state) {
    wdb_t *wdb = *state;
    cJSON *task = NULL;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "vd_scan", SQLITE_OK);
    expect_sqlite3_bind_int64_call(2, 5000, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "task-id");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "vd_scan");
    expect_value(__wrap_sqlite3_column_type, i, 2);
    will_return(__wrap_sqlite3_column_type, SQLITE_TEXT);
    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "001");
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "{}");
    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, 2);
    expect_value(__wrap_sqlite3_column_int, iCol, 5);
    will_return(__wrap_sqlite3_column_int, 1);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "10:20:scan-0", SQLITE_OK);
    expect_sqlite3_bind_int64_call(2, 5000, SQLITE_OK);
    expect_sqlite3_bind_text_call(3, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    // The claim must be durable before the handler runs, or it can roll back under a wazuh-db
    // restart while the lane is still executing and let a second lane claim the same row.
    will_return(__wrap_wdb_commit2, 0);

    assert_int_equal(wdb_manager_task_claim(wdb, "vd_scan", "10:20:scan-0", 5000, &task), OS_SUCCESS);
    assert_non_null(task);
    assert_string_equal(cJSON_GetObjectItem(task, "task_id")->valuestring, "task-id");
    assert_string_equal(cJSON_GetObjectItem(task, "agent_id")->valuestring, "001");
    assert_int_equal(cJSON_GetObjectItem(task, "attempts")->valueint, 2);
    assert_int_equal(cJSON_GetObjectItem(task, "defer_count")->valueint, 1);

    cJSON_Delete(task);
}

void test_wdb_manager_task_claim_omits_null_agent(void **state) {
    wdb_t *wdb = *state;
    cJSON *task = NULL;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "log_rotate_daily", SQLITE_OK);
    expect_sqlite3_bind_int64_call(2, 5000, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "task-id");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "log_rotate_daily");
    expect_value(__wrap_sqlite3_column_type, i, 2);
    will_return(__wrap_sqlite3_column_type, SQLITE_NULL);
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "{}");
    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 5);
    will_return(__wrap_sqlite3_column_int, 0);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "10:20:local-0", SQLITE_OK);
    expect_sqlite3_bind_int64_call(2, 5000, SQLITE_OK);
    expect_sqlite3_bind_text_call(3, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_commit2, 0);

    assert_int_equal(wdb_manager_task_claim(wdb, "log_rotate_daily", "10:20:local-0", 5000, &task), OS_SUCCESS);
    assert_non_null(task);

    // Core tasks have no agent subject, and the field is absent rather than empty.
    assert_null(cJSON_GetObjectItem(task, "agent_id"));

    cJSON_Delete(task);
}

/* wdb_manager_task_requeue */

void test_wdb_manager_task_requeue_no_competing_row(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_requeue_t requeue = {0};

    requeue.task_id = "task-id";
    requeue.last_error = "timeout";
    requeue.next_attempt_at = 6000;
    requeue.attempts = 3;
    requeue.defer_count = 0;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_int64_call(1, 6000, SQLITE_OK);
    expect_sqlite3_bind_int_call(2, 3, SQLITE_OK);
    expect_sqlite3_bind_int_call(3, 0, SQLITE_OK);
    expect_sqlite3_bind_text_call(4, "timeout", SQLITE_OK);
    expect_sqlite3_bind_text_call(5, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    assert_int_equal(wdb_manager_task_requeue(wdb, &requeue), WDB_MANAGER_TASK_REQUEUED);
}

void test_wdb_manager_task_requeue_non_coalescing_skips_lookup(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_requeue_t requeue = {0};

    // A non-coalescing type cannot have a competing row, so no lookup is issued: only the
    // re-queue statement below is expected.
    requeue.task_id = "task-id";
    requeue.task_type = "agent_delete_indexer";
    requeue.agent_id = "001";
    requeue.next_attempt_at = 6000;
    requeue.attempts = 1;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_int64_call(1, 6000, SQLITE_OK);
    expect_sqlite3_bind_int_call(2, 1, SQLITE_OK);
    expect_sqlite3_bind_int_call(3, 0, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_null, index, 4);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    expect_sqlite3_bind_text_call(5, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    assert_int_equal(wdb_manager_task_requeue(wdb, &requeue), WDB_MANAGER_TASK_REQUEUED);
}

void test_wdb_manager_task_requeue_superseded_inherits_counters(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_requeue_t requeue = {0};

    requeue.task_id = "task-id";
    requeue.task_type = "vd_scan";
    requeue.agent_id = "001";
    requeue.last_error = "timeout";
    requeue.next_attempt_at = 6000;
    requeue.attempts = 5;
    requeue.defer_count = 1;
    requeue.coalesce = true;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "001", SQLITE_OK);
    expect_sqlite3_bind_text_call(2, "vd_scan", SQLITE_OK);
    expect_sqlite3_bind_text_call(3, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "newer-task-id");
    expect_value(__wrap_sqlite3_column_int, iCol, 1);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, 4);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    // The survivor takes the higher of each counter, so the retry budget belongs to the work
    // rather than to the row. Without this a coalescing type never reaches dead_letter under
    // load: each timed-out row is replaced by a fresh one starting at zero.
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_int_call(1, 5, SQLITE_OK);
    expect_sqlite3_bind_int_call(2, 4, SQLITE_OK);
    expect_sqlite3_bind_text_call(3, "newer-task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "timeout", SQLITE_OK);
    expect_sqlite3_bind_text_call(2, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    assert_int_equal(wdb_manager_task_requeue(wdb, &requeue), WDB_MANAGER_TASK_SUPERSEDED);
}

/* wdb_manager_task_set_result */

void test_wdb_manager_task_set_result_does_not_commit(void **state) {
    wdb_t *wdb = *state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "completed", SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_null, index, 2);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    expect_sqlite3_bind_int_call(3, 1, SQLITE_OK);
    expect_sqlite3_bind_int_call(4, 0, SQLITE_OK);
    expect_sqlite3_bind_text_call(5, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    // No commit is queued. The outcome write is deliberately left in the deferred transaction:
    // a rollback leaves the row claimed, the sweep reclaims it, and the handler -- which is
    // required to be idempotent -- runs again. Reaching wdb_commit2 here fails this test.
    assert_int_equal(wdb_manager_task_set_result(wdb, "task-id", "completed", NULL, 1, 0), OS_SUCCESS);
}

void test_wdb_manager_task_set_result_records_error(void **state) {
    wdb_t *wdb = *state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "dead_letter", SQLITE_OK);
    expect_sqlite3_bind_text_call(2, "consumer unreachable", SQLITE_OK);
    expect_sqlite3_bind_int_call(3, 8, SQLITE_OK);
    expect_sqlite3_bind_int_call(4, 48, SQLITE_OK);
    expect_sqlite3_bind_text_call(5, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    assert_int_equal(wdb_manager_task_set_result(wdb, "task-id", "dead_letter", "consumer unreachable", 8, 48),
                     OS_SUCCESS);
}

/* wdb_manager_task_get */

void test_wdb_manager_task_get_not_found(void **state) {
    wdb_t *wdb = *state;
    cJSON *task = NULL;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_bind_text_call(1, "task-id", SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_reset, SQLITE_OK);

    assert_int_equal(wdb_manager_task_get(wdb, "task-id", &task), OS_SUCCESS);
    assert_null(task);
}

/* Argument validation */

void test_wdb_manager_task_rejects_missing_arguments(void **state) {
    wdb_t *wdb = *state;
    wdb_manager_task_create_t task = sample_task();
    cJSON *out = NULL;

    task.task_type = NULL;

    assert_int_equal(wdb_manager_task_create(wdb, &task, NULL), OS_INVALID);
    assert_int_equal(wdb_manager_task_create(wdb, NULL, NULL), OS_INVALID);
    assert_int_equal(wdb_manager_task_claim(wdb, NULL, "owner", 0, &out), OS_INVALID);
    assert_int_equal(wdb_manager_task_requeue(wdb, NULL), OS_INVALID);
    assert_int_equal(wdb_manager_task_set_result(wdb, "task-id", NULL, NULL, 0, 0), OS_INVALID);
    assert_int_equal(wdb_manager_task_get(wdb, NULL, &out), OS_INVALID);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // wdb_manager_task_payload_fits
        cmocka_unit_test(test_wdb_manager_task_payload_fits_small),
        cmocka_unit_test(test_wdb_manager_task_payload_fits_null),
        cmocka_unit_test(test_wdb_manager_task_payload_fits_at_the_bound),
        cmocka_unit_test(test_wdb_manager_task_payload_fits_one_over),
        cmocka_unit_test(test_wdb_manager_task_payload_fits_counts_escaping),
        // wdb_manager_task_result_name
        cmocka_unit_test(test_wdb_manager_task_result_name),
        // wdb_manager_task_create
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_begin_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_commit_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_collided, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_coalesced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_coalesce_miss_inserts, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_queue_full, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_under_bound_inserts, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_create_next_attempt_defaults_to_create_time, test_setup, test_teardown),
        // wdb_manager_task_claim
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_claim_no_eligible_row, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_claim_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_claim_omits_null_agent, test_setup, test_teardown),
        // wdb_manager_task_requeue
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_requeue_no_competing_row, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_requeue_non_coalescing_skips_lookup, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_requeue_superseded_inherits_counters, test_setup, test_teardown),
        // wdb_manager_task_set_result
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_set_result_does_not_commit, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_set_result_records_error, test_setup, test_teardown),
        // wdb_manager_task_get
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_get_not_found, test_setup, test_teardown),
        // Argument validation
        cmocka_unit_test_setup_teardown(test_wdb_manager_task_rejects_missing_arguments, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
