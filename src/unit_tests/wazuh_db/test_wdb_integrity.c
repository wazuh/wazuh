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
#include <stdio.h>
#include <string.h>

#include "../wazuh_db/wdb.h"
#include "../headers/shared.h"
#include "../os_crypto/sha1/sha1_op.h"
#include "../external/sqlite/sqlite3.h"
#include "utils/flatbuffers/include/syscollector_deltas_schema.h"

#include "../wrappers/externals/openssl/digest_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "cJSON.h"
#include "os_err.h"

int wdb_calculate_stmt_checksum(wdb_t * wdb, sqlite3_stmt * stmt, wdb_component_t component, os_sha1 hexdigest, const char * pk_value);
extern os_sha1 global_group_hash;

/* setup/teardown */
static int setup_wdb_t(void **state) {
    wdb_t *data = calloc(1, sizeof(wdb_t));

    if(!data) {
        return -1;
    }

    //Initializing dummy statements pointers
    for (int i = 0; i < WDB_STMT_SIZE; ++i) {
        data->stmt[i] = (sqlite3_stmt *)1;
    }

    test_mode = 1;
    *state = data;
    return 0;
}

static int teardown_wdb_t(void **state) {
    wdb_t *data = *state;

    if(data) {
        os_free(data->id);
        os_free(data);
    }

    test_mode = 0;
    return 0;
}

/* tests */

// Tests wdb_calculate_stmt_checksum
static void test_wdb_calculate_stmt_checksum_wdb_null(void **state) {
    expect_assert_failure(wdb_calculate_stmt_checksum(NULL, NULL, WDB_FIM, NULL, NULL));
}

static void test_wdb_calculate_stmt_checksum_stmt_null(void **state) {
    wdb_t *data = *state;

    expect_assert_failure(wdb_calculate_stmt_checksum(data, NULL, WDB_FIM, NULL, NULL));
}

static void test_wdb_calculate_stmt_checksum_cks_null(void **state) {
    wdb_t *data = *state;
    sqlite3_stmt *stmt = (sqlite3_stmt *)1;

    expect_assert_failure(wdb_calculate_stmt_checksum(data, stmt, WDB_FIM, NULL, NULL));
}

static void test_wdb_calculate_stmt_checksum_no_row(void **state) {
    int ret;

    wdb_t *data = *state;
    sqlite3_stmt *stmt = (sqlite3_stmt *)1;
    os_sha1 test_hex = "";

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    ret = wdb_calculate_stmt_checksum(data, stmt, WDB_FIM, test_hex, NULL);

    assert_int_equal(ret, 0);
}

static void test_wdb_calculate_stmt_checksum_success(void **state) {
    int ret;

    wdb_t *data = *state;
    data->id = strdup("000");
    sqlite3_stmt *stmt = (sqlite3_stmt *)1;
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");

    ret = wdb_calculate_stmt_checksum(data, stmt, WDB_FIM, test_hex, NULL);

    assert_int_equal(ret, 1);
}

static void test_wdb_calculate_stmt_checksum_duplicate_entries_found(void **state) {
    int ret;

    wdb_t *data = *state;
    data->id = strdup("001");
    sqlite3_stmt *stmt = (sqlite3_stmt *)1;
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};
    const char* pk_value = "test_pk_value";
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    // For loop
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "test_checksum");
    expect_string(__wrap_EVP_DigestUpdate, data, "test_checksum");
    expect_value(__wrap_EVP_DigestUpdate, count, 13);
    will_return(__wrap_EVP_DigestUpdate, 0);
    // Next iteration
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "test_checksum");
    expect_string(__wrap_EVP_DigestUpdate, data, "test_checksum");
    expect_value(__wrap_EVP_DigestUpdate, count, 13);
    will_return(__wrap_EVP_DigestUpdate, 0);
    // No more rows
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    expect_string(__wrap__mwarn, formatted_msg, "DB(001) syscollector-packages component has more than one element with the same PK value 'test_pk_value'.");

    // wdbi_remove_by_pk
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, pk_value);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    ret = wdb_calculate_stmt_checksum(data, stmt, component, test_hex, pk_value);

    assert_int_equal(ret, 1);
}

// Tests wdbi_checksum
static void test_wdbi_checksum_wdb_null(void **state) {
    expect_assert_failure(wdbi_checksum(NULL, 0, ""));
}

static void test_wdbi_checksum_hexdigest_null(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");

    expect_assert_failure(wdbi_checksum(data, 0, NULL));
}

static void test_wdbi_checksum_stmt_cache_fail(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    ret = wdbi_checksum(data, 0, test_hex);

    assert_int_equal(ret, -1);
}

static void test_wdbi_checksum_success(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");

    ret = wdbi_checksum(data, 0, test_hex);

    assert_int_equal(ret, 1);
}

// Tests wdbi_remove_by_pk
static void test_wdbi_remove_by_pk_wdb_null(void **state) {
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;
    const char* pk_value = NULL;
    expect_assert_failure(wdbi_remove_by_pk(NULL, component, pk_value));
}

static void test_wdbi_remove_by_pk_null(void **state) {
    wdb_t *data = *state;
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;
    const char* pk_value = NULL;

    expect_string(__wrap__mwarn, formatted_msg, "PK value is NULL during the removal of the component 'syscollector-packages'");

    wdbi_remove_by_pk(data, component, pk_value);
}

static void test_wdbi_remove_by_pk_stmt_cache_fail(void **state) {
    wdb_t *data = *state;
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;
    const char* pk_value = "test_pk_value";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbi_remove_by_pk(data, component, pk_value);
}

static void test_wdbi_remove_by_pk_sqlite_bind_fail(void **state) {
    wdb_t *data = *state;
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;
    const char* pk_value = "test_pk_value";
    data->id = strdup("001");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, pk_value);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "DB(001) sqlite3_bind_text(): ERROR");

    wdbi_remove_by_pk(data, component, pk_value);
}

static void test_wdbi_remove_by_pk_sqlite_step_fail(void **state) {
    wdb_t *data = *state;
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;

    const char* pk_value = "test_pk_value";
    data->id = strdup("001");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, pk_value);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(001) SQLite: ERROR");

    wdbi_remove_by_pk(data, component, pk_value);
}

static void test_wdbi_remove_by_pk_success(void **state) {
    wdb_t *data = *state;
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;

    const char* pk_value = "test_pk_value";
    data->id = strdup("001");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, pk_value);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wdbi_remove_by_pk(data, component, pk_value);
}

// Tests wdbi_checksum_range
static void test_wdbi_checksum_range_wdb_null(void **state) {
    expect_assert_failure(wdbi_checksum_range(NULL, 0, "test_begin", "test_end", ""));
}

static void test_wdbi_checksum_range_hexdigest_null(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");

    expect_assert_failure(wdbi_checksum_range(data, 0, "test_begin", "test_end", NULL));
}

static void test_wdbi_checksum_range_stmt_cache_fail(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    ret = wdbi_checksum_range(data, 0, "test_begin", "test_end", test_hex);

    assert_int_equal(ret, -1);
}

static void test_wdbi_checksum_range_begin_null(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");

    const char* begin = NULL;
    const char* end = "test_end";
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    ret = wdbi_checksum_range(data, 0, begin, end, test_hex);

    assert_int_equal(ret, 0);
}

static void test_wdbi_checksum_range_end_null(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");

    const char* begin = "test_begin";
    const char* end = NULL;
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    ret = wdbi_checksum_range(data, 0, begin, end, test_hex);

    assert_int_equal(ret, 0);
}

static void test_wdbi_checksum_range_success(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");

    ret = wdbi_checksum_range(data, 0, begin, end, test_hex);

    assert_int_equal(ret, 1);
}

// Test wdbi_delete
static void test_wdbi_delete_wdb_null(void **state) {
    expect_assert_failure(wdbi_delete(NULL, 0, "test_begin", "test_end","test_tail"));
}

static void test_wdbi_delete_begin_null(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = NULL;
    const char* end = "test_end";
    const char* tail = NULL;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_begin_null");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_begin_null");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_end_null(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = NULL;
    const char* tail = "test_tail";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, tail);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_end_null");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_end_null");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_tail_null(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    const char* tail = NULL;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_tail_null");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_tail_null");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_stmt_cache_fail(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    ret = wdbi_delete(data, 0, "test_begin", "test_end","test_tail");

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_sql_no_done(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    const char* tail = "test_fail";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, tail);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_sql_no_done");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_sql_no_done");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_success(void **state) {
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    const char* tail = "test_fail";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, tail);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, 0);
}

// Test wdbi_update_attempt
static void test_wdbi_update_attempt_wdb_null(void **state) {
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";

    expect_assert_failure(wdbi_update_attempt(NULL, 0, 1, agent_checksum, manager_checksum, FALSE));
}

static void test_wdbi_update_attempt_stmt_cache_fail(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    wdbi_update_attempt(data, 0, 0, agent_checksum, manager_checksum, FALSE);
}

static void test_wdbi_update_attempt_no_sql_done(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, agent_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, manager_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 1);
    will_return(__wrap_sqlite3_errmsg, "test_no_sql_done");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_no_sql_done");

    wdbi_update_attempt(data, WDB_FIM, 0, agent_checksum, manager_checksum, FALSE);
}

static void test_wdbi_update_attempt_success(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, agent_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, manager_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    wdbi_update_attempt(data, WDB_FIM, 0, agent_checksum, manager_checksum, FALSE);
}

// Test wdbi_update_completion
static void test_wdbi_update_completion_wdb_null(void **state) {
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";
    expect_assert_failure(wdbi_update_completion(NULL, 0, 0, agent_checksum, manager_checksum));
}

static void test_wdbi_update_completion_stmt_cache_fail(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    wdbi_update_completion(data, 0, 0, agent_checksum, manager_checksum);
}

static void test_wdbi_update_completion_no_sql_done(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, agent_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, manager_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 1);
    will_return(__wrap_sqlite3_errmsg, "test_no_sql_done");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_no_sql_done");

    wdbi_update_completion(data, WDB_FIM, 0, agent_checksum, manager_checksum);
}

static void test_wdbi_update_completion_success(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";
    os_sha1 agent_checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";
    os_sha1 manager_checksum = "a1b976d41cfce3f216ef7ccef58dfb550d0dccbe";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, agent_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, manager_checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    wdbi_update_completion(data, WDB_FIM, 0, agent_checksum, manager_checksum);
}

// Test wdbi_query_clear
void test_wdbi_query_clear_null_payload(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char * payload = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse checksum range payload: '(null)'");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_invalid_payload(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char payload[] = "This is some test";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse checksum range payload: 'This is some test'");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_no_id(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char payload[] = "{\"Key\":\"Value\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'id' in JSON payload.");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_stmt_cache_error(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *payload = "{\"id\":5678}";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_sql_step_error(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *payload = "{\"id\":5678}";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_error");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: test_error");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_ok(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *component = "fim";
    const char *payload = "{\"id\":5678}";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 5678);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 5678);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, 0);
}

// Test wdbi_query_checksum
void test_wdbi_query_checksum_null_payload(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char * payload = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse checksum range payload: '(null)'");

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_ERR);
}

void test_wdbi_query_checksum_no_begin(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"Bad\":\"Payload\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'begin' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_ERR);
}

void test_wdbi_query_checksum_no_end(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'end' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_ERR);
}

void test_wdbi_query_checksum_no_checksum(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'checksum' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_ERR);
}

void test_wdbi_query_checksum_no_id(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'id' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_ERR);
}

void test_wdbi_query_checksum_range_fail(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    // wdbi_get_last_manager_checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_ERR);
}

void test_wdbi_query_checksum_range_no_data(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char *component = "fim";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    // wdbi_get_last_manager_checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101); //predelete
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101); //pre attemps
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    // wdbi_delete
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    // wdbi_update_attempt
    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 1234);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_NO_DATA);
}

void test_wdbi_query_checksum_diff_hexdigest(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    // wdbi_get_last_manager_checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");
    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_CKS_FAIL);
}

void test_wdbi_query_checksum_equal_hexdigest(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"id\":1234}";

    // wdbi_get_last_manager_checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_EVP_DigestUpdate, data, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_CKS_OK);
}

void test_wdbi_query_checksum_bad_action(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");
    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CLEAR, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_CKS_FAIL);
}

void test_wdbi_query_checksum_check_left_no_tail(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "something");
    expect_string(__wrap_EVP_DigestUpdate, data, "something");
    expect_value(__wrap_EVP_DigestUpdate, count, 9);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_LEFT, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_CKS_FAIL);
}

void test_wdbi_query_checksum_check_left_ok(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);

    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234,\"tail\":\"something\"}";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "something");
    expect_string(__wrap_EVP_DigestUpdate, data, "something");
    expect_value(__wrap_EVP_DigestUpdate, count, 9);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_LEFT, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_CKS_FAIL);
}

void test_wdbi_query_checksum_last_manager_success(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *component = "fim";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"id\":1234}";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();
    cJSON_AddStringToObject(j_object, "last_manager_checksum", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    cJSON_AddItemToArray(j_data, j_object);

    // wdbi_get_last_manager_checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '000' fim range checksum avoided.");

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_CKS_OK);
}

void test_wdbi_query_checksum_last_manager_diff(void **state) {
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *component = "fim";
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"id\":1234}";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();
    cJSON_AddStringToObject(j_object, "last_manager_checksum", "");
    cJSON_AddItemToArray(j_data, j_object);

    // wdbi_get_last_manager_checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_EVP_DigestUpdate, data, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, INTEGRITY_CHECK_GLOBAL, payload);

    assert_int_equal(ret, INTEGRITY_SYNC_CKS_OK);
}

// Test wdbi_get_last_manager_checksum
void test_wdbi_get_last_manager_checksum_success(void **state) {
    wdb_t *data = *state;
    const char *component = "fim_file";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();

    cJSON_AddStringToObject(j_object, "last_manager_checksum", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    cJSON_AddItemToArray(j_data, j_object);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    os_sha1 manager_checksum = {0};
    int ret_val = wdbi_get_last_manager_checksum(data, WDB_FIM_FILE, manager_checksum);

    assert_int_equal (ret_val, OS_SUCCESS);
    assert_string_equal(manager_checksum, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

void test_wdbi_get_last_manager_stmt_cache_fail(void **state) {
    wdb_t *data = *state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    os_sha1 manager_checksum = {0};
    int ret_val = wdbi_get_last_manager_checksum(data, WDB_FIM_FILE, manager_checksum);

    assert_int_equal (ret_val, OS_INVALID);
}

void test_wdbi_get_last_manager_exec_stmt_fail(void **state) {
    wdb_t *data = *state;
    const char *component = "fim_file";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "test_err");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): test_err");

    os_sha1 manager_checksum = {0};
    int ret_val = wdbi_get_last_manager_checksum(data, WDB_FIM_FILE, manager_checksum);

    assert_int_equal (ret_val, OS_INVALID);
}

// Test wdbi_array_hash
void test_wdbi_array_hash_success(void **state) {
    const char** test_words = NULL;
    int ret_val = -1;
    os_sha1 hexdigest;

    os_malloc(6 * sizeof(char*),test_words);

    test_words[0] = "FirstWord";
    test_words[1] = "SecondWord";
    test_words[2] = "Word number 3";
    test_words[3] = "";
    test_words[4] = " ";
    test_words[5]= NULL;

    // Using real EVP_DigestUpdate
    test_mode = 0;

    ret_val = wdbi_array_hash(test_words, hexdigest);

    assert_int_equal (ret_val, 0);
    assert_string_equal(hexdigest, "159a9a6e19ff891a8560376df65a078e064bd0ce");

    os_free(test_words);
}

void test_wdbi_array_hash_null(void **state) {
    int ret_val = -1;
    os_sha1 hexdigest;

    // Using real EVP_DigestUpdate
    test_mode = 0;

    ret_val = wdbi_array_hash(NULL, hexdigest);

    assert_int_equal (ret_val, 0);
    assert_string_equal(hexdigest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

// Test wdbi_strings_hash
void test_wdbi_strings_hash_success(void **state) {
    int ret_val = -1;
    os_sha1 hexdigest;

    // Using real EVP_DigestUpdate
    test_mode = 0;

    ret_val = wdbi_strings_hash(hexdigest, "FirstWord", "SecondWord", "Word number 3", "", " ", NULL);

    assert_int_equal (ret_val, 0);
    assert_string_equal(hexdigest, "159a9a6e19ff891a8560376df65a078e064bd0ce");
}

void test_wdbi_strings_hash_null(void **state) {
    int ret_val = -1;
    os_sha1 hexdigest;

    // Using real EVP_DigestUpdate
    test_mode = 0;

    ret_val = wdbi_strings_hash(hexdigest, NULL);

    assert_int_equal (ret_val, 0);
    assert_string_equal(hexdigest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

// Test wdbi_check_sync_status
void test_wdbi_check_sync_status_cache_failed(void **state) {
    int ret_val = OS_INVALID;
    wdb_t * data = *state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);

    assert_int_equal (ret_val, OS_INVALID);
}

void test_wdbi_check_sync_status_exec_failed(void **state) {
    int ret_val = OS_INVALID;
    wdb_t * data = *state;
    const char *component = "syscollector-packages";

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR_MESSAGE");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);
    assert_int_equal (ret_val, OS_INVALID);
}

void test_wdbi_check_sync_status_data_failed(void **state) {
    int ret_val = OS_INVALID;
    wdb_t * data = *state;
    const char *component = "syscollector-packages";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "last_attempt", 123456);
    cJSON_AddItemToArray(j_data, j_object);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Failed to get agent's sync status data");

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);

    assert_int_equal (ret_val, OS_INVALID);
}

void test_wdbi_check_sync_status_data_synced(void **state) {
    int ret_val = OS_INVALID;
    wdb_t * data = *state;
    const char *component = "syscollector-packages";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "last_attempt", 123456);
    cJSON_AddNumberToObject(j_object, "last_completion", 123456);
    cJSON_AddStringToObject(j_object, "last_agent_checksum", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    cJSON_AddItemToArray(j_data, j_object);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);

    assert_int_equal (ret_val, 1);
}

void test_wdbi_check_sync_status_data_never_synced_without_checksum(void **state) {
    int ret_val = OS_INVALID;
    wdb_t * data = *state;
    const char *component = "syscollector-packages";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "last_attempt", 123456);
    cJSON_AddNumberToObject(j_object, "last_completion", 0);
    cJSON_AddStringToObject(j_object, "last_agent_checksum", "");
    cJSON_AddItemToArray(j_data, j_object);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);

    assert_int_equal (ret_val, 0);
}

void test_wdbi_check_sync_status_data_not_synced_error_checksum(void **state) {
    int ret_val = OS_INVALID;
    wdb_t * data = *state;
    const char *component = "syscollector-packages";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "last_attempt", 123456);
    cJSON_AddNumberToObject(j_object, "last_completion", 123455);
    cJSON_AddStringToObject(j_object, "last_agent_checksum", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    cJSON_AddItemToArray(j_data, j_object);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    // Error calling to calculate checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);

    assert_int_equal (ret_val, -1);
}

void test_wdbi_check_sync_status_data_not_synced_checksum_no_data(void **state) {
    int ret_val = -1;
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "syscollector-packages";
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "last_attempt", 123456);
    cJSON_AddNumberToObject(j_object, "last_completion", 123455);
    cJSON_AddStringToObject(j_object, "last_agent_checksum", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    cJSON_AddItemToArray(j_data, j_object);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    // Calling to calculate checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);

    assert_int_equal (ret_val, 0);
}

void test_wdbi_check_sync_status_data_not_synced_checksum_valid(void **state) {
    int ret_val = -1;
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "syscollector-packages";
    unsigned int timestamp = 10000;
    cJSON* j_data = cJSON_CreateArray();
    cJSON* j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "last_attempt", 123456);
    cJSON_AddNumberToObject(j_object, "last_completion", 123455);
    cJSON_AddStringToObject(j_object, "last_agent_checksum", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    cJSON_AddItemToArray(j_data, j_object);

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_exec_stmt, j_data);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    // Calling to calculate checksum
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "da39a3ee5eda39a3ee5eda39a3ee5eda39a3ee5e");
    expect_string(__wrap_EVP_DigestUpdate, data, "da39a3ee5eda39a3ee5eda39a3ee5eda39a3ee5e");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_time, timestamp);

    // wdbi_set_last_completion
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, timestamp);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "syscollector-packages");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    ret_val = wdbi_check_sync_status(data, WDB_SYSCOLLECTOR_PACKAGES);

    assert_int_equal (ret_val, 1);
}

// Test wdbi_last_completion
void test_wdbi_last_completion_step_fail(void **state) {
    wdb_t * data = *state;
    data->id = strdup("000");
    unsigned int timestamp = 10000;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, timestamp);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "syscollector-packages");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: ERROR_MESSAGE");

    wdbi_set_last_completion(data, WDB_SYSCOLLECTOR_PACKAGES, timestamp);
}

// Test wdb_global_group_hash_cache

void test_wdb_global_group_hash_cache_clear_success(void **state)
{
    wdb_global_group_hash_operations_t operation = WDB_GLOBAL_GROUP_HASH_CLEAR;
    os_sha1 hexdigest;
    int ret;

    /* Storing a dummy hash value before clearing it */
    snprintf(global_group_hash, sizeof(global_group_hash), "bd612e9ae2faf8a44b387eeb9f3d5a5e577c8c64");

    ret = wdb_global_group_hash_cache(operation, hexdigest);

    assert_int_equal(global_group_hash[0], 0);
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_global_group_hash_cache_read_fail(void **state)
{
    wdb_global_group_hash_operations_t operation = WDB_GLOBAL_GROUP_HASH_READ;
    os_sha1 hexdigest;
    int ret;

    /* Clearing the variable before reading it */
    global_group_hash[0] = 0;

    ret = wdb_global_group_hash_cache(operation, hexdigest);

    assert_int_equal(global_group_hash[0], 0);
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_global_group_hash_cache_write_success(void **state)
{
    wdb_global_group_hash_operations_t operation = WDB_GLOBAL_GROUP_HASH_WRITE;
    os_sha1 hexdigest = "bd612e9ae2faf8a44b387eeb9f3d5a5e577c8c64";
    int ret;

    ret = wdb_global_group_hash_cache(operation, hexdigest);

    assert_string_equal(global_group_hash, hexdigest);
    assert_int_equal(ret, OS_SUCCESS);

    /* Clearing the variable after writing it */
    global_group_hash[0] = 0;
}

void test_wdb_global_group_hash_cache_read_success(void **state)
{
    wdb_global_group_hash_operations_t operation = WDB_GLOBAL_GROUP_HASH_READ;
    os_sha1 hexdigest;
    int ret;

    /* Storing a dummy hash value before reading it */
    snprintf(global_group_hash, sizeof(global_group_hash), "bd612e9ae2faf8a44b387eeb9f3d5a5e577c8c64");

    ret = wdb_global_group_hash_cache(operation, hexdigest);

    assert_string_equal(hexdigest, "bd612e9ae2faf8a44b387eeb9f3d5a5e577c8c64");
    assert_int_equal(ret, OS_SUCCESS);

    /* Clearing the variable after reading it */
    global_group_hash[0] = 0;
}

void test_wdb_global_group_hash_cache_invalid_mode(void **state)
{
    wdb_global_group_hash_operations_t operation = 3;
    os_sha1 hexdigest;
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "Invalid mode for global group hash operation.");

    ret = wdb_global_group_hash_cache(operation, hexdigest);

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_get_global_group_hash

void wdb_get_global_group_hash_read_success(void **state)
{
    wdb_t * data = *state;
    os_sha1 hexdigest;
    int ret;

    /* Storing a dummy hash value before reading it */
    snprintf(global_group_hash, sizeof(global_group_hash), "bd612e9ae2faf8a44b387eeb9f3d5a5e577c8c64");

    expect_string(__wrap__mdebug2, formatted_msg, "Using global group hash from cache");

    ret = wdb_get_global_group_hash(data, hexdigest);

    assert_int_equal(ret, OS_SUCCESS);

    /* Clearing the variable after reading it */
    global_group_hash[0] = 0;
}

void wdb_get_global_group_hash_invalid_db_structure(void **state)
{
    os_sha1 hexdigest;
    int ret;

    /* Clearing the variable before reading it */
    global_group_hash[0] = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "Database structure not initialized. Unable to calculate global group hash.");

    ret = wdb_get_global_group_hash(NULL, hexdigest);

    assert_int_equal(ret, OS_INVALID);
}

void wdb_get_global_group_hash_invalid_statement(void **state)
{
    wdb_t * data = *state;
    os_sha1 hexdigest;
    int ret;

    /* Clearing the variable before reading it */
    global_group_hash[0] = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_HASH_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    ret = wdb_get_global_group_hash(data, hexdigest);

    assert_int_equal(ret, OS_INVALID);
}

void wdb_get_global_group_hash_calculate_success_no_group_hash_information(void **state)
{
    wdb_t * data = *state;
    os_sha1 hexdigest;
    int ret;

    /* Clearing the variable before reading it */
    global_group_hash[0] = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_HASH_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return(__wrap_sqlite3_step, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    expect_string(__wrap__mdebug2, formatted_msg, "No group hash was found to calculate the global group hash.");

    ret = wdb_get_global_group_hash(data, hexdigest);

    assert_int_equal(ret, OS_SUCCESS);
}

void wdb_get_global_group_hash_calculate_success(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 hexdigest;
    int ret;

    /* Clearing the variable before reading it */
    global_group_hash[0] = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_HASH_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, 1);

    will_return(__wrap_sqlite3_step, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);
    will_return(__wrap_sqlite3_step, SQLITE_OK);
    will_return(__wrap_sqlite3_step, SQLITE_OK);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL  checksum.");
    expect_string(__wrap__mdebug2, formatted_msg, "New global group hash calculated and stored in cache.");

    ret = wdb_get_global_group_hash(data, hexdigest);

    assert_int_equal(ret, OS_SUCCESS);
}

// Tests wdbi_report_removed

void test_wdbi_report_removed_no_handle(void **state) {
    const char* agent_id = "001";
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;
    sqlite3_stmt* stmt = NULL;
    router_agent_events_handle = NULL;

    expect_string(__wrap__mdebug2, formatted_msg, "Router handle not available.");

    wdbi_report_removed(agent_id, component, stmt);
}

void test_wdbi_report_removed_packages_success(void **state) {
    const char* agent_id = "001";
    wdb_component_t component = WDB_SYSCOLLECTOR_PACKAGES;
    sqlite3_stmt* stmt = NULL;
    router_inventory_events_handle = (ROUTER_PROVIDER_HANDLE)1;
    const char* expected_message = "{\"agent_info\":{\"agent_id\":\"001\"},\"action\":\"deletePackage\","
                                   "\"data\":{\"name\":\"name\",\"version\":\"version\",\"architecture\":\"architecture\",\"format\":\"format\",\"location\":\"location\",\"item_id\":\"item_id\"}}";

    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "name");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "version");
    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "architecture");
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "format");
    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, "location");
    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, "item_id");

    expect_string(__wrap_router_provider_send, message, expected_message);
    expect_value(__wrap_router_provider_send, message_size, strlen(expected_message));
    will_return(__wrap_router_provider_send, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wdbi_report_removed(agent_id, component, stmt);
}

void test_wdbi_report_removed_hotfixes_success(void **state) {
    const char* agent_id = "001";
    wdb_component_t component = WDB_SYSCOLLECTOR_HOTFIXES;
    sqlite3_stmt* stmt = NULL;
    router_inventory_events_handle = (ROUTER_PROVIDER_HANDLE)1;
    const char* expected_message = "{\"agent_info\":{\"agent_id\":\"001\"},\"action\":\"deleteHotfix\","
                                   "\"data\":{\"hotfix\":\"hotfix\"}}";

    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "hotfix");

    expect_string(__wrap_router_provider_send, message, expected_message);
    expect_value(__wrap_router_provider_send, message_size, strlen(expected_message));
    will_return(__wrap_router_provider_send, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wdbi_report_removed(agent_id, component, stmt);
}

void test_wdbi_report_removed_hotfixes_success_multiple_steps(void **state) {
    const char* agent_id = "001";
    wdb_component_t component = WDB_SYSCOLLECTOR_HOTFIXES;
    sqlite3_stmt* stmt = NULL;
    router_inventory_events_handle = (ROUTER_PROVIDER_HANDLE)1;
    const char* expected_message_1 = "{\"agent_info\":{\"agent_id\":\"001\"},\"action\":\"deleteHotfix\","
                                     "\"data\":{\"hotfix\":\"hotfix1\"}}";

    const char* expected_message_2 = "{\"agent_info\":{\"agent_id\":\"001\"},\"action\":\"deleteHotfix\","
                                     "\"data\":{\"hotfix\":\"hotfix2\"}}";

    // First hotfix
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "hotfix1");

    expect_string(__wrap_router_provider_send, message, expected_message_1);
    expect_value(__wrap_router_provider_send, message_size, strlen(expected_message_1));
    will_return(__wrap_router_provider_send, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    // Second hotfix

    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "hotfix2");

    expect_string(__wrap_router_provider_send, message, expected_message_2);
    expect_value(__wrap_router_provider_send, message_size, strlen(expected_message_2));
    will_return(__wrap_router_provider_send, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    wdbi_report_removed(agent_id, component, stmt);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        //Test wdb_calculate_stmt_checksum
        cmocka_unit_test(test_wdb_calculate_stmt_checksum_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_stmt_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_cks_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_no_row, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_duplicate_entries_found, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_checksum_range
        cmocka_unit_test(test_wdbi_checksum_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_hexdigest_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_success, setup_wdb_t, teardown_wdb_t),
        // wdbi_remove_by_pk
        cmocka_unit_test(test_wdbi_remove_by_pk_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdbi_remove_by_pk_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_remove_by_pk_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_remove_by_pk_sqlite_bind_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_remove_by_pk_sqlite_step_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_remove_by_pk_success, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_checksum_range
        cmocka_unit_test(test_wdbi_checksum_range_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_hexdigest_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_begin_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_end_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_success, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_delete
        cmocka_unit_test(test_wdbi_delete_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_begin_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_end_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_tail_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_sql_no_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_success, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_update_attempt
        cmocka_unit_test(test_wdbi_update_attempt_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_no_sql_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_success, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_update_completion
        cmocka_unit_test(test_wdbi_update_completion_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_no_sql_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_success, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_query_clear
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_null_payload, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_invalid_payload, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_no_id, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_stmt_cache_error, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_sql_step_error, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_ok, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_query_checksum
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_null_payload, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_begin, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_end, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_checksum, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_id, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_range_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_range_no_data, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_diff_hexdigest, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_equal_hexdigest, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_bad_action, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_check_left_no_tail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_check_left_ok, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_last_manager_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_last_manager_diff, setup_wdb_t, teardown_wdb_t),
        // Test wdbi_get_last_manager_checksum
        cmocka_unit_test_setup_teardown(test_wdbi_get_last_manager_checksum_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_get_last_manager_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_get_last_manager_exec_stmt_fail, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_array_hash
        cmocka_unit_test_setup_teardown(test_wdbi_array_hash_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_array_hash_null, setup_wdb_t, teardown_wdb_t),
        //Test wdbi_strings_hash
        cmocka_unit_test_setup_teardown(test_wdbi_strings_hash_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_strings_hash_null, setup_wdb_t, teardown_wdb_t),
        // Test wdbi_check_sync_status
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_cache_failed, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_exec_failed, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_data_failed, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_data_synced, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_data_never_synced_without_checksum, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_data_not_synced_error_checksum, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_data_not_synced_checksum_no_data, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_check_sync_status_data_not_synced_checksum_valid, setup_wdb_t, teardown_wdb_t),
        // Test wdbi_last_completion
        cmocka_unit_test_setup_teardown(test_wdbi_last_completion_step_fail, setup_wdb_t, teardown_wdb_t),

        // Test wdb_global_group_hash_cache
        cmocka_unit_test(test_wdb_global_group_hash_cache_clear_success),
        cmocka_unit_test(test_wdb_global_group_hash_cache_read_fail),
        cmocka_unit_test(test_wdb_global_group_hash_cache_write_success),
        cmocka_unit_test(test_wdb_global_group_hash_cache_read_success),
        cmocka_unit_test(test_wdb_global_group_hash_cache_invalid_mode),

        // Test wdb_get_global_group_hash
        cmocka_unit_test_setup_teardown(wdb_get_global_group_hash_read_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(wdb_get_global_group_hash_invalid_db_structure, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(wdb_get_global_group_hash_invalid_statement, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(wdb_get_global_group_hash_calculate_success_no_group_hash_information, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(wdb_get_global_group_hash_calculate_success, setup_wdb_t, teardown_wdb_t),

        // Tests wdbi_report_removed
        cmocka_unit_test(test_wdbi_report_removed_no_handle),
        cmocka_unit_test(test_wdbi_report_removed_packages_success),
        cmocka_unit_test(test_wdbi_report_removed_hotfixes_success),
        cmocka_unit_test(test_wdbi_report_removed_hotfixes_success_multiple_steps),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
