/*
 * Copyright (C) 2015, Wazuh Inc.
 * March, 2021.
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
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "wazuhdb_op.h"

cJSON * wdb_dbsync_stmt_bind_from_json(sqlite3_stmt * stmt, int index, field_type_t type, const cJSON * value, const char * field_name,
                                       const char * table_name, bool convert_empty_string_as_null);
const char * wdb_dbsync_translate_field(const struct field * field);
cJSON * wdb_dbsync_get_field_default(const struct field * field);

#define ANY_PTR_VALUE 1
#define TEST_INDEX    1
#define HWINFO_TABLE "sys_hwinfo"
#define USERS_TABLE "sys_users"

/* wdb_dbsync_stmt_bind_from_json */

void test_wdb_dbsync_stmt_bind_from_json_null_inputs(void ** state) {
    assert_false(wdb_dbsync_stmt_bind_from_json(NULL, TEST_INDEX, FIELD_TEXT, (cJSON *) ANY_PTR_VALUE, "", "", true));
    assert_false(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, NULL, "", "", true));
    assert_false(wdb_dbsync_stmt_bind_from_json(NULL, TEST_INDEX, FIELD_TEXT, NULL, "", "", true));
}

void test_wdb_dbsync_stmt_bind_from_json_value_contains_null_ok(void ** state) {
    cJSON * value = cJSON_CreateNull();
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}
void test_wdb_dbsync_stmt_bind_from_json_value_contains_null_fail(void ** state) {
    cJSON * value = cJSON_CreateNull();
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_ERROR);
    assert_false(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}
void test_wdb_dbsync_stmt_bind_from_json_string_to_text_empty_canbenull_ok(void ** state) {
    cJSON * value = cJSON_CreateString("");
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}
void test_wdb_dbsync_stmt_bind_from_json_string_to_text_empty_canbenull_err(void ** state) {
    cJSON * value = cJSON_CreateString("");
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_ERROR);
    assert_false(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_text_not_empty_canbenull_err(void ** state) {
    cJSON * value = cJSON_CreateNull();
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_ERROR);
    assert_false(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}
void test_wdb_dbsync_stmt_bind_from_json_string_to_text_not_empty_cannotbenull_ok(void ** state) {
    cJSON * value = cJSON_CreateString("test string");
    expect_value(__wrap_sqlite3_bind_text, pos, TEST_INDEX);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test string");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_integer_to_text_ok(void ** state) {
    cJSON * value = cJSON_CreateNumber(12345);
    expect_value(__wrap_sqlite3_bind_text, pos, TEST_INDEX);
    expect_string(__wrap_sqlite3_bind_text, buffer, "12345");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_real_to_text_ok(void ** state) {
    cJSON * value = cJSON_CreateNumber(3.141592);
    expect_value(__wrap_sqlite3_bind_text, pos, TEST_INDEX);
    expect_string(__wrap_sqlite3_bind_text, buffer, "3.141592");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_TEXT, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_integer_ok(void ** state) {
    cJSON * value = cJSON_CreateString("12345");
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 12345);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_integer_err_conversion(void ** state) {
    cJSON * value = cJSON_CreateString("10Hz");
    assert_false(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_integer_err_stmt(void ** state) {
    cJSON * value = cJSON_CreateString("12345");
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 12345);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    assert_false(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_integer_to_integer_ok(void ** state) {
    cJSON * value = cJSON_CreateNumber(12345);
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 12345);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_integer_to_integer_err_stmt(void ** state) {
    cJSON * value = cJSON_CreateNumber(12345);
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 12345);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    assert_false(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_real_to_integer_ok(void ** state) {
    cJSON * value = cJSON_CreateNumber(3.14156);
    expect_value(__wrap_sqlite3_bind_int, pos, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, index, 3.14156);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    assert_false(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_long_ok(void ** state) {
    cJSON * value = cJSON_CreateString("123456789");
    expect_value(__wrap_sqlite3_bind_int64, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int64, value, 123456789);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_OK);
    assert_true(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER_LONG, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_long_err(void ** state) {
    cJSON * value = cJSON_CreateString("123456789Hz");
    assert_false(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER_LONG, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_long_err_stmt(void ** state) {
    cJSON * value = cJSON_CreateString("123456789");
    expect_value(__wrap_sqlite3_bind_int64, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int64, value, 123456789);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_ERROR);
    assert_false(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER_LONG, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_integer_to_long(void ** state) {
    cJSON * value = cJSON_CreateNumber(123456789);
    expect_value(__wrap_sqlite3_bind_int64, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int64, value, 123456789);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_OK);
    assert_true(
        wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER_LONG, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_real_ok(void ** state) {
    cJSON * value = cJSON_CreateString("3.141592");
    expect_value(__wrap_sqlite3_bind_double, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_double, value, 3.141592);
    will_return(__wrap_sqlite3_bind_double, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_REAL, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_string_to_real_err(void ** state) {
    cJSON * value = cJSON_CreateString("3.141592");
    expect_value(__wrap_sqlite3_bind_double, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_double, value, 3.141592);
    will_return(__wrap_sqlite3_bind_double, SQLITE_ERROR);
    assert_false(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_REAL, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_integer_to_real_ok(void ** state) {
    cJSON * value = cJSON_CreateNumber(12345);
    expect_value(__wrap_sqlite3_bind_double, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_double, value, 12345);
    will_return(__wrap_sqlite3_bind_double, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_REAL, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_from_json_integer_to_real_err(void ** state) {
    cJSON * value = cJSON_CreateNumber(12345);
    expect_value(__wrap_sqlite3_bind_double, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_double, value, 12345);
    will_return(__wrap_sqlite3_bind_double, SQLITE_ERROR);
    assert_false(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_REAL, value, "", "", true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_cpu_mhz_from_negative_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(-1);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_REAL, value, "cpu_mhz", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_cpu_cores_from_negative_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(-1);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "cpu_cores", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_free_from_negative_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(-1);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_free", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_total_from_negative_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(-1);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_total", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_negative_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(-1);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_usage", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_cpu_mhz_from_zero_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(0);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_REAL, value, "cpu_mhz", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_cpu_cores_from_zero_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(0);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "cpu_cores", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_free_from_zero_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(0);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_free", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_total_from_zero_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(0);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_total", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_zero_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(0);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_usage", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_over_onehundred_value_to_null (void **state) {
    cJSON * value = cJSON_CreateNumber(101);
    expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_usage", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_cpu_mhz_from_valid_value_to_number (void **state) {
    cJSON * value = cJSON_CreateNumber(100);
    expect_value(__wrap_sqlite3_bind_double, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_double, value, 100);
    will_return(__wrap_sqlite3_bind_double, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_REAL, value, "cpu_mhz", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_cpu_cores_from_valid_value_to_number (void **state) {
    cJSON * value = cJSON_CreateNumber(100);
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 100);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "cpu_cores", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_free_from_valid_value_to_number (void **state) {
    cJSON * value = cJSON_CreateNumber(100);
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 100);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_free", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_total_from_valid_value_to_number (void **state) {
    cJSON * value = cJSON_CreateNumber(100);
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 100);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_total", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

void test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_valid_value_to_number (void **state) {
    cJSON * value = cJSON_CreateNumber(100);
    expect_value(__wrap_sqlite3_bind_int, index, TEST_INDEX);
    expect_value(__wrap_sqlite3_bind_int, value, 100);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, "ram_usage", HWINFO_TABLE, true));
    cJSON_Delete(value);
}

/* wdb_dbsync_stmt_bind_from_json for users */
void test_wdb_dbsync_stmt_bind_users_multiple_fields_from_negative_value_to_null(void **state) {
    cJSON * value = cJSON_CreateNumber(-1);
    const char * fields[] = {
        "user_id",
        "user_group_id",
        "user_auth_failures_count",
        "user_password_max_days_between_changes",
        "user_password_min_days_between_changes",
        "user_password_warning_days_before_expiration", 
        "process_pid"
    };
    for (int i = 0; i < (sizeof(fields)/sizeof(fields[0])); ++i) {
        expect_value(__wrap_sqlite3_bind_null, index, TEST_INDEX);
        will_return(__wrap_sqlite3_bind_null, SQLITE_OK);
        assert_true(wdb_dbsync_stmt_bind_from_json((sqlite3_stmt *) ANY_PTR_VALUE, TEST_INDEX, FIELD_INTEGER, value, fields[i], USERS_TABLE, true));
    }

    cJSON_Delete(value);  
}

/* wdb_upsert_dsync */

void test_wdb_upsert_dbsync_err(void ** state) {
    assert_false(wdb_upsert_dbsync(NULL, (struct kv *) ANY_PTR_VALUE, (cJSON *) ANY_PTR_VALUE));
    assert_false(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, NULL, (cJSON *) ANY_PTR_VALUE));
    assert_false(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, (struct kv *) ANY_PTR_VALUE, NULL));
}

void test_wdb_upsert_dbsync_bad_cache(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        {.value = {FIELD_INTEGER, 1, true, false, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, false, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        {.value = {FIELD_INTEGER, 3, true, false, NULL, "test_3", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    will_return(__wrap_wdb_get_cache_stmt, NULL);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, (cJSON *) ANY_PTR_VALUE));
}

void test_wdb_upsert_dbsync_stmt_nok(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234,\"test_4\":\"value_4\"}");
    wdb_t db = {.id = "test-db"};
    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg,
                  "(5216): DB(test-db) Could not bind delta field 'test_1' from 'table_origin_name' scan.");
    assert_false(wdb_upsert_dbsync(&db, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_upsert_dbsync_field_stmt_nok(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234,\"test_4\":\"value_4\"}");
    wdb_t db = {.id = "test-db"};

    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_2");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_4");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    // Not PKs or Aux fields
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_4");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg,
                  "(5216): DB(test-db) Could not bind delta field 'test_4' from 'table_origin_name' scan.");
    assert_false(wdb_upsert_dbsync(&db, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_upsert_dbsync_step_nok(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234,\"test_4\":\"value_4\"}");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_2");
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_4");
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    // Not PKs or Aux fields
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_4");
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    assert_false(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_upsert_dbsync_ok(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234,\"test_4\":\"value_4\"}");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_2");
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_4");
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    // Not PKs or Aux fields
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_4");
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_upsert_dbsync_default_regular_field_canbenull(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234}");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_null, SQLITE_OK);

    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_2");
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    expect_value(__wrap_sqlite3_bind_null, index, 4);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    // Not PKs or Aux fields
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_upsert_dbsync_default_regular_field_cannotbenull(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, false}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234}");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_2");
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    // Not PKs or Aux fields
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_upsert_dbsync_packages_not_present_pk_field (void **state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs.
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        { .value = { FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, false}, .next = &TEST_FIELDS[2] },
        // Regular field.
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"packages", "sys_programs", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_3\":1234}");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    // Not PKs or Aux fields
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_upsert_dbsync_packages_null_pk_field (void **state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs.
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        { .value = { FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, false}, .next = &TEST_FIELDS[2] },
        // Regular field.
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"packages", "sys_programs", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":null,\"test_3\":1234}");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    // Not PKs or Aux fields
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1234);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_upsert_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

//
// wdb_delete_dbsync
//

void test_wdb_delete_dbsync_err(void ** state) {
    assert_false(wdb_delete_dbsync(NULL, (struct kv *) ANY_PTR_VALUE, (cJSON *) ANY_PTR_VALUE));
    assert_false(wdb_delete_dbsync((wdb_t *) ANY_PTR_VALUE, NULL, (cJSON *) ANY_PTR_VALUE));
    assert_false(wdb_delete_dbsync((wdb_t *) ANY_PTR_VALUE, (struct kv *) ANY_PTR_VALUE, NULL));
}

void test_wdb_delete_dbsync_bad_cache(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    will_return(__wrap_wdb_get_cache_stmt, NULL);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_delete_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, (cJSON *) ANY_PTR_VALUE));
}

void test_wdb_delete_dbsync_step_nok(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234,\"test_4\":\"value_4\"}");
    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_2");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    assert_false(wdb_delete_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_delete_dbsync_stmt_nok(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234,\"test_4\":\"value_4\"}");
    wdb_t db = {.id = "test-db"};
    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg,
                  "(5216): DB(test-db) Could not bind delta field 'test_1' from 'table_origin_name' scan.");
    assert_false(wdb_delete_dbsync(&db, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_delete_dbsync_ok(void ** state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        {.value = {FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, true}, .next = &TEST_FIELDS[2]},
        // Regular fields
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = &TEST_FIELDS[3]},
        {.value = {FIELD_TEXT, 5, false, false, NULL, "test_4", {.text = ""}, true}, .next = &TEST_FIELDS[4]},
        // Old values
        {.value = {FIELD_INTEGER, 6, true, false, NULL, "test_5", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"table_origin_name", "table_target_name", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":\"value_2\",\"test_3\":1234,\"test_4\":\"value_4\"}");
    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "value_2");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_delete_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_delete_dbsync_packages_not_present_pk_field (void **state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs.
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        { .value = { FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, false}, .next = &TEST_FIELDS[2] },
        // Regular field.
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"packages", "sys_programs", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_3\":1234}");
    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_delete_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

void test_wdb_delete_dbsync_packages_null_pk_field (void **state) {
    struct column_list const TEST_FIELDS[] = {
        // PKs.
        {.value = {FIELD_INTEGER, 1, false, true, NULL, "test_1", {.integer = 0}, true}, .next = &TEST_FIELDS[1]},
        { .value = { FIELD_TEXT, 2, false, true, NULL, "test_2", {.text = ""}, false}, .next = &TEST_FIELDS[2] },
        // Regular field.
        {.value = {FIELD_INTEGER, 3, false, false, NULL, "test_3", {.integer = 0}, true}, .next = NULL},
    };

    struct kv const TEST_TABLE = {"packages", "sys_programs", false, TEST_FIELDS};

    cJSON * delta = cJSON_Parse("{\"test_1\":4321,\"test_2\":null,\"test_3\":1234}");
    will_return(__wrap_wdb_get_cache_stmt, (sqlite3_stmt *) ANY_PTR_VALUE);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 4321);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    assert_true(wdb_delete_dbsync((wdb_t *) ANY_PTR_VALUE, &TEST_TABLE, delta));
    cJSON_Delete(delta);
}

/* wdb_dbsync_get_field_default */

void test_wdb_dbsync_get_field_default_null(void ** state) { assert_null(wdb_dbsync_get_field_default(NULL)); }

void test_wdb_dbsync_get_field_default_text(void ** state) {
    struct field test_field = {.type = FIELD_TEXT, .default_value.text = "test"};
    cJSON * retval = wdb_dbsync_get_field_default(&test_field);
    assert_non_null(retval);
    assert_string_equal(cJSON_GetStringValue(retval), "test");
    cJSON_Delete(retval);
}

void test_wdb_dbsync_get_field_default_invalid_type(void ** state) {
    struct field test_field = {.type = (field_type_t) 1234, .default_value.text = "test"};
    expect_string(__wrap__mdebug2, formatted_msg, "Invalid syscollector field type: 1234");
    assert_null(wdb_dbsync_get_field_default(&test_field));
}

void test_wdb_dbsync_get_field_default_integer(void ** state) {
    struct field test_field = {.type = FIELD_INTEGER, .default_value.integer = 1234};
    cJSON * retval = wdb_dbsync_get_field_default(&test_field);
    assert_non_null(retval);
    assert_int_equal(retval->valueint, 1234);
    cJSON_Delete(retval);
}

void test_wdb_dbsync_get_field_default_real(void ** state) {
    struct field test_field = {.type = FIELD_REAL, .default_value.real = 3.14159265};
    cJSON * retval = wdb_dbsync_get_field_default(&test_field);
    assert_non_null(retval);
    assert_float_equal(retval->valuedouble, 3.14159265, 0.001);
    cJSON_Delete(retval);
}

void test_wdb_dbsync_get_field_default_long(void ** state) {
    struct field test_field = {.type = FIELD_INTEGER_LONG, .default_value.integer_long = LONG_MAX};
    cJSON * retval = wdb_dbsync_get_field_default(&test_field);
    assert_non_null(retval);
    assert_float_equal(retval->valuedouble, LONG_MAX, 0.001);
    cJSON_Delete(retval);
}

/* wdb_dbsync_translate_field */

void test_wdb_dbsync_translate_field_not_translated(void ** state) {
    struct field test_field = {.source_name = NULL, .target_name = "db_field_name"};
    assert_string_equal(wdb_dbsync_translate_field(&test_field), "db_field_name");
}

void test_wdb_dbsync_translate_field_translated(void ** state) {
    struct field test_field = {.source_name = "delta_field_name", .target_name = "db_field_name"};
    assert_string_equal(wdb_dbsync_translate_field(&test_field), "delta_field_name");
}

int main() {
    const struct CMUnitTest tests[] = {
        /* wdb_dbsync_get_field_default */
        cmocka_unit_test(test_wdb_dbsync_get_field_default_null),
        cmocka_unit_test(test_wdb_dbsync_get_field_default_text),
        cmocka_unit_test(test_wdb_dbsync_get_field_default_integer),
        cmocka_unit_test(test_wdb_dbsync_get_field_default_real),
        cmocka_unit_test(test_wdb_dbsync_get_field_default_long),
        cmocka_unit_test(test_wdb_dbsync_get_field_default_invalid_type),
        /* wdb_dbsync_translate_field */
        cmocka_unit_test(test_wdb_dbsync_translate_field_not_translated),
        cmocka_unit_test(test_wdb_dbsync_translate_field_translated),
        /* wdb_dbsync_stmt_bind_from_json */
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_null_inputs),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_value_contains_null_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_value_contains_null_fail),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_text_empty_canbenull_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_text_empty_canbenull_err),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_text_not_empty_canbenull_err),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_text_not_empty_cannotbenull_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_integer_to_text_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_real_to_text_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_integer_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_integer_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_integer_err_conversion),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_integer_err_stmt),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_integer_to_integer_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_integer_to_integer_err_stmt),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_real_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_real_err),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_integer_to_real_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_integer_to_real_err),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_long_err_stmt),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_long_ok),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_string_to_long_err),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_json_integer_to_long),
        // wdb_dbsync_stmt_bind_from_json for hwinfo
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_cpu_mhz_from_negative_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_cpu_cores_from_negative_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_free_from_negative_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_total_from_negative_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_negative_value_to_null),

        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_cpu_mhz_from_zero_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_cpu_cores_from_zero_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_free_from_zero_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_total_from_zero_value_to_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_zero_value_to_null),

        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_over_onehundred_value_to_null),

        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_cpu_mhz_from_valid_value_to_number),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_cpu_cores_from_valid_value_to_number),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_free_from_valid_value_to_number),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_total_from_valid_value_to_number),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_hwinfo_ram_usage_from_valid_value_to_number),
        // wdb_dbsync_stmt_bind_from_json for users
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_users_multiple_fields_from_negative_value_to_null),
        /* wdb_upsert_dbsync */
        cmocka_unit_test(test_wdb_upsert_dbsync_err),
        cmocka_unit_test(test_wdb_upsert_dbsync_bad_cache),
        cmocka_unit_test(test_wdb_upsert_dbsync_stmt_nok),
        cmocka_unit_test(test_wdb_upsert_dbsync_field_stmt_nok),
        cmocka_unit_test(test_wdb_upsert_dbsync_step_nok),
        cmocka_unit_test(test_wdb_upsert_dbsync_ok),
        cmocka_unit_test(test_wdb_upsert_dbsync_default_regular_field_canbenull),
        cmocka_unit_test(test_wdb_upsert_dbsync_default_regular_field_cannotbenull),
        cmocka_unit_test(test_wdb_upsert_dbsync_packages_not_present_pk_field),
        cmocka_unit_test(test_wdb_upsert_dbsync_packages_null_pk_field),
        /* wdb_delete_dbsync */
        cmocka_unit_test(test_wdb_delete_dbsync_err), cmocka_unit_test(test_wdb_delete_dbsync_bad_cache),
        cmocka_unit_test(test_wdb_delete_dbsync_step_nok), cmocka_unit_test(test_wdb_delete_dbsync_ok),
        cmocka_unit_test(test_wdb_delete_dbsync_stmt_nok),
        cmocka_unit_test(test_wdb_delete_dbsync_packages_not_present_pk_field),
        cmocka_unit_test(test_wdb_delete_dbsync_packages_null_pk_field),
        };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
