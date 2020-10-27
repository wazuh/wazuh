/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"

static const char* VALID_ENTRY = "{"
    "\"path\": \"/test\",\n"
    "\"timestamp\": 10,\n"
    "\"attributes\": {}\n"
    "}"
;

/* setup/teardown */
static int setup_wdb_t(void **state) {
    wdb_t *data = calloc(1, sizeof(wdb_t));

    if(!data) {
        return -1;
    }

    *state = data;
    return 0;
}

static int teardown_wdb_t(void **state) {
    wdb_t *data = *state;

    if(data) {
        os_free(data->id);
        os_free(data);
    }

    return 0;
}

/* tests */

static void test_wdb_syscheck_save2_wbs_null(void **state)
{
    (void) state; /* unused */
    int ret;
    expect_string(__wrap__merror, formatted_msg, "WDB object cannot be null.");
    ret = wdb_syscheck_save2(NULL, "{}");
    assert_int_equal(ret, -1);

}

static void test_wdb_syscheck_save2_payload_null(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse FIM payload: '(null)'");
    ret = wdb_syscheck_save2(wdb, NULL);
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_data_null(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    will_return(__wrap_wdb_begin2, 0);
    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Can't insert file entry.");
    ret = wdb_syscheck_save2(wdb, "{}");
    assert_int_equal(ret, -1);

}

static void test_wdb_syscheck_save2_fail_transaction(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    wdb->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Can't begin transaction.");
    ret = wdb_syscheck_save2(wdb, "{}");
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_fail_file_entry(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    wdb->transaction = 1;
    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Can't insert file entry.");
    const char *entry =
    "{"
    "\"timestamp\": \"123456789\"\n"
    "}"
    ;
    ret = wdb_syscheck_save2(wdb, entry);
    assert_int_equal(ret, -1);
}


static void test_wdb_syscheck_save2_success(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    wdb->transaction = 1;
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "/test");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 10);
    will_return(__wrap_sqlite3_bind_int64,0);
    will_return(__wrap_sqlite3_step,101);
    ret = wdb_syscheck_save2(wdb, VALID_ENTRY);
    assert_int_equal(ret, 0);
}


static void test_wdb_fim_insert_entry2_wdb_null(void **state)
{
    (void) state; /* unused */
    int ret;
    expect_string(__wrap__merror, formatted_msg, "WDB object cannot be null.");
    cJSON * data = cJSON_Parse(VALID_ENTRY);
    ret = wdb_fim_insert_entry2(NULL, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_data_null(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");
    ret = wdb_fim_insert_entry2(wdb, NULL);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_path_null(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    cJSON* data = cJSON_CreateObject();
    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_timestamp_null(void **state)
{
    int ret;
    cJSON* data;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    data = cJSON_Parse(VALID_ENTRY);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, false);
    cJSON_ReplaceItemInObject(data, "timestamp", cJSON_CreateString(""));
    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no timestamp path argument.");
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_attributes_null(void **state)
{
    int ret;
    cJSON* data;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    data = cJSON_Parse(VALID_ENTRY);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, false);
    cJSON_ReplaceItemInObject(data, "attributes", cJSON_CreateString(""));
    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no valid attributes.");
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_cache(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, -1);
    cJSON *data = cJSON_Parse(VALID_ENTRY);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Can't cache statement");
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_null(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();
    cJSON_AddItemToObject(array, "inode", cJSON_CreateObject());
    cJSON_ReplaceItemInObject(data, "attributes", array);
    data->child->next->next->child->string = NULL;
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "/test");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 10);
    will_return(__wrap_sqlite3_bind_int64,0);
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_string(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();
    cJSON_AddItemToObject(array, "invalid_attribute", cJSON_CreateString("sasssss"));
    cJSON_ReplaceItemInObject(data, "attributes", array);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "/test");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 10);
    will_return(__wrap_sqlite3_bind_int64,0);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Invalid attribute name: invalid_attribute");
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_number(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();
    cJSON_AddItemToObject(array, "invalid_attribute", cJSON_CreateNumber(1000));
    cJSON_ReplaceItemInObject(data, "attributes", array);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "/test");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 10);
    will_return(__wrap_sqlite3_bind_int64,0);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Invalid attribute name: invalid_attribute");
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_sqlite3_stmt(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "/test");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 10);
    will_return(__wrap_sqlite3_bind_int64,0);
    will_return(__wrap_sqlite3_step,0);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): out of memory");
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_success(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *object = cJSON_CreateObject();

    cJSON_AddItemToObject(object, "size", cJSON_CreateNumber(2048));
    cJSON_AddItemToObject(object, "mtime", cJSON_CreateNumber(10));
    cJSON_AddItemToObject(object, "inode", cJSON_CreateNumber(2));
    cJSON_AddItemToObject(object, "type", cJSON_CreateString("test_type"));
    cJSON_AddItemToObject(object, "perm", cJSON_CreateString("yes"));
    cJSON_AddItemToObject(object, "uid", cJSON_CreateString("00000"));
    cJSON_AddItemToObject(object, "gid", cJSON_CreateString("AAAAA"));
    cJSON_AddItemToObject(object, "hash_md5", cJSON_CreateString("AAAA23BCD1113A"));
    cJSON_AddItemToObject(object, "hash_sha1", cJSON_CreateString("AAAA23BCD1113A"));
    cJSON_AddItemToObject(object, "user_name", cJSON_CreateString("user"));
    cJSON_AddItemToObject(object, "group_name", cJSON_CreateString("group"));
    cJSON_AddItemToObject(object, "hash_sha256", cJSON_CreateString("AAAA23BCD1113AASDASDASD"));
    cJSON_AddItemToObject(object, "symbolic_path", cJSON_CreateString("/path/second-path"));
    cJSON_AddItemToObject(object, "checksum", cJSON_CreateString("GGGGGGGGGGGG"));
    cJSON_AddItemToObject(object, "attributes", cJSON_CreateString("readonly"));
    cJSON_ReplaceItemInObject(data, "attributes", object);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 2048);
    expect_value(__wrap_sqlite3_bind_int, index, 12);
    expect_value(__wrap_sqlite3_bind_int, value, 10);
    will_return_count(__wrap_sqlite3_bind_int, 0, 2);

    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 10);
    will_return(__wrap_sqlite3_bind_int64,0);
    will_return(__wrap_sqlite3_step,SQLITE_DONE);

    expect_value(__wrap_sqlite3_bind_int64, index, 13);
    expect_value(__wrap_sqlite3_bind_int64, value, 2);
    will_return(__wrap_sqlite3_bind_int64,0);
    expect_any_count(__wrap_sqlite3_bind_text, pos, 13);
    expect_any_count(__wrap_sqlite3_bind_text, buffer, 13);
    will_return_count(__wrap_sqlite3_bind_text, 1, 13);
    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_large_inode(void **state)
{
    int ret;

    wdb_t * wdb = *state;
    wdb->id = strdup("000");
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *object = cJSON_CreateObject();

    cJSON_AddItemToObject(object, "size", cJSON_CreateNumber(2048));
    cJSON_AddItemToObject(object, "mtime", cJSON_CreateNumber(10));
    cJSON_AddItemToObject(object, "inode", cJSON_CreateNumber(2311061769));
    cJSON_AddItemToObject(object, "type", cJSON_CreateString("test_type"));
    cJSON_AddItemToObject(object, "perm", cJSON_CreateString("yes"));
    cJSON_AddItemToObject(object, "uid", cJSON_CreateString("00000"));
    cJSON_AddItemToObject(object, "gid", cJSON_CreateString("AAAAA"));
    cJSON_AddItemToObject(object, "hash_md5", cJSON_CreateString("AAAA23BCD1113A"));
    cJSON_AddItemToObject(object, "hash_sha1", cJSON_CreateString("AAAA23BCD1113A"));
    cJSON_AddItemToObject(object, "user_name", cJSON_CreateString("user"));
    cJSON_AddItemToObject(object, "group_name", cJSON_CreateString("group"));
    cJSON_AddItemToObject(object, "hash_sha256", cJSON_CreateString("AAAA23BCD1113AASDASDASD"));
    cJSON_AddItemToObject(object, "symbolic_path", cJSON_CreateString("/path/second-path"));
    cJSON_AddItemToObject(object, "checksum", cJSON_CreateString("GGGGGGGGGGGG"));
    cJSON_AddItemToObject(object, "attributes", cJSON_CreateString("readonly"));
    cJSON_ReplaceItemInObject(data, "attributes", object);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 2048);
    expect_value(__wrap_sqlite3_bind_int, index, 12);
    expect_value(__wrap_sqlite3_bind_int, value, 10);
    will_return_count(__wrap_sqlite3_bind_int, 0, 2);

    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 10);
    will_return(__wrap_sqlite3_bind_int64, 0);
    will_return(__wrap_sqlite3_step,SQLITE_DONE);


    expect_value(__wrap_sqlite3_bind_int64, index, 13);
    expect_value(__wrap_sqlite3_bind_int64, value, 2311061769);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_any_count(__wrap_sqlite3_bind_text, pos, 13);
    expect_any_count(__wrap_sqlite3_bind_text, buffer, 13);
    will_return_count(__wrap_sqlite3_bind_text, 1, 13);

    ret = wdb_fim_insert_entry2(wdb, data);
    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        //Test wdb_syscheck_save2
        cmocka_unit_test_setup_teardown(test_wdb_syscheck_save2_wbs_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_syscheck_save2_payload_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_syscheck_save2_data_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_syscheck_save2_fail_transaction, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_syscheck_save2_fail_file_entry, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_syscheck_save2_success, setup_wdb_t, teardown_wdb_t),

        //Test wdb_fim_insert_entry2
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_wdb_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_data_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_path_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_timestamp_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_attributes_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_fail_cache, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_fail_element_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_fail_element_string, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_fail_element_number, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_fail_sqlite3_stmt, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_large_inode, setup_wdb_t, teardown_wdb_t),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
