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
    "}";

static cJSON *prepare_valid_entry(sqlite3_int64 inode) {
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *object = cJSON_CreateObject();

    cJSON_AddItemToObject(object, "size", cJSON_CreateNumber(2048));
    cJSON_AddItemToObject(object, "mtime", cJSON_CreateNumber(10));
    cJSON_AddItemToObject(object, "inode", cJSON_CreateNumber(inode));
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

    return data;
}

/* expect functions */

void expect_wdb_fim_insert_entry2_success(sqlite3_int64 inode) {
    expect_cJSON_GetStringValue_call("/test");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("file");

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    expect_sqlite3_bind_int_call(4, 2048, 1);
    expect_sqlite3_bind_int_call(12, 10, 1);
    expect_sqlite3_bind_int64_call(13, inode, 1);

    expect_sqlite3_bind_text_call(5, "yes", 1);
    expect_sqlite3_bind_text_call(6, "00000", 1);
    expect_sqlite3_bind_text_call(7, "AAAAA", 1);
    expect_sqlite3_bind_text_call(8, "AAAA23BCD1113A", 1);
    expect_sqlite3_bind_text_call(9, "AAAA23BCD1113A", 1);
    expect_sqlite3_bind_text_call(10, "user", 1);
    expect_sqlite3_bind_text_call(11, "group", 1);
    expect_sqlite3_bind_text_call(14, "AAAA23BCD1113AASDASDASD", 1);
    expect_sqlite3_bind_text_call(16, "/path/second-path", 1);
    expect_sqlite3_bind_text_call(17, "GGGGGGGGGGGG", 1);
    expect_sqlite3_bind_text_call(15, "readonly", 1);

    expect_sqlite3_step_call(SQLITE_DONE);
}

/* setup/teardown */
static int setup_wdb_t(void **state) {
    wdb_t *data = calloc(1, sizeof(wdb_t));

    if(!data) {
        return -1;
    }

    data->id = strdup("000");

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

static void test_wdb_syscheck_save2_wbs_null(void **state) {
    (void) state; /* unused */
    int ret;

    expect_string(__wrap__merror, formatted_msg, "WDB object cannot be null.");

    ret = wdb_syscheck_save2(NULL, "{}");

    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_payload_null(void **state) {
    int ret;
    wdb_t * wdb = *state;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse FIM payload: '(null)'");

    ret = wdb_syscheck_save2(wdb, NULL);

    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_data_null(void **state) {
    int ret;
    wdb_t * wdb = *state;

    will_return(__wrap_wdb_begin2, 0);

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Can't insert file entry.");

    ret = wdb_syscheck_save2(wdb, "{}");

    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_fail_transaction(void **state) {
    int ret;
    wdb_t * wdb = *state;

    wdb->transaction = 0;

    will_return(__wrap_wdb_begin2, -1);

    expect_string(__wrap__merror, formatted_msg, "DB(000) Can't begin transaction.");

    ret = wdb_syscheck_save2(wdb, "{}");

    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_fail_file_entry(void **state) {
    int ret;
    wdb_t * wdb = *state;

    wdb->transaction = 1;

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Can't insert file entry.");

    const char *entry =
        "{"
        "\"timestamp\": \"123456789\"\n"
        "}";

    ret = wdb_syscheck_save2(wdb, entry);

    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_success(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON *data = prepare_valid_entry(2);
    char *unformatted_data = cJSON_PrintUnformatted(data);

    wdb->transaction = 1;

    expect_wdb_fim_insert_entry2_success(2);

    ret = wdb_syscheck_save2(wdb, unformatted_data);

    cJSON_Delete(data);
    free(unformatted_data);
    assert_int_equal(ret, 0);
}


static void test_wdb_fim_insert_entry2_wdb_null(void **state) {
    (void) state; /* unused */
    int ret;
    cJSON * data = cJSON_Parse(VALID_ENTRY);

    expect_string(__wrap__merror, formatted_msg, "WDB object cannot be null.");

    ret = wdb_fim_insert_entry2(NULL, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_data_null(void **state) {
    int ret;

    wdb_t * wdb = *state;

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");

    ret = wdb_fim_insert_entry2(wdb, NULL);

    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_path_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_CreateObject();

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no file path argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_timestamp_null(void **state) {
    int ret;
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    wdb_t * wdb = *state;

    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, false);

    cJSON_ReplaceItemInObject(data, "timestamp", cJSON_CreateString(""));

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no timestamp path argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_attributes_null(void **state) {
    int ret;
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    wdb_t * wdb = *state;

    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, false);

    cJSON_ReplaceItemInObject(data, "attributes", cJSON_CreateString(""));

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no valid attributes.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_cache(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON *data = cJSON_Parse(VALID_ENTRY);

    expect_cJSON_GetStringValue_call("/test");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("file");

    will_return(__wrap_wdb_stmt_cache, -1);

    expect_string(__wrap__merror, formatted_msg, "DB(000) Can't cache statement");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();

    cJSON_AddItemToObject(array, "inode", cJSON_CreateObject());
    cJSON_ReplaceItemInObject(data, "attributes", array);
    data->child->next->next->child->string = NULL;

    expect_cJSON_GetStringValue_call("/test");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("file");

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_string(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();

    cJSON_AddItemToObject(array, "invalid_attribute", cJSON_CreateString("sasssss"));
    cJSON_ReplaceItemInObject(data, "attributes", array);

    expect_cJSON_GetStringValue_call("/test");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("file");

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    expect_string(__wrap__merror, formatted_msg, "DB(000) Invalid attribute name: invalid_attribute");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_number(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();

    cJSON_AddItemToObject(array, "invalid_attribute", cJSON_CreateNumber(1000));
    cJSON_ReplaceItemInObject(data, "attributes", array);

    expect_cJSON_GetStringValue_call("/test");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("file");

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    expect_string(__wrap__merror, formatted_msg, "DB(000) Invalid attribute name: invalid_attribute");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_sqlite3_stmt(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    expect_cJSON_GetStringValue_call("/test");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("file");

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    expect_sqlite3_step_call(0);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): out of memory");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_registry_arch_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateObject());

    expect_cJSON_GetStringValue_call("HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("registry_value");
    expect_cJSON_GetStringValue_call(NULL);

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save registry request with no arch argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_registry_value_name_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));
    cJSON_AddItemToObject(data, "value_name", cJSON_CreateObject());

    expect_cJSON_GetStringValue_call("HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("registry_value");
    expect_cJSON_GetStringValue_call("[x32]");
    expect_cJSON_GetStringValue_call(NULL);

    expect_string(__wrap__merror,
                  formatted_msg,
                  "DB(000) fim/save registry value request with no value name argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_registry_item_type_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));
    cJSON_ReplaceItemInObject(data, "type", cJSON_CreateObject());

    expect_cJSON_GetStringValue_call("HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call(NULL);

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with no type attribute.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_invalid_item_type(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    if (data == NULL) {
        fail_msg("Unable to parse base json");
    }

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));

    expect_cJSON_GetStringValue_call("[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("invalid");

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save request with invalid 'invalid' type argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_registry_invalid_item_type(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    if (data == NULL) {
        fail_msg("Unable to parse base json");
    }

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));

    expect_cJSON_GetStringValue_call("HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("registry_invalid");
    expect_cJSON_GetStringValue_call("[x32]");

    expect_string(__wrap__merror, formatted_msg,
                  "DB(000) fim/save request with invalid 'registry_invalid' type argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_registry_succesful(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    if (data == NULL) {
        fail_msg("Unable to parse base json");
    }

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));

    expect_wdb_stmt_cache_call(1);

    expect_cJSON_GetStringValue_call("[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("registry");

    expect_sqlite3_bind_text_call(1, "[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave", 1);
    expect_sqlite3_bind_text_call(2, "registry_key", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave", 1);

    expect_sqlite3_step_call(SQLITE_DONE);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_registry_key_succesful(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    if (data == NULL) {
        fail_msg("Unable to parse base json");
    }

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));

    expect_wdb_stmt_cache_call(1);

    expect_cJSON_GetStringValue_call("HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("registry_key");
    expect_cJSON_GetStringValue_call("[x32]");

    expect_sqlite3_bind_text_call(1, "HKEY_LOCAL_MACHINE\\System\\TEST\\clave", 1);
    expect_sqlite3_bind_text_call(2, "registry_key", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, "[x32]", 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave:", 1);

    expect_sqlite3_step_call(SQLITE_DONE);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_registry_value_succesful(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    if (data == NULL) {
        fail_msg("Unable to parse base json");
    }

    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");

    if (attributes == NULL) {
        cJSON_Delete(data);
        fail_msg("Unable to retrieve 'attributes'");
    }

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\clave"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));
    cJSON_AddItemToObject(data, "value_name", cJSON_CreateObject());
    cJSON_AddStringToObject(attributes, "value_type", "REG_SZ");

    expect_wdb_stmt_cache_call(1);

    expect_cJSON_GetStringValue_call("HKEY_LOCAL_MACHINE\\System\\TEST\\clave");
    expect_cJSON_IsNumber_call(true);
    expect_cJSON_IsObject_call(true);
    expect_cJSON_GetStringValue_call("registry_value");
    expect_cJSON_GetStringValue_call("[x32]");
    expect_cJSON_GetStringValue_call("testname");

    expect_sqlite3_bind_text_call(1, "HKEY_LOCAL_MACHINE\\System\\TEST\\clave", 1);
    expect_sqlite3_bind_text_call(2, "registry_value", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, "[x32]", 1);
    expect_sqlite3_bind_text_call(19, "testname", 1);
    expect_sqlite3_bind_text_call(21, "[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\clave:testname", 1);
    expect_sqlite3_bind_text_call(20, "REG_SZ", 1);

    expect_sqlite3_step_call(SQLITE_DONE);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_success(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = prepare_valid_entry(2);

    expect_wdb_fim_insert_entry2_success(2);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_large_inode(void **state) {
    int ret;

    wdb_t * wdb = *state;
    cJSON* data = prepare_valid_entry(2311061769);

    expect_wdb_fim_insert_entry2_success(2311061769);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        //Test wdb_syscheck_save2
        cmocka_unit_test(test_wdb_syscheck_save2_wbs_null),
        cmocka_unit_test(test_wdb_syscheck_save2_payload_null),
        cmocka_unit_test(test_wdb_syscheck_save2_data_null),
        cmocka_unit_test(test_wdb_syscheck_save2_fail_transaction),
        cmocka_unit_test(test_wdb_syscheck_save2_fail_file_entry),
        cmocka_unit_test(test_wdb_syscheck_save2_success),

        //Test wdb_fim_insert_entry2
        cmocka_unit_test(test_wdb_fim_insert_entry2_wdb_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_data_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_path_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_timestamp_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_attributes_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_cache),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_element_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_element_string),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_element_number),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_sqlite3_stmt),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_arch_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_value_name_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_item_type_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_invalid_item_type),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_invalid_item_type),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_succesful),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_key_succesful),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_value_succesful),
        cmocka_unit_test(test_wdb_fim_insert_entry2_success),
        cmocka_unit_test(test_wdb_fim_insert_entry2_large_inode),
    };

    return cmocka_run_group_tests(tests, setup_wdb_t, teardown_wdb_t);
}
