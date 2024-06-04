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

#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"

static const char *VALID_ENTRY = "{\"path\":\"/test\",\"timestamp\":10,\"version\":2,\"attributes\":{\"type\":\"file\"}}";
static const char *VALUE_V3_ENTRY = "{\"arch\":\"[x32]\",\"attributes\":{\"checksum\":\"920b517a949aec0a6fa91b0556f0a60503058fbb\",\
                                  \"hash_md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"hash_sha1\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\
                                  \"hash_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"size\":3221225472,\
                                  \"type\":\"registry_value\",\"value_type\":\"REG_UNKNOWN\"},\"index\":\"00a7ee53218b25b5364c8773f37a38c93eae3880\",\
                                  \"path\":\"HKEY_LOCAL_MACHINE\\\\System\\\\TEST\\\\key\",\
                                  \"timestamp\":1645981428,\"value_name\":\"test_name\",\"version\":3}";
static const char *KEY_V3_ENTRY = "{\"arch\":\"[x32]\",\"attributes\":{\"checksum\":\"6853b29eef33ff39d8b63911673cf7b078f95485\",\
                                    \"gid\":\"0\",\"group_name\":\"SYSTEM\",\"mtime\":1645882878,\"perm\":\"perm_json\",\
                                    \"type\":\"registry_key\",\"uid\":\"0\",\"user_name\":\"Administradores\"},\
                                    \"index\":\"ff03d79932df0148efa6a066552badf25ea9c466\",\
                                    \"path\":\"HKEY_LOCAL_MACHINE\\\\System\\\\TEST\\\\key\",\
                                    \"timestamp\":1645981428,\"version\":3}";

#define BASE_WIN_ALLOWED_ACE \
    "["                      \
    "\"delete\","            \
    "\"read_control\","      \
    "\"write_dac\","         \
    "\"write_owner\","       \
    "\"synchronize\","       \
    "\"read_data\","         \
    "\"write_data\","        \
    "\"append_data\","       \
    "\"read_ea\","           \
    "\"write_ea\","          \
    "\"execute\","           \
    "\"read_attributes\","   \
    "\"write_attributes\""   \
    "]"

#define BASE_WIN_DENIED_ACE \
    "["                     \
    "\"read_control\","     \
    "\"synchronize\","      \
    "\"read_data\","        \
    "\"read_ea\","          \
    "\"execute\","          \
    "\"read_attributes\""   \
    "]"

#define BASE_WIN_ACE                         \
    "{"                                      \
    "\"name\": \"Users\","                   \
    "\"allowed\": " BASE_WIN_ALLOWED_ACE "," \
    "\"denied\": " BASE_WIN_DENIED_ACE "}"

#define BASE_WIN_SID "S-1-5-32-636"

static cJSON *create_win_permissions_object() {
    static const char *const BASE_WIN_PERMS = "{\"" BASE_WIN_SID "\": " BASE_WIN_ACE "}";
    return cJSON_Parse(BASE_WIN_PERMS);
}

typedef enum { PERM_JSON = 0, PERM_STRING = 1 } perm_format_t;

#define prepare_valid_entry(inode) _prepare_valid_entry(inode, "yes", PERM_STRING)
#define prepare_valid_entry_json(inode, perm) _prepare_valid_entry(inode, perm, PERM_JSON)

static cJSON *_prepare_valid_entry(sqlite3_int64 inode, void *perm, perm_format_t perm_format) {
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *object = cJSON_CreateObject();

    cJSON_AddItemToObject(object, "size", cJSON_CreateNumber(3221225472));
    cJSON_AddItemToObject(object, "mtime", cJSON_CreateNumber(10));
    cJSON_AddItemToObject(object, "inode", cJSON_CreateNumber(inode));
    cJSON_AddItemToObject(object, "type", cJSON_CreateString("file"));
    if (perm_format == PERM_JSON) {
        cJSON_AddItemToObject(object, "perm", perm);
    } else if (perm_format == PERM_STRING) {
        cJSON_AddItemToObject(object, "perm", cJSON_CreateString(perm));
    } else {
        fail_msg("Invalid format for permission (%d)", perm_format);
    }
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
#define expect_wdb_fim_insert_entry2_success(inode) _expect_wdb_fim_insert_entry2_success(inode, "yes")
#define expect_wdb_fim_insert_entry2_perm_success(inode, perm) _expect_wdb_fim_insert_entry2_success(inode, perm)

void _expect_wdb_fim_insert_entry2_success(sqlite3_int64 inode, const char *const perm) {

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    expect_sqlite3_bind_int64_call(4, 3221225472, 1);
    expect_sqlite3_bind_int_call(12, 10, 1);
    expect_sqlite3_bind_int64_call(13, inode, 1);

    expect_sqlite3_bind_text_call(5, perm, 1);
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

    will_return(__wrap_wdb_step, SQLITE_DONE);
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
    int ret;

    expect_string(__wrap__merror, formatted_msg, "WDB object cannot be null.");

    ret = wdb_syscheck_save2(NULL, "{}");

    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_payload_null(void **state) {
    int ret;
    wdb_t * wdb = *state;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse FIM payload: ''");

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

    will_return(__wrap_wdb_stmt_cache, -1);

    expect_string(__wrap__merror, formatted_msg, "DB(000) Can't cache statement");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_string(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_GetObjectItem(data, "attributes");

    cJSON_AddItemToObject(array, "invalid_attribute", cJSON_CreateString("sasssss"));

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
    cJSON *array = cJSON_GetObjectItem(data, "attributes");


    cJSON_AddItemToObject(array, "invalid_attribute", cJSON_CreateNumber(1000));

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

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    //expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_prepare_v2(): out of memory");
    //expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot rollback transaction");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) SQLite: out of memory");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_registry_arch_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_ReplaceItemInObject(cJSON_GetObjectItem(data, "attributes"), "type", cJSON_CreateString("registry_value"));

    expect_string(__wrap__merror, formatted_msg, "DB(000) fim/save registry request with no arch argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_registry_value_name_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_ReplaceItemInObject(cJSON_GetObjectItem(data, "attributes"), "type", cJSON_CreateString("registry_value"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));

    expect_string(__wrap__merror,
                  formatted_msg,
                  "DB(000) fim/save registry value request with no value name argument.");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_item_type_null(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_DeleteItemFromObject(cJSON_GetObjectItem(data, "attributes"), "type");

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

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_ReplaceItemInObject(cJSON_GetObjectItem(data, "attributes"), "type", cJSON_CreateString("invalid"));

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

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_ReplaceItemInObject(cJSON_GetObjectItem(data, "attributes"), "type", cJSON_CreateString("registry_invalid"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));

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

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_ReplaceItemInObject(cJSON_GetObjectItem(data, "attributes"), "type", cJSON_CreateString("registry"));

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\key", 1);
    expect_sqlite3_bind_text_call(2, "registry_key", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "[x32] HKEY_LOCAL_MACHINE\\System\\TEST\\key", 1);

    will_return(__wrap_wdb_step, SQLITE_DONE);

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

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_ReplaceItemInObject(cJSON_GetObjectItem(data, "attributes"), "type", cJSON_CreateString("registry_key"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "HKEY_LOCAL_MACHINE\\System\\TEST\\key", 1);
    expect_sqlite3_bind_text_call(2, "registry_key", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, "[x32]", 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "[x32] HKEY_LOCAL_MACHINE\\\\System\\\\TEST\\\\key", 1);

    will_return(__wrap_wdb_step, SQLITE_DONE);

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

    cJSON_ReplaceItemInObject(data, "path", cJSON_CreateString("HKEY_LOCAL_MACHINE\\System\\TEST\\key"));
    cJSON_ReplaceItemInObject(attributes, "type", cJSON_CreateString("registry_value"));
    cJSON_AddItemToObject(data, "arch", cJSON_CreateString("[x32]"));
    cJSON_AddItemToObject(data, "value_name", cJSON_CreateString("testname"));
    cJSON_AddStringToObject(attributes, "value_type", "REG_SZ");

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "HKEY_LOCAL_MACHINE\\System\\TEST\\key", 1);
    expect_sqlite3_bind_text_call(2, "registry_value", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, "[x32]", 1);
    expect_sqlite3_bind_text_call(19, "testname", 1);
    expect_sqlite3_bind_text_call(21, "[x32] HKEY_LOCAL_MACHINE\\\\System\\\\TEST\\\\key:testname", 1);
    expect_sqlite3_bind_text_call(20, "REG_SZ", 1);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_registry_key_succesful_v3(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(KEY_V3_ENTRY);

    if (data == NULL) {
        fail_msg("Unable to parse base json");
    }

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "HKEY_LOCAL_MACHINE\\System\\TEST\\key", 1);
    expect_sqlite3_bind_text_call(2, "registry_key", 1);
    expect_sqlite3_bind_int64_call(3, 1645981428, 0);
    expect_sqlite3_bind_text_call(18, "[x32]", 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "ff03d79932df0148efa6a066552badf25ea9c466", 1);

    expect_sqlite3_bind_text_call(17, "6853b29eef33ff39d8b63911673cf7b078f95485", 1);
    expect_sqlite3_bind_text_call(7, "0", 1);
    expect_sqlite3_bind_text_call(11, "SYSTEM", 1);
    expect_sqlite3_bind_int_call(12, 1645882878, 1);
    expect_sqlite3_bind_text_call(5, "perm_json", 1);
    expect_sqlite3_bind_text_call(6, "0", 1);
    expect_sqlite3_bind_text_call(10, "Administradores", 1);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_registry_value_succesful_v3(void **state) {
    int ret;
    wdb_t * wdb = *state;
    cJSON* data = cJSON_Parse(VALUE_V3_ENTRY);

    if (data == NULL) {
        fail_msg("Unable to parse base json");
    }

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "HKEY_LOCAL_MACHINE\\System\\TEST\\key", 1);
    expect_sqlite3_bind_text_call(2, "registry_value", 1);
    expect_sqlite3_bind_int64_call(3, 1645981428, 0);
    expect_sqlite3_bind_text_call(18, "[x32]", 1);
    expect_sqlite3_bind_text_call(19, "test_name", 1);
    expect_sqlite3_bind_text_call(21, "00a7ee53218b25b5364c8773f37a38c93eae3880", 1);

    expect_sqlite3_bind_text_call(17, "920b517a949aec0a6fa91b0556f0a60503058fbb", 1);
    expect_sqlite3_bind_text_call(8, "d41d8cd98f00b204e9800998ecf8427e", 1);
    expect_sqlite3_bind_text_call(9, "da39a3ee5e6b4b0d3255bfef95601890afd80709", 1);
    expect_sqlite3_bind_text_call(14, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 1);
    expect_sqlite3_bind_int64_call(4, 3221225472, 1);
    expect_sqlite3_bind_text_call(20, "REG_UNKNOWN", 1);

    will_return(__wrap_wdb_step, SQLITE_DONE);

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

static void test_wdb_fim_insert_entry2_json_perms(void **state) {
    wdb_t *wdb = *state;
    int ret;
    cJSON *win_perms = create_win_permissions_object();

    if (win_perms == NULL) {
        fail_msg("Failed to create Windows permissions object");
    }

    char * win_perms_str = cJSON_PrintUnformatted(win_perms);
    if (win_perms_str == NULL) {
        fail_msg("Failed formatting Windows permissions object");
    }

    cJSON *data = prepare_valid_entry_json(2311061769, win_perms);

    expect_wdb_fim_insert_entry2_perm_success(2311061769, win_perms_str);

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    free(win_perms_str);
    assert_int_equal(ret, 0);
}

static void test_wdb_fim_insert_entry2_invalid_json_object(void **state) {
    wdb_t *wdb = *state;
    int ret;
    cJSON *object = cJSON_CreateObject();
    cJSON* data = cJSON_Parse(VALID_ENTRY);

    if (object == NULL || data == NULL) {
        fail_msg("Failed to create object");
    }

    cJSON_AddItemToObject(cJSON_GetObjectItem(data, "attributes"), "invalid", object);

    expect_wdb_stmt_cache_call(1);

    expect_sqlite3_bind_text_call(1, "/test", 1);
    expect_sqlite3_bind_text_call(2, "file", 1);
    expect_sqlite3_bind_int64_call(3, 10, 0);
    expect_sqlite3_bind_text_call(18, NULL, 1);
    expect_sqlite3_bind_text_call(19, NULL, 1);
    expect_sqlite3_bind_text_call(21, "/test", 1);

    expect_string(__wrap__merror, formatted_msg, "DB(000) Invalid attribute name: invalid");

    ret = wdb_fim_insert_entry2(wdb, data);

    cJSON_Delete(data);
    assert_int_equal(ret, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test wdb_syscheck_save2
        cmocka_unit_test(test_wdb_syscheck_save2_wbs_null),
        cmocka_unit_test(test_wdb_syscheck_save2_payload_null),
        cmocka_unit_test(test_wdb_syscheck_save2_data_null),
        cmocka_unit_test(test_wdb_syscheck_save2_fail_transaction),
        cmocka_unit_test(test_wdb_syscheck_save2_fail_file_entry),
        cmocka_unit_test(test_wdb_syscheck_save2_success),

        // Test wdb_fim_insert_entry2
        cmocka_unit_test(test_wdb_fim_insert_entry2_wdb_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_data_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_path_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_timestamp_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_attributes_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_cache),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_element_string),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_element_number),
        cmocka_unit_test(test_wdb_fim_insert_entry2_fail_sqlite3_stmt),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_arch_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_value_name_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_item_type_null),
        cmocka_unit_test(test_wdb_fim_insert_entry2_invalid_item_type),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_invalid_item_type),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_succesful),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_key_succesful),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_value_succesful),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_key_succesful_v3),
        cmocka_unit_test(test_wdb_fim_insert_entry2_registry_value_succesful_v3),
        cmocka_unit_test(test_wdb_fim_insert_entry2_success),
        cmocka_unit_test(test_wdb_fim_insert_entry2_large_inode),
        cmocka_unit_test(test_wdb_fim_insert_entry2_json_perms),
        cmocka_unit_test(test_wdb_fim_insert_entry2_invalid_json_object),
        cmocka_unit_test(test_wdb_fim_insert_entry2_invalid_json_object)
    };

    return cmocka_run_group_tests(tests, setup_wdb_t, teardown_wdb_t);
}
