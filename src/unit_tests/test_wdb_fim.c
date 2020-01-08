/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
        os_free(data->agent_id);
        os_free(data);
    }

    return 0;
}

/* redefinitons/wrapping */

int __wrap_wdb_begin2(wdb_t* aux) 
{
    return mock();
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mdebug1()
{
    return 0;
}

int __wrap_wdb_stmt_cache(wdb_t wdb, int index)
{
    return mock();
}

int __wrap_sqlite3_step()
{
    return mock();
}

/* tests */

static void test_wdb_syscheck_save2_wbs_null(void **state)
{
    (void) state; /* unused */
    int ret;
    ret = wdb_syscheck_save2(NULL, "{}");
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_payload_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    ret = wdb_syscheck_save2(data, NULL);
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_data_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_begin2, 0);
    ret = wdb_syscheck_save2(data, "{}");
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_fail_transaction(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    ret = wdb_syscheck_save2(data, "{}");
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_fail_file_entry(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    data->transaction = 1;
    const char *entry = 
    "{"
    "\"path\": \"/test\",\n"
    "\"timestamp\": \"string-val\"\n"
    "}"
    ;
    ret = wdb_syscheck_save2(data, entry);
    assert_int_equal(ret, -1);
}


static void test_wdb_syscheck_save2_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step,101);
    ret = wdb_syscheck_save2(data, VALID_ENTRY);
    assert_int_equal(ret, 0);
}


static void test_wdb_fim_insert_entry2_wdb_null(void **state)
{
    (void) state; /* unused */
    int ret;
    ret = wdb_fim_insert_entry2(NULL, cJSON_Parse(VALID_ENTRY));
    assert_int_equal(ret, -1);    
}

static void test_wdb_fim_insert_entry2_data_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    ret = wdb_fim_insert_entry2(data,NULL);
    assert_int_equal(ret, -1);    
}

static void test_wdb_fim_insert_entry2_path_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject();
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);    
}

static void test_wdb_fim_insert_entry2_timestamp_null(void **state)
{
    int ret;
    cJSON* doc;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    doc = cJSON_Parse(VALID_ENTRY);
    cJSON_ReplaceItemInObject(doc, "timestamp", cJSON_CreateString(""));
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);  
}

static void test_wdb_fim_insert_entry2_attributes_null(void **state)
{
    int ret;
    cJSON* doc;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    doc = cJSON_Parse(VALID_ENTRY);
    cJSON_ReplaceItemInObject(doc, "attributes", cJSON_CreateString(""));
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_cache(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, -1);
    cJSON *doc = cJSON_Parse(VALID_ENTRY);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_string(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();
    cJSON_AddItemToObject(array, "invalid_attribute", cJSON_CreateString("sasssss"));
    cJSON_ReplaceItemInObject(doc, "attributes", array);
    will_return(__wrap_wdb_stmt_cache, 1);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_sqlite3_stmt(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step,0);
    cJSON* doc = cJSON_Parse(VALID_ENTRY);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_Parse(VALID_ENTRY);
    cJSON *array = cJSON_CreateObject();
    cJSON_AddItemToObject(array, "type", cJSON_CreateString("test_type"));
    cJSON_AddItemToObject(array, "uid", cJSON_CreateString("00000"));
    cJSON_AddItemToObject(array, "size", cJSON_CreateNumber(2048));
    cJSON_ReplaceItemInObject(doc, "attributes", array);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step,SQLITE_DONE);  
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
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
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_fail_element_string, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_fail_sqlite3_stmt, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_fim_insert_entry2_success, setup_wdb_t, teardown_wdb_t),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
