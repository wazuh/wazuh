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

cJSON* __wrap_cJSON_Parse(const char * item) {
    return mock_type(cJSON*);
}

int __wrap_cJSON_Delete(cJSON* item) {
    return 0;
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mdebug1()
{
    return 0;
}

char* __wrap_cJSON_GetStringValue(cJSON * item)
{
    return mock_type(char*);
}

cJSON_bool __wrap_cJSON_IsNumber(cJSON * item)
{
    return mock_type(cJSON_bool);
}

cJSON_bool __wrap_cJSON_IsObject(cJSON * item)
{
    return mock_type(cJSON_bool);
}

int __wrap_wdb_stmt_cache(wdb_t wdb, int index)
{
    return mock();
}
int __wrap_sqlite3_bind_text()
{
    return mock();
}

int __wrap_sqlite3_bind_int64()
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
    will_return(__wrap_cJSON_Parse, cJSON_CreateObject());
    ret = wdb_syscheck_save2(NULL, "test");
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_payload_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_cJSON_Parse, cJSON_CreateObject());
    ret = wdb_syscheck_save2(NULL, NULL);
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_data_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON * doc = NULL;
    will_return(__wrap_cJSON_Parse, doc);
    ret = wdb_syscheck_save2(data, "test");
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_fail_transaction(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    data->transaction = 0;
    cJSON * doc = cJSON_CreateObject();
    will_return(__wrap_cJSON_Parse, doc);
    will_return(__wrap_wdb_begin2, -1);
    ret = wdb_syscheck_save2(data, "test");
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_syscheck_save2_fail_file_entry(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    data->transaction = 1;
    cJSON * doc = cJSON_CreateObject();
    will_return(__wrap_cJSON_Parse, doc);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, false);
    ret = wdb_syscheck_save2(data, "test");
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}


static void test_wdb_syscheck_save2_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    data->transaction = 1;
    cJSON * doc = cJSON_CreateObject();
    cJSON_AddNumberToObject(doc,"timestamp",10); 
    will_return(__wrap_cJSON_Parse, doc);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_bind_text,1);
    will_return(__wrap_sqlite3_bind_int64,0);
    will_return(__wrap_sqlite3_step,101);
    ret = wdb_syscheck_save2(data, "test");
    cJSON_Delete(doc);
    assert_int_equal(ret, 0);
}


static void test_wdb_fim_insert_entry2_wdb_null(void **state)
{
    (void) state; /* unused */
    int ret;
    cJSON* doc = cJSON_CreateObject();
    will_return(__wrap_cJSON_GetStringValue, NULL);
    ret = wdb_fim_insert_entry2(NULL, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);    
}

static void test_wdb_fim_insert_entry2_data_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_cJSON_GetStringValue,cJSON_GetObjectItem(NULL, "path"));
    ret = wdb_fim_insert_entry2(data,NULL);
    assert_int_equal(ret, -1);    
}

static void test_wdb_fim_insert_entry2_path_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject();
    will_return(__wrap_cJSON_GetStringValue, NULL);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);    
}

static void test_wdb_fim_insert_entry2_timestamp_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject();
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, false);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);  
}

static void test_wdb_fim_insert_entry2_attributes_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject(); 
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, false);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_cache(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject(); 
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, -1);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_element_string(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject();
    cJSON_AddNumberToObject(doc,"timestamp",10);
    cJSON *array = cJSON_CreateArray();
    cJSON_AddItemToArray(array, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(array, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(array, cJSON_CreateNumber(3));
    cJSON_AddItemToArray(array, cJSON_CreateNumber(4));
    cJSON_AddItemToObject(doc, "attributes", array);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_bind_text,1);
    will_return(__wrap_sqlite3_bind_int64,0);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(array);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_fail_sqlite3_stmt(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject();
    cJSON_AddNumberToObject(doc,"timestamp",10);
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_bind_text,1);
    will_return(__wrap_sqlite3_bind_int64,0);
    will_return(__wrap_sqlite3_step,0);
    ret = wdb_fim_insert_entry2(data, doc);
    cJSON_Delete(doc);
    assert_int_equal(ret, -1);
}

static void test_wdb_fim_insert_entry2_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    cJSON* doc = cJSON_CreateObject();
    cJSON_AddNumberToObject(doc,"timestamp",10); 
    will_return(__wrap_cJSON_GetStringValue, "/test");
    will_return(__wrap_cJSON_IsNumber, true);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_bind_text,1);
    will_return(__wrap_sqlite3_bind_int64,0);
    will_return(__wrap_sqlite3_step,101);
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
