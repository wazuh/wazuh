/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "wazuhdb_op.h"


bool wdb_dbsync_stmt_bind_from_string(sqlite3_stmt * stmt, int index, field_type_t type, const char * value, const char ** replace);

/*
* Dummy tables information
*/
static struct column_list const TABLE_NETIFACE_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_NETIFACE_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct column_list const TABLE_NETPROTO_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_NETPROTO_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct column_list const TABLE_NETADDR_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_NETADDR_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct column_list const TABLE_OS_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_OS_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct column_list const TABLE_HARDWARE_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_HARDWARE_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct column_list const TABLE_PORTS_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_PORTS_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct column_list const TABLE_PACKAGES_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_PACKAGES_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct column_list const TABLE_PROCESSES_TEST[] = {
    { .value = { FIELD_INTEGER, 1, true, false, "test_1" }, .next = &TABLE_PROCESSES_TEST[1] } ,
    { .value = { FIELD_TEXT, 2, false, false, "test_2" }, .next = NULL } ,
};

static struct kv_list const TABLE_MAP_TEST[] = {
    { .current = { "network_iface", "sys_netiface", false, TABLE_NETIFACE_TEST }, .next = &TABLE_MAP_TEST[1]},
    { .current = { "network_protocol", "sys_netproto", false, TABLE_NETPROTO_TEST }, .next = &TABLE_MAP_TEST[2]},
    { .current = { "network_address", "sys_netaddr", false, TABLE_NETADDR_TEST }, .next = &TABLE_MAP_TEST[3]},
    { .current = { "osinfo", "sys_osinfo", false, TABLE_OS_TEST }, .next = &TABLE_MAP_TEST[4]},
    { .current = { "hwinfo", "sys_hwinfo", false, TABLE_HARDWARE_TEST }, .next = &TABLE_MAP_TEST[5]},
    { .current = { "ports", "sys_ports", false, TABLE_PORTS_TEST }, .next = &TABLE_MAP_TEST[6]},
    { .current = { "packages", "sys_programs", false, TABLE_PACKAGES_TEST }, .next = &TABLE_MAP_TEST[7]},
    { .current = { "processes", "sys_processes",  false, TABLE_PROCESSES_TEST}, .next = NULL},
};

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("global",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

//
// wdb_single_row_insert_dbsync
//

void test_wdb_single_row_insert_dbsync_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    assert_false(wdb_single_row_insert_dbsync(data->wdb, NULL, "something"));
}

void test_wdb_single_row_insert_dbsync_get_cache_stmt_fail(void **state)
{
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, NULL);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_single_row_insert_dbsync(NULL, &head->current, "something"));
}

void test_wdb_single_row_insert_dbsync_get_cache_stmt_bad_query(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, NULL);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_single_row_insert_dbsync(data->wdb, &head->current, "bad_query"));
}

void test_wdb_single_row_insert_dbsync_get_cache_stmt_null(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_get_cache_stmt, 0);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_single_row_insert_dbsync(data->wdb, &head->current, "good query"));
}

void test_wdb_single_row_insert_dbsync_get_cache_stmt_not_null(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_get_cache_stmt, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "data");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    assert_true(wdb_single_row_insert_dbsync(data->wdb, &head->current, "data|1"));
}


//
// wdb_insert_dbsync
//

void test_wdb_insert_dbsync_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    assert_false(wdb_insert_dbsync(NULL, &head->current, "something"));
    assert_false(wdb_insert_dbsync(data->wdb, NULL, "something"));
    assert_false(wdb_insert_dbsync(data->wdb, &head->current, NULL));
}

void test_wdb_insert_dbsync_bad_cache(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, NULL);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_insert_dbsync(data->wdb, &head->current, "something"));
}

void test_wdb_insert_dbsync_bind_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;

    will_return(__wrap_wdb_get_cache_stmt, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    const char error_value[] = { "bad parameter or other API misuse" };
    char error_message[128] = { "\0" };
    sprintf(error_message, DB_AGENT_SQL_ERROR, "global", error_value);
    will_return(__wrap_sqlite3_errmsg, error_value);
    expect_string(__wrap__merror, formatted_msg, error_message);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "data");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, error_value);
    expect_string(__wrap__merror, formatted_msg, error_message);

    assert_false(wdb_insert_dbsync(data->wdb, &head->current, "data|1"));
}

void test_wdb_insert_dbsync_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;

    will_return(__wrap_wdb_get_cache_stmt, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "data");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    assert_true(wdb_insert_dbsync(data->wdb, &head->current, "data|1"));
}

//
// wdb_modify_dbsync
//

void test_wdb_modify_dbsync_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    assert_false(wdb_modify_dbsync(NULL, &head->current, "something"));
    assert_false(wdb_modify_dbsync(data->wdb, NULL, "something"));
    assert_false(wdb_modify_dbsync(data->wdb, &head->current, NULL));
}

void test_wdb_modify_dbsync_bad_cache(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, NULL);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_modify_dbsync(data->wdb, &head->current, "something"));
}

void test_wdb_modify_dbsync_step_nok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "data1");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);

    assert_false(wdb_modify_dbsync(data->wdb, &head->current, "data1|1|data2|2"));
}

void test_wdb_modify_dbsync_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "data1");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 1);

    assert_true(wdb_modify_dbsync(data->wdb, &head->current, "data1|1|data2|2"));
}

void test_wdb_modify_dbsync_nochanges(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "data1");
    will_return_always(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 0);

    assert_false(wdb_modify_dbsync(data->wdb, &head->current, "data1|1|data2|2"));
}


//
// wdb_delete_dbsync
//

void test_wdb_delete_dbsync_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    assert_false(wdb_delete_dbsync(NULL, &head->current, "something"));
    assert_false(wdb_delete_dbsync(data->wdb, NULL, "something"));
    assert_false(wdb_delete_dbsync(data->wdb, &head->current, NULL));
}

void test_wdb_delete_dbsync_bad_cache(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, NULL);
    expect_string(__wrap__merror, formatted_msg, DB_CACHE_NULL_STMT);
    assert_false(wdb_delete_dbsync(data->wdb, &head->current, "something"));
}

void test_wdb_delete_dbsync_step_nok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    assert_false(wdb_delete_dbsync(data->wdb, &head->current, "data|1"));
}

void test_wdb_delete_dbsync_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 1);
    assert_true(wdb_delete_dbsync(data->wdb, &head->current, "test_1"));
}

void test_wdb_delete_dbsync_nochanges(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    struct kv_list const *head = TABLE_MAP_TEST;
    will_return(__wrap_wdb_get_cache_stmt, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 0);
    assert_false(wdb_delete_dbsync(data->wdb, &head->current, "test_1"));
}

//
// wdb_stmt_bind_from_string
//

void test_wdb_dbsync_stmt_bind_from_string_replace_null(void ** state) {

    assert_false(wdb_dbsync_stmt_bind_from_string(NULL, 0, FIELD_INTEGER, "some value", NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_stmt_null(void ** state) {

    assert_false(wdb_dbsync_stmt_bind_from_string(NULL, 0, FIELD_INTEGER, "some value", NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_value_null(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, 0, FIELD_INTEGER, NULL, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_real(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str = "0.5";
    const double test_value = 0.5;

    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_double, index, test_index);
    expect_value(__wrap_sqlite3_bind_double, value, test_value);
    will_return(__wrap_sqlite3_bind_double, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_REAL, test_value_str, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_real_replace(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str[] = {"", NULL};

    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_null, index, test_index);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_REAL, *test_value_str, test_value_str));
}

void test_wdb_dbsync_stmt_bind_from_string_type_real_invalid(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value = "this is a string";
    const int test_index = 1;

    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_REAL, test_value, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_real_bind_error(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str = "0.5";
    const double test_value = 0.5;
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_double, index, test_index);
    expect_value(__wrap_sqlite3_bind_double, value, test_value);
    will_return(__wrap_sqlite3_bind_double, SQLITE_ERROR);

    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_REAL, test_value_str, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str = "3";
    const int test_value = 3;
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_int, index, test_index);
    expect_value(__wrap_sqlite3_bind_int, value, test_value);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER, test_value_str, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer_replace(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str[] = {"", NULL};
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_null, index, test_index);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER, *test_value_str, test_value_str));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer_invalid(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value = "this is a string";
    const int test_index = 1;

    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER, test_value, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer_bind_error(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str = "3";
    const int test_value = 3;
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_int, index, test_index);
    expect_value(__wrap_sqlite3_bind_int, value, test_value);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER, test_value_str, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_text(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value = "this is a string";
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_text, pos, test_index);
    expect_string(__wrap_sqlite3_bind_text, buffer, test_value);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_TEXT, test_value, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_text_replace(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_replace[] = {"", NULL};
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_null, index, test_index);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_TEXT, *test_value_replace, test_value_replace));
}

void test_wdb_dbsync_stmt_bind_from_string_type_text_bind_error(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value = "this is a string";
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_text, pos, test_index);
    expect_string(__wrap_sqlite3_bind_text, buffer, test_value);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_TEXT, test_value, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer_long(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str = "5294967296";
    const long long test_value = 5294967296;

    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_int64, index, test_index);
    expect_value(__wrap_sqlite3_bind_int64, value, test_value);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER_LONG, test_value_str, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer_long_replace(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str[] = {"", NULL};

    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_null, index, test_index);
    will_return(__wrap_sqlite3_bind_null, SQLITE_OK);

    assert_true(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER_LONG, *test_value_str, test_value_str));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer_long_invalid(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value = "this is a string";
    const int test_index = 1;

    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER_LONG, test_value, NULL));
}

void test_wdb_dbsync_stmt_bind_from_string_type_integer_long_bind_error(void ** state) {

    sqlite3_stmt * test_stmt = (sqlite3_stmt *) 1;
    const char * test_value_str = "5294967296";
    const long long test_value = 5294967296;
    const int test_index = 1;

    expect_value(__wrap_sqlite3_bind_int64, index, test_index);
    expect_value(__wrap_sqlite3_bind_int64, value, test_value);
    will_return(__wrap_sqlite3_bind_int64, SQLITE_ERROR);

    assert_false(wdb_dbsync_stmt_bind_from_string(test_stmt, test_index, FIELD_INTEGER_LONG, test_value_str, NULL));
}

int main()
{
    const struct CMUnitTest tests[] = {
        /* wdb_dbsync_stmt_bind_from_string */
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_stmt_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_value_null),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_real),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_real_replace),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_real_invalid),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_real_bind_error),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer_replace),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer_invalid),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer_bind_error),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_text),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_text_replace),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_text_bind_error),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer_long),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer_long_replace),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer_long_invalid),
        cmocka_unit_test(test_wdb_dbsync_stmt_bind_from_string_type_integer_long_bind_error),
        /* wdb_single_row_insert_dbsync */
        cmocka_unit_test_setup_teardown(test_wdb_single_row_insert_dbsync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_single_row_insert_dbsync_get_cache_stmt_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_single_row_insert_dbsync_get_cache_stmt_bad_query, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_single_row_insert_dbsync_get_cache_stmt_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_single_row_insert_dbsync_get_cache_stmt_not_null, test_setup, test_teardown),
        /* wdb_insert_dbsync */
        cmocka_unit_test_setup_teardown(test_wdb_insert_dbsync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_insert_dbsync_bad_cache, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_insert_dbsync_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_insert_dbsync_ok, test_setup, test_teardown),
        /* wdb_modify_dbsync */
        cmocka_unit_test_setup_teardown(test_wdb_modify_dbsync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_modify_dbsync_bad_cache, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_modify_dbsync_step_nok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_modify_dbsync_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_modify_dbsync_nochanges, test_setup, test_teardown),
        /* wdb_delete_dbsync */
        cmocka_unit_test_setup_teardown(test_wdb_delete_dbsync_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_delete_dbsync_bad_cache, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_delete_dbsync_step_nok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_delete_dbsync_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_delete_dbsync_nochanges, test_setup, test_teardown),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
