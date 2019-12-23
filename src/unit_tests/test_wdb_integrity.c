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
#include "../os_crypto/sha1/sha1_op.h"
#include "../external/sqlite/sqlite3.h"

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
int __wrap__mdebug1()
{
    return 0;
}

int __wrap_wdb_stmt_cache(wdb_t * wdb, int index)
{
    return mock();
}

int __wrap_sqlite3_step(sqlite3_stmt * stmt)
{
    return mock();
}

const char * __wrap_sqlite3_errmsg(sqlite3 *db)
{
    return mock_type(const char*);
}

int __wrap_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    return mock();
}
int __wrap_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
    return mock();
}
int __wrap_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    return mock();
}
 
/* tests */
static void test_wdbi_checksum_range_wbs_null(void **state)
{
    (void) state; /* unused */
    int ret;
    os_sha1 test_hex = "";
    will_return(__wrap_wdb_stmt_cache, 1);
    ret = wdbi_checksum_range(NULL, 0, "test_begin", "test_end",test_hex);
    assert_int_equal(ret, -1);
}

static void test_wdbi_checksum_range_begin_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    os_sha1 test_hex = "";
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0); 
    ret = wdbi_checksum_range(data, 0, NULL, "test_end",test_hex);
    assert_int_equal(ret, 0);
}

static void test_wdbi_checksum_range_end_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    os_sha1 test_hex = "";
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    ret = wdbi_checksum_range(data, 0, "test_begin", NULL, test_hex);
    assert_int_equal(ret, 0);
}

static void test_wdbi_checksum_range_hexdigest_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    ret = wdbi_checksum_range(data, 0, "test_begin", "test_end", NULL); 
    assert_int_equal(ret, 1);
}

static void test_wdbi_checksum_range_wdb_stmt_cache_fail(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    os_sha1 test_hex = "";
    will_return(__wrap_wdb_stmt_cache, -1);
    ret = wdbi_checksum_range(data, 0, "test_begin", "test_end", test_hex);
    assert_int_equal(ret, -1);
}

static void test_wdbi_checksum_range_no_row(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    os_sha1 test_hex = "";
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    ret = wdbi_checksum_range(data, 0, "test_begin", "test_end", test_hex);
    assert_int_equal(ret, 0);
}

static void test_wdbi_checksum_range_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    ret = wdbi_checksum_range(data, 0, "test_begin", "test_end", test_hex); 
    assert_int_equal(ret, 1);
}

static void test_wdbi_delete_wbs_null(void **state)
{
    (void) state; /* unused */
    int ret;
    will_return(__wrap_wdb_stmt_cache, 1);
    ret = wdbi_delete(NULL, 0, "test_begin", "test_end","test_tail");
    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_begin_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, 0);
    ret = wdbi_delete(data, 0, NULL, "test_end",0);
    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_end_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, 0);
    ret = wdbi_delete(data, 0, "test_begin", NULL, "test_tail");
    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_tail_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, 0);
    ret = wdbi_delete(data, 0, "test_begin", "test_end",NULL);
    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_wdb_stmt_cache_fail(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, -1);
    ret = wdbi_delete(data, 0, "test_begin", "test_end","test_tail");
    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_sql_no_done(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, 0);
    ret = wdbi_delete(data, 0, "test_begin", "test_end",NULL);
    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 101);
    ret = wdbi_delete(data, 0, "test_begin", "test_end",NULL);
    assert_int_equal(ret, 0);
}

static void test_wdbi_update_attempt_wbs_null(void **state)
{
    (void) state; /* unused */

    will_return(__wrap_wdb_stmt_cache, 1);
    wdbi_update_attempt(NULL, 0, 1);
}

static void test_wdbi_update_attempt_stmt_cache_fail(void **state)
{
    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, -1);
    wdbi_update_attempt(data, 0, 0);
}

static void test_wdbi_update_attempt_no_sql_done(void **state)
{
    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 1);
    will_return(__wrap_sqlite3_errmsg, 0);
    wdbi_update_attempt(data, 0, 0);
}

static void test_wdbi_update_attempt_success(void **state)
{
    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 101);
    wdbi_update_attempt(data, 0, 0);
}

static void test_wdbi_update_completion_wbs_null(void **state)
{
    (void) state; /* unused */

    will_return(__wrap_wdb_stmt_cache, 1);
    wdbi_update_attempt(NULL, 0, 1);
}

static void test_wdbi_update_completion_stmt_cache_fail(void **state)
{
    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, -1);
    wdbi_update_attempt(data, 0, 0);
}

static void test_wdbi_update_completion_no_sql_done(void **state)
{
    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 1);
    will_return(__wrap_sqlite3_errmsg, 0);
    wdbi_update_attempt(data, 0, 0);
}

static void test_wdbi_update_completion_success(void **state)
{
    wdb_t * data = *state;
    data->agent_id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 101);
    wdbi_update_attempt(data, 0, 0);
}

//will_return(__wrap_sqlite3_step, 101);

int main(void) {
    const struct CMUnitTest tests[] = {           
        //Test wdbi_checksum_range
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_wbs_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_begin_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_end_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_hexdigest_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_wdb_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_no_row, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_delete
        cmocka_unit_test_setup_teardown(test_wdbi_delete_wbs_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_begin_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_end_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_tail_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_wdb_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_sql_no_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_success, setup_wdb_t, teardown_wdb_t),

        //Test  wdbi_update_attempt 
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_wbs_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_no_sql_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_update_completion
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_wbs_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_no_sql_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_success, setup_wdb_t, teardown_wdb_t),
    };  
    return cmocka_run_group_tests(tests, NULL, NULL);
}

