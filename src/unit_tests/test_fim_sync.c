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

#include "../syscheckd/syscheck.h"


/* redefinitons/wrapping */

fim_entry_data *__wrap_rbtree_get() {
    fim_entry_data *data = mock_type(fim_entry_data *);
    return data;
}


char ** __wrap_rbtree_keys() {
    return mock_type(char **);
}


char ** __wrap_rbtree_range() {
    return mock_type(char **);
}


int __wrap_fim_send_sync_msg(char * msg) {
    check_expected(msg);
    return 1;
}

int __wrap_time(){
    return 1572521857;
}


/* tests */

void test_fim_sync_push_msg_no_response(void **state)
{
    (void) state;

    fim_sync_push_msg("test");
}


void test_fim_sync_checksum(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test1", keys);
    keys = os_AddStrArray("test2", keys);

    will_return(__wrap_rbtree_keys, keys);

    fim_entry_data *data1 = calloc(1, sizeof(fim_entry_data));
    strcpy(data1->checksum, "455c1767e123a76d6af511024d2fc883ae656bef");
    fim_entry_data *data2 = calloc(1, sizeof(fim_entry_data));
    strcpy(data2->checksum, "84f86d40933996a154c687e498433c3bc6ed0697");

    will_return(__wrap_rbtree_get, data1);
    will_return(__wrap_rbtree_get, data2);

    char * expected = "{\"component\":\"syscheck\",\"type\":\"integrity_check_global\",\"data\":{\"id\":1572521857,\"begin\":\"test1\",\"end\":\"test2\",\"checksum\":\"9f9756ed5d4acf61c9d674463c8460a61b9618fb\"}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected);

    fim_sync_checksum();
}


void test_fim_sync_checksum_clear(void **state)
{
    (void) state;
    char ** keys = malloc(2 * sizeof(char *));
    keys[0] = NULL;

    will_return(__wrap_rbtree_keys, keys);

    char * expected = "{\"component\":\"syscheck\",\"type\":\"integrity_clear\",\"data\":{\"id\":1572521857}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected);

    fim_sync_checksum();
}


void test_fim_sync_checksum_split_unary(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test", keys);

    will_return(__wrap_rbtree_range, keys);

    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));
    strcpy(data->checksum, "455c1767e123a76d6af511024d2fc883ae656bef");

    will_return(__wrap_rbtree_get, data);

    char * expected = "{\"component\":\"syscheck\",\"type\":\"state\",\"data\":{\"path\":\"test\",\"timestamp\":0,\"attributes\":{\"checksum\":\"455c1767e123a76d6af511024d2fc883ae656bef\"}}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected);

    fim_sync_checksum_split("init", "end", 1);
}


void test_fim_sync_checksum_split_list(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test1", keys);
    keys = os_AddStrArray("test2", keys);

    will_return(__wrap_rbtree_range, keys);

    fim_entry_data *data1 = calloc(1, sizeof(fim_entry_data));
    strcpy(data1->checksum, "455c1767e123a76d6af511024d2fc883ae656bef");
    fim_entry_data *data2 = calloc(1, sizeof(fim_entry_data));
    strcpy(data2->checksum, "84f86d40933996a154c687e498433c3bc6ed0697");

    will_return(__wrap_rbtree_get, data1);
    will_return(__wrap_rbtree_get, data2);

    char * expected1 = "{\"component\":\"syscheck\",\"type\":\"integrity_check_left\",\"data\":{\"id\":1,\"begin\":\"test1\",\"end\":\"test1\",\"tail\":\"test2\",\"checksum\":\"645e24a2f8b66719fa604868846a8d85ef9e2d70\"}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected1);
    char * expected2 = "{\"component\":\"syscheck\",\"type\":\"integrity_check_right\",\"data\":{\"id\":1,\"begin\":\"test2\",\"end\":\"test2\",\"checksum\":\"18433571887b0ae750d1b749b0859b82ab8f90d7\"}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected2);

    fim_sync_checksum_split("init", "end", 1);
}


void test_fim_sync_send_list(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test1", keys);
    keys = os_AddStrArray("test2", keys);

    will_return(__wrap_rbtree_range, keys);

    fim_entry_data *data1 = calloc(1, sizeof(fim_entry_data));
    strcpy(data1->checksum, "455c1767e123a76d6af511024d2fc883ae656bef");
    fim_entry_data *data2 = calloc(1, sizeof(fim_entry_data));
    strcpy(data2->checksum, "84f86d40933996a154c687e498433c3bc6ed0697");

    will_return(__wrap_rbtree_get, data1);
    will_return(__wrap_rbtree_get, data2);

    char * expected1 = "{\"component\":\"syscheck\",\"type\":\"state\",\"data\":{\"path\":\"test1\",\"timestamp\":0,\"attributes\":{\"checksum\":\"455c1767e123a76d6af511024d2fc883ae656bef\"}}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected1);
    char * expected2 = "{\"component\":\"syscheck\",\"type\":\"state\",\"data\":{\"path\":\"test2\",\"timestamp\":0,\"attributes\":{\"checksum\":\"84f86d40933996a154c687e498433c3bc6ed0697\"}}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected2);

    fim_sync_send_list("start", "top");
}


void test_fim_sync_send_list_null(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test1", keys);
    keys = os_AddStrArray("test2", keys);

    will_return(__wrap_rbtree_range, keys);

    will_return_always(__wrap_rbtree_get, NULL);

    fim_sync_send_list("start", "top");
}


void test_fim_sync_dispatch_noarg(void **state)
{
    (void) state;

    fim_sync_dispatch("payload");
}


void test_fim_sync_dispatch_invalidarg(void **state)
{
    (void) state;
    char payload[] = "test payload";

    fim_sync_dispatch(payload);
}

void test_fim_sync_dispatch_invalid_id(void **state)
{
    (void) state;

    char payload[] = "msg {\"id\":\"1\"}";

    fim_sync_dispatch(payload);
}

void test_fim_sync_dispatch_id(void **state)
{
    (void) state;

    char payload[] = "msg {\"id\":1}";

    fim_sync_dispatch(payload);
}

void test_fim_sync_dispatch_checksum(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test", keys);

    // In fim_sync_checksum_split
    will_return(__wrap_rbtree_range, keys);

    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));
    strcpy(data->checksum, "455c1767e123a76d6af511024d2fc883ae656bef");

    will_return(__wrap_rbtree_get, data);

    char * expected = "{\"component\":\"syscheck\",\"type\":\"state\",\"data\":{\"path\":\"test\",\"timestamp\":0,\"attributes\":{\"checksum\":\"455c1767e123a76d6af511024d2fc883ae656bef\"}}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected);

    char payload[] = "checksum_fail {\"id\":1,\"begin\":\"test_begin\",\"end\":\"test_end\"}";

    fim_sync_dispatch(payload);
}


void test_fim_sync_dispatch_no_data(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test", keys);

    // In fim_sync_checksum_split
    will_return(__wrap_rbtree_range, keys);

    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));
    strcpy(data->checksum, "455c1767e123a76d6af511024d2fc883ae656bef");

    will_return(__wrap_rbtree_get, data);

    char * expected = "{\"component\":\"syscheck\",\"type\":\"state\",\"data\":{\"path\":\"test\",\"timestamp\":0,\"attributes\":{\"checksum\":\"455c1767e123a76d6af511024d2fc883ae656bef\"}}}";
    expect_string(__wrap_fim_send_sync_msg, msg, expected);

    char payload[] = "no_data {\"id\":1,\"begin\":\"test_begin\",\"end\":\"test_end\"}";

    fim_sync_dispatch(payload);
}


void test_fim_sync_dispatch_unknown(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test", keys);

    char payload[] = "unknown {\"id\":1,\"begin\":\"test_begin\",\"end\":\"test_end\"}";

    fim_sync_dispatch(payload);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fim_sync_push_msg_no_response),
        cmocka_unit_test(test_fim_sync_checksum),
        cmocka_unit_test(test_fim_sync_checksum_clear),
        cmocka_unit_test(test_fim_sync_checksum_split_unary),
        cmocka_unit_test(test_fim_sync_checksum_split_list),
        cmocka_unit_test(test_fim_sync_send_list),
        cmocka_unit_test(test_fim_sync_send_list_null),
        cmocka_unit_test(test_fim_sync_dispatch_noarg),
        cmocka_unit_test(test_fim_sync_dispatch_invalidarg),
        cmocka_unit_test(test_fim_sync_dispatch_invalid_id),
        cmocka_unit_test(test_fim_sync_dispatch_id),
        cmocka_unit_test(test_fim_sync_dispatch_checksum),
        cmocka_unit_test(test_fim_sync_dispatch_no_data),
        cmocka_unit_test(test_fim_sync_dispatch_unknown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
