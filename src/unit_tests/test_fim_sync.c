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

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

/* Globals */
extern w_queue_t * fim_sync_queue;

/* redefinitons/wrapping */

fim_entry_data *__wrap_rbtree_get() {
    fim_entry_data *data = mock_type(fim_entry_data *);
    return data;
}


char ** __wrap_rbtree_keys() {
    return mock_type(char **);
}


char ** __wrap_rbtree_range(const rb_tree * tree, const char * min, const char * max) {
    // This asserts come from the real rbtree_range, if modified please adjust it here.
    assert(tree != NULL);
    assert(min != NULL);
    assert(max != NULL);

    return mock_type(char **);
}


int __wrap_fim_send_sync_msg(char * msg) {
    check_expected(msg);
    return 1;
}

int __wrap_time(){
    return 1572521857;
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_queue_push_ex(w_queue_t * queue, void * data) {
    int retval = mock();

    check_expected_ptr(queue);
    check_expected(data);

    if(retval != -1)
        free(data);     //  This won't be used, free it

    return retval;
}

/* setup/teardown */
static int setup_group(void **state) {
    fim_initialize();

    return 0;
}

static int setup_fim_sync_queue(void **state) {
    fim_sync_queue = queue_init(10);

    return 0;
}

static int teardown_fim_sync_queue(void **state) {
    queue_free(fim_sync_queue);

    fim_sync_queue = NULL;

    return 0;
}

static int teardown_free_fim_entry_mutex(void **state) {
    w_mutex_unlock(&syscheck.fim_entry_mutex);

    return 0;
}

/* tests */

void test_fim_sync_push_msg_success(void **state) {
    char *msg = "This is a mock message, it won't go anywhere";

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, 0);

    fim_sync_push_msg(msg);
}

void test_fim_sync_push_msg_queue_full(void **state) {
    char *msg = "This is a mock message, it won't go anywhere";

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Cannot push a data synchronization message: queue is full.");

    fim_sync_push_msg(msg);
}

void test_fim_sync_push_msg_no_response(void **state)
{
    (void) state;

    expect_string(__wrap__mwarn, formatted_msg,
        "A data synchronization response was received before sending the first message.");

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

void test_fim_sync_checksum_null_rbtree(void **state)
{
    (void) state;
    char ** keys = NULL;
    keys = os_AddStrArray("test1", keys);
    keys = os_AddStrArray("test2", keys);

    will_return(__wrap_rbtree_keys, keys);

    will_return(__wrap_rbtree_get, NULL);

    expect_assert_failure(fim_sync_checksum());
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

void test_fim_sync_checksum_split_null_start(void **state)
{
    expect_assert_failure(fim_sync_checksum_split(NULL, "end", 1));
}

void test_fim_sync_checksum_split_null_stop(void **state)
{
    expect_assert_failure(fim_sync_checksum_split("init", NULL, 1));
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

void test_fim_sync_send_list_null_start(void **state)
{
    expect_assert_failure(fim_sync_send_list(NULL, "top"));
}

void test_fim_sync_send_list_null_top(void **state)
{
    expect_assert_failure(fim_sync_send_list("start", NULL));
}

void test_fim_sync_dispatch_noarg(void **state)
{
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg, "(6312): Data synchronization command 'payload' with no argument.");

    fim_sync_dispatch("payload");
}


void test_fim_sync_dispatch_invalidarg(void **state)
{
    (void) state;
    char payload[] = "test payload";

    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: 'payload'");

    fim_sync_dispatch(payload);
}

void test_fim_sync_dispatch_invalid_id(void **state)
{
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"id\":\"1\"}'");

    char payload[] = "msg {\"id\":\"1\"}";

    fim_sync_dispatch(payload);
}

void test_fim_sync_dispatch_id(void **state)
{
    (void) state;

    char payload[] = "msg {\"id\":1}";

    expect_string(__wrap__mdebug1, formatted_msg, "(6315): Setting global ID back to lower message ID (1)");
    expect_string(__wrap__mdebug1, formatted_msg, "(6314): Invalid data synchronization argument: '{\"id\":1}'");

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

    expect_string(__wrap__mdebug1, formatted_msg, "(6313): Unknown data synchronization command: 'unknown'");

    fim_sync_dispatch(payload);
}

void test_fim_sync_dispatch_null_payload(void **state)
{
    (void) state;

    expect_assert_failure(fim_sync_dispatch(NULL));
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_success, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_queue_full, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test(test_fim_sync_push_msg_no_response),
        cmocka_unit_test(test_fim_sync_checksum),
        cmocka_unit_test(test_fim_sync_checksum_clear),
        cmocka_unit_test_teardown(test_fim_sync_checksum_null_rbtree, teardown_free_fim_entry_mutex),
        cmocka_unit_test(test_fim_sync_checksum_split_unary),
        cmocka_unit_test_teardown(test_fim_sync_checksum_split_null_start, teardown_free_fim_entry_mutex),
        cmocka_unit_test_teardown(test_fim_sync_checksum_split_null_stop, teardown_free_fim_entry_mutex),
        cmocka_unit_test(test_fim_sync_checksum_split_list),
        cmocka_unit_test(test_fim_sync_send_list),
        cmocka_unit_test(test_fim_sync_send_list_null),
        cmocka_unit_test_teardown(test_fim_sync_send_list_null_start, teardown_free_fim_entry_mutex),
        cmocka_unit_test_teardown(test_fim_sync_send_list_null_top, teardown_free_fim_entry_mutex),
        cmocka_unit_test(test_fim_sync_dispatch_noarg),
        cmocka_unit_test(test_fim_sync_dispatch_invalidarg),
        cmocka_unit_test(test_fim_sync_dispatch_invalid_id),
        cmocka_unit_test(test_fim_sync_dispatch_id),
        cmocka_unit_test(test_fim_sync_dispatch_checksum),
        cmocka_unit_test(test_fim_sync_dispatch_no_data),
        cmocka_unit_test(test_fim_sync_dispatch_unknown),
        cmocka_unit_test(test_fim_sync_dispatch_null_payload),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
