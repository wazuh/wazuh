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
#include <stdlib.h>

#include "remoted/remoted.h"
#include "headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_metadata_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/queue_linked_op_wrappers.h"


extern keystore keys;
extern remoted logr;

/* Forward declarations */
void * close_fp_main(void * args);

/* Setup/teardown */

static int setup_config(void **state) {
    w_linked_queue_t *queue = linked_queue_init();
    keys.opened_fp_queue = queue;
    test_mode = 1;
    return 0;
}

static int teardown_config(void **state) {
    linked_queue_free(keys.opened_fp_queue);
    test_mode = 0;
    return 0;
}

/* Wrappers */

time_t __wrap_time(int time) {
    check_expected(time);
    return mock();
}

void __wrap_key_lock_read(){
    function_called();
}

void __wrap_key_unlock(){
    function_called();
}

/* Tests close_fp_main*/

void test_close_fp_main_queue_empty(void **state)
{
    logr.rids_closing_time = 10;

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
}

void test_close_fp_main_first_node_no_close_first(void **state)
{
    logr.rids_closing_time = 10;

    keyentry *first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - 1;

    // Queue with one element
    w_linked_queue_node_t *node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);
    keys.opened_fp_queue->first = node1;

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 1);
    os_free(node1);
    os_free(first_node_key->id);
    os_free(first_node_key);
}

void test_close_fp_main_close_first(void **state)
{
    logr.rids_closing_time = 10;

    keyentry *first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;

    first_node_key->fp = (FILE *)1234;

    // Queue with one element
    w_linked_queue_node_t *node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 001.");

    expect_value(__wrap_fclose, _File, (FILE *)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
    os_free(first_node_key->id);
    os_free(first_node_key);
}

void test_close_fp_main_close_first_queue_2(void **state)
{
    logr.rids_closing_time = 10;

    keyentry *first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    keyentry *second_node_key = NULL;
    os_calloc(1, sizeof(keyentry), second_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;
    first_node_key->fp = (FILE *)1234;

    second_node_key->id = strdup("002");
    second_node_key->updating_time = now - 1;

    // Queue with one element
    w_linked_queue_node_t *node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);
    w_linked_queue_node_t *node2 = linked_queue_push(keys.opened_fp_queue, second_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 2");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 001.");

    expect_value(__wrap_fclose, _File, (FILE *)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 002.");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 1);
    os_free(first_node_key->id);
    os_free(first_node_key);

    os_free(node2);
    os_free(second_node_key->id);
    os_free(second_node_key);
}

void test_close_fp_main_close_first_queue_2_close_2(void **state)
{
    logr.rids_closing_time = 10;

    keyentry *first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    keyentry *second_node_key = NULL;
    os_calloc(1, sizeof(keyentry), second_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;
    first_node_key->fp = (FILE *)1234;

    second_node_key->id = strdup("002");
    second_node_key->updating_time = now - logr.rids_closing_time - 99;
    second_node_key->fp = (FILE *)1234;

    // Queue with one element
    w_linked_queue_node_t *node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);
    w_linked_queue_node_t *node2 = linked_queue_push(keys.opened_fp_queue, second_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 2");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 001.");

    expect_value(__wrap_fclose, _File, (FILE *)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 002.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 002.");

    expect_string(__wrap__mdebug2, formatted_msg, "Closing rids for agent 002.");

    expect_value(__wrap_fclose, _File, (FILE *)1234);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
    os_free(first_node_key->id);
    os_free(first_node_key);

    os_free(second_node_key->id);
    os_free(second_node_key);
}

void test_close_fp_main_close_fp_null(void **state)
{
    logr.rids_closing_time = 10;

    keyentry *first_node_key = NULL;
    os_calloc(1, sizeof(keyentry), first_node_key);

    int now = 123456789;
    first_node_key->id = strdup("001");
    first_node_key->updating_time = now - logr.rids_closing_time - 100;
    first_node_key->fp = NULL;

    // Queue with one element
    w_linked_queue_node_t *node1 = linked_queue_push(keys.opened_fp_queue, first_node_key);

    // sleep
    expect_value(__wrap_sleep, seconds, 10);

    // key_lock
    expect_function_call(__wrap_key_lock_read);

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 1");

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Checking rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Pop rids_node of agent 001.");

    expect_string(__wrap__mdebug2, formatted_msg, "Opened rids queue size: 0");

    // key_unlock
    expect_function_call(__wrap_key_unlock);

    close_fp_main(&keys);
    assert_int_equal(keys.opened_fp_queue->elements, 0);
    os_free(first_node_key->id);
    os_free(first_node_key);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests close_fp_main
        cmocka_unit_test_setup_teardown(test_close_fp_main_queue_empty, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_first_node_no_close_first, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_first, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_first_queue_2, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_first_queue_2_close_2, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_close_fp_main_close_fp_null, setup_config, teardown_config)
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
