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
#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/wazuh/shared/queue_linked_op_wrappers.h"




/* Forward declarations */
void StoreCounter(const keystore *keys, int id, unsigned int global, unsigned int local);

/* Setup/teardown */

static int setup_config(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_config(void **state) {
    test_mode = 0;
    return 0;
}

/* Wrappers */

time_t __wrap_time(int time) {
    check_expected(time);
    return mock();
}

/* Tests StoreCounter*/

void test_StoreCounter_updating_rids(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->updating_time = now;
    key->fp = (FILE *)1234;
    w_linked_queue_node_t *node1 = linked_queue_push(keys.opened_fp_queue, keys.keyentries[0]);
    key->rids_node = node1;
    keys.keyentries[0] = key;

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Updating rids_node for agent 001.");

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);
    linked_queue_free(keys.opened_fp_queue);
    os_free(node1);
    os_free(key->id);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}

void test_StoreCounter_pushing_rids(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->updating_time = now;
    key->fp = (FILE *)1234;
    key->rids_node = NULL;
    keys.keyentries[0] = key;

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Pushing rids_node for agent 001.");
    expect_memory(__wrap_linked_queue_push_ex, queue, keys.opened_fp_queue, sizeof(keys.opened_fp_queue));
    expect_memory(__wrap_linked_queue_push_ex, data, keys.keyentries[0], sizeof(keys.keyentries[0]));

    assert_int_equal(keys.opened_fp_queue->elements, 0);

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);
    assert_int_equal(keys.keyentries[0]->updating_time, now);

    linked_queue_free(keys.opened_fp_queue);
    os_free(key->id);
    os_free(keys.keyentries[0]->rids_node);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}

void test_StoreCounter_pushing_rids_fp_null(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);
    key->id = strdup("001");
    key->updating_time = now;
    key->fp = NULL;
    key->rids_node = NULL;
    keys.keyentries[0] = key;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/queue/rids/001");
    expect_string(__wrap_fopen, mode, "r+");
    will_return(__wrap_fopen, 1234);

    expect_string(__wrap__mdebug2, formatted_msg, "Opening rids for agent 001.");

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Pushing rids_node for agent 001.");
    expect_memory(__wrap_linked_queue_push_ex, queue, keys.opened_fp_queue, sizeof(keys.opened_fp_queue));
    expect_memory(__wrap_linked_queue_push_ex, data, keys.keyentries[0], sizeof(keys.keyentries[0]));

    assert_int_equal(keys.opened_fp_queue->elements, 0);

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);
    assert_int_equal(keys.keyentries[0]->updating_time, now);

    linked_queue_free(keys.opened_fp_queue);
    os_free(key->id);
    os_free(keys.keyentries[0]->rids_node);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}

void test_StoreCounter_fail_first_open(void **state)
{
    keystore keys = KEYSTORE_INITIALIZER;
    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;
    w_linked_queue_t *queue;
    queue = linked_queue_init();
    keys.keysize = 0;
    keys.id_counter = 0;
    keys.opened_fp_queue = queue;

    int global = 1;
    int local = 2;
    int id = 0;
    int now = 123456789;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);

    key->id = strdup("001");
    key->updating_time = now;
    key->fp = NULL;
    key->rids_node = NULL;
    keys.keyentries[0] = key;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/queue/rids/001");
    expect_string(__wrap_fopen, mode, "r+");
    will_return(__wrap_fopen, NULL);
    errno = EACCES;
    expect_string(__wrap_fopen, path, "/queue/rids/001");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1234);

    expect_string(__wrap__mdebug2, formatted_msg, "Opening rids for agent 001.");

    will_return(__wrap_fseek, 0);

    expect_value(__wrap_fprintf, __stream, 1234);
    expect_string(__wrap_fprintf, formatted_msg, "1:2:");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_time, time, 0);
    will_return(__wrap_time, now);

    expect_string(__wrap__mdebug2, formatted_msg, "Pushing rids_node for agent 001.");
    expect_memory(__wrap_linked_queue_push_ex, queue, keys.opened_fp_queue, sizeof(keys.opened_fp_queue));
    expect_memory(__wrap_linked_queue_push_ex, data, keys.keyentries[0], sizeof(keys.keyentries[0]));

    assert_int_equal(keys.opened_fp_queue->elements, 0);

    StoreCounter(&keys, id, global, local);

    assert_int_equal(keys.opened_fp_queue->elements, 1);

    linked_queue_free(keys.opened_fp_queue);
    os_free(key->id);
    os_free(keys.keyentries[0]->rids_node);
    os_free(keys.keyentries[0]);
    os_free(keys.keyentries);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests StoreCounter
        cmocka_unit_test_setup_teardown(test_StoreCounter_updating_rids, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_pushing_rids, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_pushing_rids_fp_null, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_StoreCounter_fail_first_open, setup_config, teardown_config)
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
