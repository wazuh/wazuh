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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

#ifdef TEST_SERVER

// Setup / teardown

static int setup_agent_task(void **state) {
    wm_agent_task *agent_task = NULL;
    agent_task = wm_agent_upgrade_init_agent_task();
    *state = (void *)agent_task;
    return 0;
}

static int teardown_agent_task(void **state) {
    wm_agent_task *agent_task = *state;
    wm_agent_upgrade_free_agent_task(agent_task);
    return 0;
}

static int setup_node(void **state) {
    OSHashNode *node = NULL;
    os_calloc(1, sizeof(OSHashNode), node);
    *state = (void *)node;
    return 0;
}

static int teardown_node(void **state) {
    OSHashNode *node = (OSHashNode *)*state;
    os_free(node);
    return 0;
}

#endif

// Wrappers

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_OSHash_Add_ex(OSHash *self, const char *key, void *data) {
    check_expected(key);
    check_expected(data);

    return mock();
}

void *__wrap_OSHash_Get_ex(const OSHash *self, const char *key) {
    check_expected(key);

    return mock_type(void*);
}

int __wrap_OSHash_Update_ex(OSHash *self, const char *key, void *data) {
    check_expected(key);
    check_expected(data);

    return mock();
}

void *__wrap_OSHash_Delete_ex(OSHash *self, const char *key) {
    check_expected(key);

    return mock_type(void*);
}

int __wrap_OSHash_Begin(unsigned int *index) {
    check_expected(index);

    return mock();
}

int __wrap_OSHash_Next(unsigned int *index, OSHashNode *current) {
    check_expected(index);

    return mock();
}

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_create_task_entry_ok(void **state)
{
    int agent_id = 6;
    wm_agent_task *agent_task = *state;

    expect_string(__wrap_OSHash_Add_ex, key, "6");
    expect_memory(__wrap_OSHash_Add_ex, data, agent_task, sizeof(agent_task));
    will_return(__wrap_OSHash_Add_ex, OSHASH_SUCCESS);

    int ret = wm_agent_upgrade_create_task_entry(agent_id, agent_task);

    assert_int_equal(ret, OSHASH_SUCCESS);
}

void test_wm_agent_upgrade_create_task_entry_duplicate(void **state)
{
    int agent_id = 6;
    wm_agent_task *agent_task = *state;

    expect_string(__wrap_OSHash_Add_ex, key, "6");
    expect_memory(__wrap_OSHash_Add_ex, data, agent_task, sizeof(agent_task));
    will_return(__wrap_OSHash_Add_ex, OSHASH_DUPLICATED);

    int ret = wm_agent_upgrade_create_task_entry(agent_id, agent_task);

    assert_int_equal(ret, OSHASH_DUPLICATED);
}

void test_wm_agent_upgrade_insert_task_id_ok(void **state)
{
    int agent_id = 8;
    int task_id = 100;
    wm_agent_task *agent_task = *state;

    agent_task->task_info = wm_agent_upgrade_init_task_info();

    expect_string(__wrap_OSHash_Get_ex, key, "8");
    will_return(__wrap_OSHash_Get_ex, agent_task);

    expect_string(__wrap_OSHash_Update_ex, key, "8");
    expect_memory(__wrap_OSHash_Update_ex, data, agent_task, sizeof(agent_task));
    will_return(__wrap_OSHash_Update_ex, OSHASH_SUCCESS);

    wm_agent_upgrade_insert_task_id(agent_id, task_id);

    assert_int_equal(agent_task->task_info->task_id, task_id);
}

void test_wm_agent_upgrade_insert_task_id_err(void **state)
{
    int agent_id = 8;
    int task_id = 100;

    expect_string(__wrap_OSHash_Get_ex, key, "8");
    will_return(__wrap_OSHash_Get_ex, NULL);

    wm_agent_upgrade_insert_task_id(agent_id, task_id);
}

void test_wm_agent_upgrade_remove_entry_ok(void **state)
{
    int agent_id = 10;
    wm_agent_task *agent_task = *state;

    expect_string(__wrap_OSHash_Delete_ex, key, "10");
    will_return(__wrap_OSHash_Delete_ex, agent_task);

    wm_agent_upgrade_remove_entry(agent_id);
}

void test_wm_agent_upgrade_remove_entry_err(void **state)
{
    int agent_id = 10;

    expect_string(__wrap_OSHash_Delete_ex, key, "10");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    wm_agent_upgrade_remove_entry(agent_id);
}

void test_wm_agent_upgrade_get_first_node(void **state)
{
    int index = 0;

    expect_value(__wrap_OSHash_Begin, index, index);
    will_return(__wrap_OSHash_Begin, 1);

    OSHashNode* ret = wm_agent_upgrade_get_first_node(&index);

    assert_int_equal(ret, 1);
}

void test_wm_agent_upgrade_get_next_node(void **state)
{
    int index = 0;
    OSHashNode *node = *state;

    expect_value(__wrap_OSHash_Next, index, index);
    will_return(__wrap_OSHash_Next, 1);

    OSHashNode* ret = wm_agent_upgrade_get_next_node(&index, node);

    assert_int_equal(ret, 1);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_upgrade_success_callback
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_create_task_entry_ok, setup_agent_task, teardown_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_create_task_entry_duplicate, setup_agent_task, teardown_agent_task),
        // wm_agent_upgrade_insert_task_id
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_insert_task_id_ok, setup_agent_task, teardown_agent_task),
        cmocka_unit_test(test_wm_agent_upgrade_insert_task_id_err),
        // wm_agent_upgrade_remove_entry
        cmocka_unit_test_setup(test_wm_agent_upgrade_remove_entry_ok, setup_agent_task),
        cmocka_unit_test(test_wm_agent_upgrade_remove_entry_err),
        // wm_agent_upgrade_get_first_node
        cmocka_unit_test(test_wm_agent_upgrade_get_first_node),
        // wm_agent_upgrade_get_next_node
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_get_next_node, setup_node, teardown_node),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
