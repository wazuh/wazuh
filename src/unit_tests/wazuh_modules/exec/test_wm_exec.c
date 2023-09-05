/*
 * Copyright (C) 2023, Wazuh Inc.
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
#include "shared.h"
#include "../../../wazuh_modules/wmodules.h"

#include "../../wrappers/wazuh/shared/list_op_wrappers.h"
#include "../../wrappers/posix/signal_wrappers.h"

#define COMMAND u8"Powershell -c \"@{ winCounter = (Get-Counter '\\mémoire\\mégaoctets disponibles').CounterSamples[0] } | ConvertTo-Json -compress\""
#define COMMAND2 u8"Powershell -c \"@{ winCounter = (Get-Counter '\\processeur(_total)\\% temps processeur').CounterSamples[0] } | ConvertTo-Json -compress\""

int __wrap_sleep (unsigned int __seconds) {
    return mock();
}

static int setup_modules(void ** state) {
    *state = NULL;
    // wm_kill_timeout to default value
    wm_kill_timeout = 10;
    test_mode = true;
    wm_children_pool_init();
    return 0;
}

static int teardown_modules(void ** state) {
    // wm_kill_timeout to default value
    wm_kill_timeout = 0;
    test_mode = false;
    wm_children_pool_destroy();
    return 0;
}

static void test_wm_exec_accented_command(void ** state) {
#ifdef WIN32
    size_t size = mbstowcs(NULL, COMMAND, 0);
    wchar_t *wcommand = calloc(size, sizeof(wchar_t));
    mbstowcs(wcommand, COMMAND, size);

    expect_any(__wrap__mdebug2, formatted_msg);
    expect_string(wrap_CreateProcessW, lpCommandLine, wcommand);
    will_return(wrap_CreateProcessW, TRUE);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, 0);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    assert_int_equal(0, wm_exec(COMMAND, NULL, NULL, 0, NULL));

    free(wcommand);
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_not_accented_command(void ** state) {
#ifdef WIN32
    size_t size = mbstowcs(NULL, COMMAND2, 0);
    wchar_t *wcommand = calloc(size, sizeof(wchar_t));
    mbstowcs(wcommand, COMMAND2, size);

    expect_any(__wrap__mdebug2, formatted_msg);
    expect_string(wrap_CreateProcessW, lpCommandLine, wcommand);
    will_return(wrap_CreateProcessW, TRUE);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, 0);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    assert_int_equal(0, wm_exec(COMMAND2, NULL, NULL, 0, NULL));

    free(wcommand);
#else
    printf("not implemented yet!\n");
#endif
}

#ifndef TEST_WINAGENT
static void test_wm_append_sid_null_list(void ** state) {
    pid_t sid = 10;

    expect_string(__wrap__merror, formatted_msg, "Child process sid 10 could not be registered.");

    wm_append_sid(sid);
}

static void test_wm_append_sid_fail(void ** state) {

    pid_t sid = 10;

    will_return(__wrap_OSList_AddData, false);
    will_return(__wrap_OSList_AddData, NULL);

    expect_string(__wrap__merror, formatted_msg, "Child process sid 10 could not be registered.");

    wm_append_sid(sid);
}

static void test_wm_append_sid_success(void ** state) {

    pid_t sid = 10;
    OSListNode *node;

    will_return(__wrap_OSList_AddData, true);
    will_return(__wrap_OSList_AddData, node);

    wm_append_sid(sid);
}

static void test_wm_remove_sid_null_list(void ** state) {
    pid_t sid = 10;

    expect_string(__wrap__merror, formatted_msg, "Child process 10 not found.");

    wm_remove_sid(sid);
}

static void test_wm_remove_sid_not_found(void ** state) {
    pid_t sid = 10;

    will_return(__wrap_OSList_GetFirstNode, NULL);
    expect_string(__wrap__merror, formatted_msg, "Child process 10 not found.");

    wm_remove_sid(sid);
}

static void test_wm_remove_sid_success(void ** state) {
    pid_t sid = 10;
    pid_t * p_sid = NULL;
    OSListNode *node;

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);
    expect_function_call(__wrap_OSList_DeleteThisNode);

    wm_remove_sid(sid);

    os_free(node);
}

static void test_wm_kill_children_fork_failed(void ** state) {
    pid_t sid = 10;
    pid_t * p_sid = NULL;
    OSListNode *node;

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);

    pid_t pidError = -1;
    will_return(__wrap_fork, pidError);
    errno = 13;

    expect_string(__wrap__merror, formatted_msg, "wm_kill_children(): Couldn't fork: (13) Permission denied.");

    test_mode = false;

    wm_kill_children(sid);

    os_free(p_sid);
    os_free(node);
}

static void test_wm_kill_children_timeout_kill_child(void ** state) {
    pid_t sid = 10;
    pid_t * p_sid = NULL;
    OSListNode *node;

    wm_kill_timeout = 1;

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);

    pid_t pidOk = 0;
    will_return(__wrap_fork, pidOk);

    expect_value(__wrap_kill,pid,sid*(-1));
    expect_value(__wrap_kill,sig,SIGTERM);
    will_return(__wrap_kill,0);

    will_return(__wrap_sleep, OS_SUCCESS);

    expect_value(__wrap_kill,pid,sid*(-1));
    expect_value(__wrap_kill,sig,0);
    will_return(__wrap_kill,-1);

    errno = 3;

    expect_function_call(__wrap_exit);

    expect_string(__wrap__merror, formatted_msg, "wm_kill_children(): Couldn't wait PID 10: (3) No such process.");

    expect_function_call(__wrap_exit);

    expect_string(__wrap__mdebug1, formatted_msg, "Killing process group 10");

    expect_value(__wrap_kill,pid,sid*(-1));
    expect_value(__wrap_kill,sig,SIGKILL);
    will_return(__wrap_kill,0);

    expect_function_call(__wrap_exit);

    test_mode = false;

    wm_kill_children(sid);

    os_free(p_sid);
    os_free(node);
}

static void test_wm_kill_children_parent(void ** state) {
    pid_t sid = 10;
    pid_t * p_sid = NULL;
    OSListNode *node;

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);

    pid_t pidParent = 1;
    will_return(__wrap_fork, pidParent);

    test_mode = false;

    wm_kill_children(sid);

    os_free(p_sid);
    os_free(node);
}

#else
static void test_wm_append_handle(void ** state) {

}

static void test_wm_remove_handle(void ** state) {

}

static void test_wm_kill_children_fork_failed_win(void ** state) {

}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wm_exec_accented_command),
        cmocka_unit_test(test_wm_exec_not_accented_command),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_wm_append_sid_null_list, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_wm_append_sid_fail, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_append_sid_success, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_null_list, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_not_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_success, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_fork_failed, setup_modules, NULL),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_timeout_kill_child, setup_modules, NULL),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_parent, setup_modules, NULL)
#else
        cmocka_unit_test_setup_teardown(test_wm_append_handle, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_handle, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_win, setup_modules, teardown_modules)
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
