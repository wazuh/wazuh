/*
 * Copyright (C) Wazuh Inc.
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

#include "os_win.h"
#include "../wrappers/windows/winsvc_wrappers.h"
#include "../wrappers/common.h"
#include "../wrappers/windows/fileapi_wrappers.h"
#include "../wrappers/windows/synchapi_wrappers.h"
#include "../wrappers/windows/errhandlingapi_wrappers.h"

#ifdef TEST_WINAGENT

/* --- CheckServiceRunning(): issue 38428 defect #6 ------------------------
 *
 * Before the fix, this returned 1 only for SERVICE_RUNNING, so the
 * service-restart wait loop in win_agent.c gave up the instant the SCM
 * reported SERVICE_STOP_PENDING -- long before the old process had actually
 * finished stop_wmodules() -- and started a new process over it, racing for
 * the same SQLite files ("database is locked"). It must now treat anything
 * other than SERVICE_STOPPED as still running. */

static void test_check_service_running_true_for_running(void **state) {
    (void)state;
    expect_CheckServiceRunning_query(SERVICE_RUNNING);
    assert_int_equal(CheckServiceRunning(), 1);
}

static void test_check_service_running_true_for_stop_pending(void **state) {
    (void)state;
    expect_CheckServiceRunning_query(SERVICE_STOP_PENDING);
    assert_int_equal(CheckServiceRunning(), 1);
}

static void test_check_service_running_true_for_start_pending(void **state) {
    (void)state;
    expect_CheckServiceRunning_query(SERVICE_START_PENDING);
    assert_int_equal(CheckServiceRunning(), 1);
}

static void test_check_service_running_false_for_stopped(void **state) {
    (void)state;
    expect_CheckServiceRunning_query(SERVICE_STOPPED);
    assert_int_equal(CheckServiceRunning(), 0);
}

static void test_check_service_running_false_when_service_missing(void **state) {
    (void)state;
    will_return(wrap_OpenSCManager, (SC_HANDLE)0x1);
    will_return(wrap_OpenService, (SC_HANDLE)NULL);
    will_return(wrap_CloseServiceHandle, TRUE);

    assert_int_equal(CheckServiceRunning(), 0);
}

/* --- acquire_restart_lock() ---------------------------------------------- */

#define RESTART_LOCK "tmp\\service-restart.lock"

static int setup_test_mode(void **state) {
    (void)state;
    test_mode = 1;
    return 0;
}

static int teardown_test_mode(void **state) {
    (void)state;
    test_mode = 0;
    return 0;
}

static void expect_restart_lock_open(HANDLE result, DWORD error) {
    expect_string(wrap_CreateFile, lpFileName, RESTART_LOCK);
    will_return(wrap_CreateFile, result);
    if (result == INVALID_HANDLE_VALUE) {
        expect_GetLastError_call(error);
    }
}

static void test_acquire_restart_lock_free(void **state) {
    (void)state;
    int timed_out = -1;
    expect_restart_lock_open((HANDLE)0x10, 0);

    assert_ptr_equal(acquire_restart_lock(60000, &timed_out), (HANDLE)0x10);
    assert_int_equal(timed_out, 0);
}

static void test_acquire_restart_lock_waits_for_holder(void **state) {
    (void)state;
    int timed_out = -1;
    expect_restart_lock_open(INVALID_HANDLE_VALUE, ERROR_SHARING_VIOLATION);
    expect_value(wrap_Sleep, dwMilliseconds, 500);
    expect_restart_lock_open(INVALID_HANDLE_VALUE, ERROR_SHARING_VIOLATION);
    expect_value(wrap_Sleep, dwMilliseconds, 500);
    expect_restart_lock_open((HANDLE)0x10, 0);

    assert_ptr_equal(acquire_restart_lock(60000, &timed_out), (HANDLE)0x10);
    assert_int_equal(timed_out, 0);
}

static void test_acquire_restart_lock_times_out(void **state) {
    (void)state;
    int timed_out = -1;
    expect_restart_lock_open(INVALID_HANDLE_VALUE, ERROR_SHARING_VIOLATION);
    expect_value(wrap_Sleep, dwMilliseconds, 500);
    expect_restart_lock_open(INVALID_HANDLE_VALUE, ERROR_SHARING_VIOLATION);
    expect_value(wrap_Sleep, dwMilliseconds, 500);
    expect_restart_lock_open(INVALID_HANDLE_VALUE, ERROR_SHARING_VIOLATION);

    assert_ptr_equal(acquire_restart_lock(1000, &timed_out), INVALID_HANDLE_VALUE);
    assert_int_equal(timed_out, 1);
}

static void test_acquire_restart_lock_other_error(void **state) {
    (void)state;
    int timed_out = -1;
    expect_restart_lock_open(INVALID_HANDLE_VALUE, ERROR_PATH_NOT_FOUND);

    assert_ptr_equal(acquire_restart_lock(60000, &timed_out), INVALID_HANDLE_VALUE);
    assert_int_equal(timed_out, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_service_running_true_for_running),
        cmocka_unit_test(test_check_service_running_true_for_stop_pending),
        cmocka_unit_test(test_check_service_running_true_for_start_pending),
        cmocka_unit_test(test_check_service_running_false_for_stopped),
        cmocka_unit_test(test_check_service_running_false_when_service_missing),
        cmocka_unit_test_setup_teardown(test_acquire_restart_lock_free, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_acquire_restart_lock_waits_for_holder, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_acquire_restart_lock_times_out, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_acquire_restart_lock_other_error, setup_test_mode, teardown_test_mode),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else

int main(void) {
    return 0;
}

#endif
