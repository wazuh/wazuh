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

/* --- run_service_restart(): the configuration test before the stop (issue 41420) ---------- */

void __wrap_enable_dll_verification(void) {
    function_called();
}

bool __wrap_config_file_parses(const char *cfg) {
    check_expected(cfg);
    return mock_type(bool);
}

bool __wrap_local_config_readers_accept(void) {
    return mock_type(bool);
}

int __wrap_os_stop_service(void) {
    function_called();
    return mock_type(int);
}

void __wrap__plain_merror(__attribute__((unused)) const char *file, __attribute__((unused)) int line,
                          __attribute__((unused)) const char *func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

static void expect_config_test(bool parses, bool readers_accept) {
    expect_function_call(__wrap_enable_dll_verification);
    expect_string(__wrap_config_file_parses, cfg, WAZUHCONF);
    will_return(__wrap_config_file_parses, parses);
    if (parses) {
        will_return(__wrap_local_config_readers_accept, readers_accept);
    }
}

/* No restart lock or os_stop_service() expectation is queued in the refusals: cmocka fails the test if
 * either is reached. */
static void test_service_restart_refused_when_the_file_does_not_parse(void **state) {
    (void)state;
    expect_config_test(false, false);
    // Logging is not set up yet, so the refusal must not go through merror()
    expect_string(__wrap__plain_merror, formatted_msg, "Configuration test failed; the agent was not restarted.");

    assert_int_equal(run_service_restart(), 1);
}

static void test_service_restart_refused_when_a_reader_rejects(void **state) {
    (void)state;
    expect_config_test(true, false);
    // Logging is set up, so the refusal follows the configured format (json-only included)
    expect_string(__wrap__merror, formatted_msg, "Configuration test failed; the agent was not restarted.");

    assert_int_equal(run_service_restart(), 1);
}

static void test_service_restart_stops_the_service_when_config_test_passes(void **state) {
    (void)state;
    expect_config_test(true, true);
    expect_restart_lock_open((HANDLE)0x10, 0);
    // win_agent.c is built without the Sleep wrapper, so its one-second wait runs for real.
    expect_function_call(__wrap_os_stop_service);
    will_return(__wrap_os_stop_service, 0);
    expect_string(__wrap__merror, formatted_msg, "Failure running stop service.");

    assert_int_equal(run_service_restart(), 1);
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
        cmocka_unit_test_setup_teardown(test_service_restart_refused_when_the_file_does_not_parse, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_service_restart_refused_when_a_reader_rejects, setup_test_mode, teardown_test_mode),
        cmocka_unit_test_setup_teardown(test_service_restart_stops_the_service_when_config_test_passes, setup_test_mode, teardown_test_mode),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else

int main(void) {
    return 0;
}

#endif
