/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include "../wrappers/windows/aclapi_wrappers.h"

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

/* --- restart_mutex_owner_trusted() ---------------------------------------- */

static PSID well_known_sid(WELL_KNOWN_SID_TYPE type, BYTE *buffer, DWORD size) {
    assert_true(CreateWellKnownSid(type, NULL, buffer, &size));
    return (PSID)buffer;
}

static void test_restart_mutex_owner_trusted_system(void **state) {
    (void)state;
    BYTE buffer[SECURITY_MAX_SID_SIZE];
    expect_GetSecurityInfo_call(well_known_sid(WinLocalSystemSid, buffer, sizeof(buffer)), NULL, ERROR_SUCCESS);
    assert_int_equal(restart_mutex_owner_trusted((HANDLE)0x1), 1);
}

static void test_restart_mutex_owner_trusted_administrators(void **state) {
    (void)state;
    BYTE buffer[SECURITY_MAX_SID_SIZE];
    expect_GetSecurityInfo_call(well_known_sid(WinBuiltinAdministratorsSid, buffer, sizeof(buffer)), NULL, ERROR_SUCCESS);
    assert_int_equal(restart_mutex_owner_trusted((HANDLE)0x1), 1);
}

static void test_restart_mutex_owner_untrusted_user(void **state) {
    (void)state;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID user = NULL;
    /* A local account, S-1-5-21-1-2-3-1001: what a standard user's token sets as owner */
    assert_true(AllocateAndInitializeSid(&nt_authority, 5, SECURITY_NT_NON_UNIQUE, 1, 2, 3, 1001, 0, 0, 0, &user));
    expect_GetSecurityInfo_call(user, NULL, ERROR_SUCCESS);
    assert_int_equal(restart_mutex_owner_trusted((HANDLE)0x1), 0);
    FreeSid(user);
}

static void test_restart_mutex_owner_unreadable(void **state) {
    (void)state;
    BYTE buffer[SECURITY_MAX_SID_SIZE];
    expect_GetSecurityInfo_call(well_known_sid(WinLocalSystemSid, buffer, sizeof(buffer)), NULL, ERROR_ACCESS_DENIED);
    assert_int_equal(restart_mutex_owner_trusted((HANDLE)0x1), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_service_running_true_for_running),
        cmocka_unit_test(test_check_service_running_true_for_stop_pending),
        cmocka_unit_test(test_check_service_running_true_for_start_pending),
        cmocka_unit_test(test_check_service_running_false_for_stopped),
        cmocka_unit_test(test_check_service_running_false_when_service_missing),
        cmocka_unit_test(test_restart_mutex_owner_trusted_system),
        cmocka_unit_test(test_restart_mutex_owner_trusted_administrators),
        cmocka_unit_test(test_restart_mutex_owner_untrusted_user),
        cmocka_unit_test(test_restart_mutex_owner_unreadable),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else

int main(void) {
    return 0;
}

#endif
