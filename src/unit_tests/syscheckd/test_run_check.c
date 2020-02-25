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

#ifdef TEST_WINAGENT
void set_priority_windows_thread();
void set_whodata_mode_changes();
#endif

struct state {
    unsigned int sleep_seconds;
} state;

/* redefinitons/wrapping */

int __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

#ifdef TEST_AGENT
char *_read_file(const char *high_name, const char *low_name, const char *defines_file) __attribute__((nonnull(3)));

int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max) {
    int ret;
    char *value;
    char *pt;

    /* Try to read from the local define file */
    value = _read_file(high_name, low_name, "./internal_options.conf");
    if (!value) {
        merror_exit(DEF_NOT_FOUND, high_name, low_name);
    }

    pt = value;
    while (*pt != '\0') {
        if (!isdigit((int)*pt)) {
            merror_exit(INV_DEF, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if ((ret < min) || (ret > max)) {
        merror_exit(INV_DEF, high_name, low_name, value);
    }

    /* Clear memory */
    free(value);

    return (ret);
}

int __wrap_isChroot() {
    return 1;
}
#endif

int __wrap_audit_set_db_consistency() {
    return 1;
}

unsigned int __wrap_sleep(unsigned int seconds) {
    state.sleep_seconds += seconds;
    return 0;
}

int __wrap_SendMSG(int queue, const char *message, const char *locmsg, char loc) {
    (void) queue;
    (void) message;
    (void) locmsg;
    (void) loc;
    return 0;
}

#ifdef TEST_WINAGENT
int __wrap_realtime_adddir(const char *dir, int whodata) {
    check_expected(dir);
    check_expected(whodata);

    return mock();
}

int __wrap_realtime_start(void) {
    return 0;
}
#endif

/* Setup */

static int setup_group(void ** state) {
    (void) state;
    syscheck.max_eps = 100;
    syscheck.sync_max_eps = 10;

    expect_string(__wrap__mdebug1, formatted_msg, "(6287): Reading configuration file: 'test_syscheck.conf'");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 0");

    #if defined(TEST_AGENT) || defined(TEST_WINAGENT)
    expect_string(__wrap__mdebug1, formatted_msg, "(6208): Reading Client Configuration [test_syscheck.conf]");
    #endif

    if(Read_Syscheck_Config("test_syscheck.conf"))
        fail();

    return 0;
}

/* teardown */

static int teardown_group(void **state) {
    (void) state;
    Free_Syscheck(&syscheck);
    return 0;
}

/* tests */

void test_log_realtime_status(void **state)
{
    (void) state;

    log_realtime_status(2);

    expect_string(__wrap__minfo, msg, FIM_REALTIME_STARTED);
    log_realtime_status(1);
    log_realtime_status(1);

    expect_string(__wrap__minfo, msg, FIM_REALTIME_PAUSED);
    log_realtime_status(2);
    log_realtime_status(2);

    expect_string(__wrap__minfo, msg, FIM_REALTIME_RESUMED);
    log_realtime_status(1);
}


void test_fim_whodata_initialize(void **state)
{
    int ret;
    #ifdef TEST_WINAGENT
    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
        NULL
    };
    char expanded_dirs[1][OS_SIZE_1024];
    #endif

    #ifdef TEST_WINAGENT
    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, true);

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_string(__wrap_realtime_adddir, dir, expanded_dirs[i]);
        expect_value(__wrap_realtime_adddir, whodata, 9);
        will_return(__wrap_realtime_adddir, 0);
    }
    #else
    expect_string(__wrap__mdebug1, formatted_msg, "(6227): Directory added for real time monitoring: '/etc'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6227): Directory added for real time monitoring: '/usr/bin'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6227): Directory added for real time monitoring: '/usr/sbin'");
    #endif

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}

#ifdef TEST_WINAGENT
void test_set_priority_windows_thread_highest(void **state) {
    syscheck.process_priority = -10;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '-10'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_HIGHEST);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_above_normal(void **state) {
    syscheck.process_priority = -8;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '-8'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_ABOVE_NORMAL);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_normal(void **state) {
    syscheck.process_priority = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '0'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_NORMAL);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_below_normal(void **state) {
    syscheck.process_priority = 2;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '2'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_BELOW_NORMAL);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_lowest(void **state) {
    syscheck.process_priority = 7;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '7'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_idle(void **state) {
    syscheck.process_priority = 20;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '20'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_IDLE);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_error(void **state) {
    syscheck.process_priority = 10;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, false);

    will_return(wrap_GetLastError, 2345);

    expect_string(__wrap__merror, formatted_msg, "Can't set thread priority: 2345");

    set_priority_windows_thread();
}

#ifdef WIN_WHODATA
void test_set_whodata_mode_changes(void **state) {
    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        NULL
    };
    char expanded_dirs[3][OS_SIZE_1024];

    // Mark directories to be added in realtime
    syscheck.wdata.dirs_status[6].status |= WD_CHECK_REALTIME;
    syscheck.wdata.dirs_status[6].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[7].status |= WD_CHECK_REALTIME;
    syscheck.wdata.dirs_status[7].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[9].status |= WD_CHECK_REALTIME;
    syscheck.wdata.dirs_status[9].status &= ~WD_CHECK_WHODATA;

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_string(__wrap_realtime_adddir, dir, expanded_dirs[i]);
        expect_value(__wrap_realtime_adddir, whodata, 0);
        if(i % 2 != 0) {
            will_return(__wrap_realtime_adddir, 0);
        } else {
            will_return(__wrap_realtime_adddir, 1);
        }
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6225): The 'c:\\windows\\system32\\drivers\\etc' directory starts to be monitored in real-time mode.");
    expect_string(__wrap__merror, formatted_msg, "(6611): 'realtime_adddir' failed, the directory 'c:\\windows\\system32\\wbem'could't be added to real time mode.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6225): The 'c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup' directory starts to be monitored in real-time mode.");

    set_whodata_mode_changes();
}

void test_fim_whodata_initialize_eventchannel(void **state) {
    int ret;
    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
        NULL
    };
    char expanded_dirs[1][OS_SIZE_1024];

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, true);

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_string(__wrap_realtime_adddir, dir, expanded_dirs[i]);
        expect_value(__wrap_realtime_adddir, whodata, 9);
        will_return(__wrap_realtime_adddir, 0);
    }

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}
#endif  // WIN_WHODATA
#endif
void test_fim_send_sync_msg_10_eps(void ** _state) {
    (void) _state;
    syscheck.sync_max_eps = 10;

    // We must not sleep the first 9 times

    state.sleep_seconds = 0;

    for (int i = 1; i < syscheck.sync_max_eps; i++) {
        fim_send_sync_msg("");
        assert_int_equal(state.sleep_seconds, 0);
    }

    // After 10 times, sleep one second

    fim_send_sync_msg("");
    assert_int_equal(state.sleep_seconds, 1);
}

void test_fim_send_sync_msg_0_eps(void ** _state) {
    (void) _state;
    syscheck.sync_max_eps = 0;

    // We must not sleep

    state.sleep_seconds = 0;

    fim_send_sync_msg("");
    assert_int_equal(state.sleep_seconds, 0);
}

void test_send_syscheck_msg_10_eps(void ** _state) {
    (void) _state;
    syscheck.max_eps = 10;

    // We must not sleep the first 9 times

    state.sleep_seconds = 0;

    for (int i = 1; i < syscheck.max_eps; i++) {
        send_syscheck_msg("");
        assert_int_equal(state.sleep_seconds, 0);
    }

    // After 10 times, sleep one second

    send_syscheck_msg("");
    assert_int_equal(state.sleep_seconds, 1);
}

void test_send_syscheck_msg_0_eps(void ** _state) {
    (void) _state;
    syscheck.max_eps = 0;

    // We must not sleep

    state.sleep_seconds = 0;

    send_syscheck_msg("");
    assert_int_equal(state.sleep_seconds, 0);
}

int main(void) {
    #ifndef WIN_WHODATA
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_log_realtime_status),
        cmocka_unit_test(test_fim_whodata_initialize),

        #ifdef TEST_WINAGENT
        cmocka_unit_test(test_set_priority_windows_thread_highest),
        cmocka_unit_test(test_set_priority_windows_thread_above_normal),
        cmocka_unit_test(test_set_priority_windows_thread_normal),
        cmocka_unit_test(test_set_priority_windows_thread_below_normal),
        cmocka_unit_test(test_set_priority_windows_thread_lowest),
        cmocka_unit_test(test_set_priority_windows_thread_idle),
        cmocka_unit_test(test_set_priority_windows_thread_error),
        #endif

        cmocka_unit_test(test_fim_send_sync_msg_10_eps),
        cmocka_unit_test(test_fim_send_sync_msg_0_eps),
        cmocka_unit_test(test_send_syscheck_msg_10_eps),
        cmocka_unit_test(test_send_syscheck_msg_0_eps),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
    #else  // WIN_WHODATA
    const struct CMUnitTest eventchannel_tests[] = {
        cmocka_unit_test(test_set_whodata_mode_changes),
        cmocka_unit_test(test_fim_whodata_initialize_eventchannel),
    };
    return cmocka_run_group_tests(eventchannel_tests, setup_group, teardown_group);
    #endif
}
