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

struct state {
    unsigned int sleep_seconds;
} state;

/* redefinitons/wrapping */

int __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

/* teardown */

static int free_syscheck(void **state)
{
    (void) state;
    Free_Syscheck(&syscheck);
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

/* Setup */

static int setup(void ** state) {
    (void) state;
    syscheck.max_eps = 100;
    syscheck.sync_max_eps = 10;
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
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}

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
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_log_realtime_status),
        cmocka_unit_test_teardown(test_fim_whodata_initialize, free_syscheck),
        cmocka_unit_test(test_fim_whodata_initialize),
        cmocka_unit_test(test_fim_send_sync_msg_10_eps),
        cmocka_unit_test(test_fim_send_sync_msg_0_eps),
        cmocka_unit_test(test_send_syscheck_msg_10_eps),
        cmocka_unit_test(test_send_syscheck_msg_0_eps),
    };

    return cmocka_run_group_tests(tests, setup, NULL);
}
