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
#include "../syscheckd/run_check.c"

struct state {
    unsigned int sleep_seconds;
} state;

/* redefinitons/wrapping */

int __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

int __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

int __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

int __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

void __wrap__merror_exit(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

unsigned int __wrap_sleep(unsigned int seconds) {
    state.sleep_seconds += seconds;
    return mock();
}

int __wrap_SendMSG(int queue, const char *message, const char *locmsg, char loc) {
    check_expected(message);
    check_expected(locmsg);
    check_expected(loc);
    return mock();
}

int __wrap_StartMQ(const char *path, short int type) {
    check_expected(path);
    check_expected(type);
    return mock();
}

int __wrap_realtime_adddir() {
    return 1;
}

int __wrap_audit_set_db_consistency() {
    return 1;
}

int __wrap_time() {
    return mock();
}

/* Setup */

static int setup(void ** state) {
    (void) state;
    Read_Syscheck_Config("test_syscheck.conf");
    syscheck.max_eps = 100;
    syscheck.sync_max_eps = 10;
    return 0;
}

/* teardown */

static int free_syscheck(void **state) {
    (void) state;
    Free_Syscheck(&syscheck);
    return 0;
}

/* tests */

void test_fim_whodata_initialize(void **state)
{
    (void) state;
    int ret;

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}

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

void test_fim_send_msg(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_msg(SYSCHECK_MQ, SYSCHECK, "test");
}

void test_fim_send_msg_retry(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    expect_string(__wrap__merror, msg, QUEUE_SEND);

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    fim_send_msg(SYSCHECK_MQ, SYSCHECK, "test");
}

void test_fim_send_msg_retry_error(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    expect_string(__wrap__merror, msg, QUEUE_SEND);

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    expect_string(__wrap__merror_exit, formatted_msg, "(1211): Unable to access queue: '/var/ossec/queue/ossec/queue'. Giving up..");

    // This code shouldn't run
    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    fim_send_msg(SYSCHECK_MQ, SYSCHECK, "test");
}

void test_fim_send_sync_msg_10_eps(void ** _state) {
    (void) _state;
    syscheck.sync_max_eps = 10;

    // We must not sleep the first 9 times

    state.sleep_seconds = 0;

    for (int i = 1; i < syscheck.sync_max_eps; i++) {
        expect_string(__wrap__mdebug2, msg, FIM_DBSYNC_SEND);
        expect_string(__wrap_SendMSG, message, "");
        expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
        expect_value(__wrap_SendMSG, loc, DBSYNC_MQ);
        will_return(__wrap_SendMSG, 0);

        fim_send_sync_msg("");
        assert_int_equal(state.sleep_seconds, 0);
    }

    will_return(__wrap_sleep, 1);

    // After 10 times, sleep one second
    expect_string(__wrap__mdebug2, msg, FIM_DBSYNC_SEND);
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, DBSYNC_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_sync_msg("");
    assert_int_equal(state.sleep_seconds, 1);
}

void test_fim_send_sync_msg_0_eps(void ** _state) {
    (void) _state;
    syscheck.sync_max_eps = 0;

    // We must not sleep
    expect_string(__wrap__mdebug2, msg, FIM_DBSYNC_SEND);
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, DBSYNC_MQ);
    will_return(__wrap_SendMSG, 0);

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
        expect_string(__wrap__mdebug2, msg, FIM_SEND);
        expect_string(__wrap_SendMSG, message, "");
        expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
        expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
        will_return(__wrap_SendMSG, 0);

        send_syscheck_msg("");
        assert_int_equal(state.sleep_seconds, 0);
    }

    will_return(__wrap_sleep, 1);

    // After 10 times, sleep one second
    expect_string(__wrap__mdebug2, msg, FIM_SEND);
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    send_syscheck_msg("");
    assert_int_equal(state.sleep_seconds, 1);
}

void test_send_syscheck_msg_0_eps(void ** _state) {
    (void) _state;
    syscheck.max_eps = 0;

    // We must not sleep
    expect_string(__wrap__mdebug2, msg, FIM_SEND);
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    state.sleep_seconds = 0;

    send_syscheck_msg("");
    assert_int_equal(state.sleep_seconds, 0);
}

void test_fim_send_scan_info(void **state) {
    will_return(__wrap_time, 12345);

    expect_string(__wrap__mdebug2, msg, FIM_SEND);
    expect_string(__wrap_SendMSG, message, "{\"type\":\"scan_start\",\"data\":{\"timestamp\":12345}}");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_scan_info(FIM_SCAN_START);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fim_whodata_initialize),
        cmocka_unit_test(test_log_realtime_status),
        cmocka_unit_test(test_fim_send_msg),
        cmocka_unit_test(test_fim_send_msg_retry),
        cmocka_unit_test(test_fim_send_msg_retry_error),
        cmocka_unit_test(test_fim_send_sync_msg_10_eps),
        cmocka_unit_test(test_fim_send_sync_msg_0_eps),
        cmocka_unit_test(test_send_syscheck_msg_10_eps),
        cmocka_unit_test(test_send_syscheck_msg_0_eps),
        cmocka_unit_test(test_fim_send_scan_info),
    };

    return cmocka_run_group_tests(tests, setup, free_syscheck);
}
