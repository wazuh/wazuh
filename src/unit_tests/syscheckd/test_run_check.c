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

int __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

int __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...)
{
    check_expected(msg);
    return 1;
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    if (mock()) {
       char formatted_msg[OS_MAXSTR];
        va_list args;

        va_start(args, msg);
        vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
        va_end(args);

        check_expected(formatted_msg);
    }
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
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
    return 1;
}

int __wrap_lstat(const char *filename, struct stat *buf) {
    check_expected(filename);
    return mock();
}

void __wrap_fim_checker(char *path) {
    check_expected(path);
}

int __wrap_fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(storage);

    *file = mock_type(fim_tmp_file *);

    return mock();
}

int __wrap_fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(storage);
    check_expected_ptr(file);

    return mock();
}

int __wrap_fim_configuration_directory() {
    return mock();
}

int __wrap_inotify_rm_watch() {
    return mock();
}

/* Setup */

static int setup(void ** state) {
    (void) state;

    will_return_always(__wrap__mdebug1, 0);

    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.max_eps = 100;
    syscheck.sync_max_eps = 10;

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if(syscheck.realtime == NULL) {
        return -1;
    }

    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        return -1;
    }

    OSHash_Add_ex(syscheck.realtime->dirtb, "key", strdup("data"));

    return 0;
}

static int setup_tmp_file(void **state) {
    fim_tmp_file *tmp_file = calloc(1, sizeof(fim_tmp_file));
    tmp_file->elements = 1;

    *state = tmp_file;

    return 0;
}

/* teardown */

static int free_syscheck(void **state) {
    (void) state;

    Free_Syscheck(&syscheck);

    return 0;
}

static int teardown_tmp_file(void **state) {
    fim_tmp_file *tmp_file = *state;
    free(tmp_file);

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

    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);

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

    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);

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
    (void) state;

    expect_string(__wrap__mdebug2, msg, FIM_SEND);
    expect_string(__wrap_SendMSG, message, "{\"type\":\"scan_start\",\"data\":{\"timestamp\":1}}");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_scan_info(FIM_SCAN_START);
}

void test_fim_link_update(void **state) {
    (void) state;

    int pos = 0;
    char *link_path = "/folder/test";

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_string(__wrap_fim_checker, path, link_path);

    fim_link_update(pos, link_path);

    assert_string_equal(syscheck.dir[pos], link_path);
}

void test_fim_link_update_already_added(void **state) {
    (void) state;

    int pos = 0;
    char *link_path = "/folder/test";

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    will_return(__wrap__mdebug1, 1);
    expect_string(__wrap__mdebug1, formatted_msg, "(6234): Directory '/folder/test' already monitored, ignoring link '(null)'");

    fim_link_update(pos, link_path);

    assert_string_equal(syscheck.dir[pos], "");
}

void test_fim_link_check_delete(void **state) {
    (void) state;

    int pos = 1;
    char *link_path = "/usr/bin";

    expect_string(__wrap_lstat, filename, link_path);
    will_return(__wrap_lstat, 0);

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    will_return(__wrap_fim_configuration_directory, -1);

    fim_link_check_delete(pos);

    assert_string_equal(syscheck.dir[pos], "");
}

void test_fim_link_check_delete_lstat_error(void **state) {
    (void) state;

    int pos = 2;
    char *link_path = "/usr/sbin";

    expect_string(__wrap_lstat, filename, link_path);
    will_return(__wrap_lstat, -1);

    will_return(__wrap__mdebug1, 1);
    expect_string(__wrap__mdebug1, formatted_msg, "(6222): Stat() function failed on: '/usr/sbin' due to [(0)-(Success)]");

    fim_link_check_delete(pos);

    assert_string_equal(syscheck.dir[pos], link_path);
}

void test_fim_link_check_delete_noentry_error(void **state) {
    (void) state;

    int pos = 2;
    char *link_path = "/usr/sbin";

    expect_string(__wrap_lstat, filename, link_path);
    will_return(__wrap_lstat, -1);

    errno = ENOENT;

    fim_link_check_delete(pos);

    errno = 0;

    assert_string_equal(syscheck.dir[pos], "");
}

void test_fim_delete_realtime_watches(void **state) {
    (void) state;

    int pos = 1;

    will_return(__wrap_fim_configuration_directory, 0);

    will_return(__wrap_fim_configuration_directory, 0);

    will_return(__wrap_inotify_rm_watch, 1);

    fim_delete_realtime_watches(pos);

    assert_null(OSHash_Begin(syscheck.realtime->dirtb, &pos));
}

void test_fim_link_delete_range(void **state) {
    int pos = 3;

    fim_tmp_file *tmp_file = *state;

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, tmp_file);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_value(__wrap_fim_db_delete_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_delete_range, storage, FIM_DB_DISK);
    expect_memory(__wrap_fim_db_delete_range, file, tmp_file, sizeof(tmp_file));
    will_return(__wrap_fim_db_delete_range, FIMDB_OK);

    fim_link_delete_range(pos);
}

void test_fim_link_delete_range_error(void **state) {
    int pos = 3;

    fim_tmp_file *tmp_file = *state;

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, tmp_file);
    will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, "(6708): Failed to delete a range of paths between '/media/' and '/media0'");

    expect_value(__wrap_fim_db_delete_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_delete_range, storage, FIM_DB_DISK);
    expect_memory(__wrap_fim_db_delete_range, file, tmp_file, sizeof(tmp_file));
    will_return(__wrap_fim_db_delete_range, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, "(6708): Failed to delete a range of paths between '/media/' and '/media0'");

    fim_link_delete_range(pos);
}

void test_fim_link_silent_scan(void **state) {
    (void) state;

    int pos = 3;
    char *link_path = "/folder/test";

    expect_string(__wrap_fim_checker, path, link_path);

    fim_link_silent_scan(link_path, pos);
}

void test_fim_link_reload_broken_link_already_monitored(void **state) {
    (void) state;

    int pos = 4;
    char *link_path = "/home";

    will_return(__wrap__mdebug1, 1);
    expect_string(__wrap__mdebug1, formatted_msg, "(6234): Directory '/home' already monitored, ignoring link '(null)'");

    fim_link_reload_broken_link(link_path, pos);

    assert_string_equal(syscheck.dir[pos], link_path);
}

void test_fim_link_reload_broken_link_reload_broken(void **state) {
    (void) state;

    int pos = 5;
    char *link_path = "/test";

    expect_string(__wrap_fim_checker, path, link_path);

    fim_link_reload_broken_link(link_path, pos);

    assert_string_equal(syscheck.dir[pos], link_path);
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
        cmocka_unit_test(test_fim_link_update),
        cmocka_unit_test(test_fim_link_update_already_added),
        cmocka_unit_test(test_fim_link_check_delete),
        cmocka_unit_test(test_fim_link_check_delete_lstat_error),
        cmocka_unit_test(test_fim_link_check_delete_noentry_error),
        cmocka_unit_test(test_fim_delete_realtime_watches),
        cmocka_unit_test_setup_teardown(test_fim_link_delete_range, setup_tmp_file, teardown_tmp_file),
        cmocka_unit_test_setup_teardown(test_fim_link_delete_range_error, setup_tmp_file, teardown_tmp_file),
        cmocka_unit_test(test_fim_link_silent_scan),
        cmocka_unit_test(test_fim_link_reload_broken_link_already_monitored),
        cmocka_unit_test(test_fim_link_reload_broken_link_reload_broken),
    };

    return cmocka_run_group_tests(tests, setup, free_syscheck);
}
