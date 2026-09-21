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
#include <stdio.h>

#include "logcollector.h"
#include "macos_es_log.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/linux/wait_wrappers.h"
#include "../wrappers/posix/signal_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"

/* Prototypes (STATIC becomes visible under WAZUH_UNIT_TESTING) */

bool w_macos_es_is_valid_json(const char * line);
bool w_macos_es_getlog(char * buffer, int length, FILE * stream, w_macos_es_config_t * macos_es_cfg);
void w_macos_es_check_exit(logreader * lf);

extern int maximum_lines;

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

static int setup_cfg(void ** state) {
    w_macos_es_config_t * cfg = calloc(1, sizeof(w_macos_es_config_t));

    *state = cfg;

    return 0;
}

static int teardown_cfg(void ** state) {
    w_macos_es_config_t * cfg = *state;

    free(cfg);

    return 0;
}

/* wraps */

int __wrap_can_read() {
    return mock_type(int);
}

int __wrap_w_msg_hash_queues_push(const char * str, char * file, unsigned long size, logtarget * targets,
                                   char queue_mq) {
    check_expected(str);
    check_expected(file);
    check_expected(size);
    return mock_type(int);
}

/* w_macos_es_is_valid_json */

void test_w_macos_es_is_valid_json_valid(void ** state) {
    assert_true(w_macos_es_is_valid_json("{\"event\":\"authentication\"}"));
}

void test_w_macos_es_is_valid_json_invalid(void ** state) {
    assert_false(w_macos_es_is_valid_json("not json at all"));
}

/* w_macos_es_getlog */

void test_w_macos_es_getlog_no_data(void ** state) {
    w_macos_es_config_t * cfg = *state;
    char buffer[256];

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    bool ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);

    assert_false(ret);
    assert_string_equal(cfg->ctxt_buffer, "");
}

void test_w_macos_es_getlog_cannot_read(void ** state) {
    w_macos_es_config_t * cfg = *state;
    char buffer[256];

    will_return(__wrap_can_read, 0);

    bool ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);

    assert_false(ret);
}

void test_w_macos_es_getlog_partial_line(void ** state) {
    w_macos_es_config_t * cfg = *state;
    char buffer[256];

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "{\"event\":");

    bool ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);

    assert_false(ret);
    assert_string_equal(cfg->ctxt_buffer, "{\"event\":");
}

void test_w_macos_es_getlog_split_across_reads(void ** state) {
    w_macos_es_config_t * cfg = *state;
    char buffer[256];

    /* First read: partial line, saved into ctxt_buffer */
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "{\"event\":");

    bool ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);
    assert_false(ret);

    /* Second read: rest of the line arrives, completing the record */
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\"authentication\"}\n");

    ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);

    assert_true(ret);
    assert_string_equal(buffer, "{\"event\":\"authentication\"}");
    assert_string_equal(cfg->ctxt_buffer, "");
}

void test_w_macos_es_getlog_two_records_in_one_chunk(void ** state) {
    w_macos_es_config_t * cfg = *state;
    char buffer[256];

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "{\"a\":1}\n");

    bool ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);
    assert_true(ret);
    assert_string_equal(buffer, "{\"a\":1}");

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "{\"b\":2}\n");

    ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);
    assert_true(ret);
    assert_string_equal(buffer, "{\"b\":2}");
}

void test_w_macos_es_getlog_oversize_drop(void ** state) {
    w_macos_es_config_t * cfg = *state;
    char buffer[10];

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "123456789"); // 9 chars, no '\n', fills buffer[10] to the brim

    expect_string(__wrap__mdebug1, formatted_msg,
                  "macOS ES: Maximum message length reached. The record was discarded.");

    will_return(__wrap_fgetc, 'x');
    will_return(__wrap_fgetc, 'x');
    will_return(__wrap_fgetc, '\n');

    bool ret = w_macos_es_getlog(buffer, sizeof(buffer), (FILE *) 1, cfg);

    assert_false(ret);
    assert_string_equal(buffer, "");
    assert_string_equal(cfg->ctxt_buffer, "");
}

/* read_macos_es */

void test_read_macos_es_wfd_null(void ** state) {
    logreader lf;
    memset(&lf, 0, sizeof(logreader));
    lf.macos_es = NULL;
    int rc = -1;

    void * ret = read_macos_es(&lf, &rc, 0);

    assert_null(ret);
    assert_int_equal(rc, 0);
}

void test_read_macos_es_cannot_read(void ** state) {
    logreader lf;
    memset(&lf, 0, sizeof(logreader));
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    cfg.wfd = &wfd;
    lf.macos_es = &cfg;
    int rc = -1;

    will_return(__wrap_can_read, 0);

    void * ret = read_macos_es(&lf, &rc, 0);

    assert_null(ret);
}

void test_read_macos_es_pushes_valid_json(void ** state) {
    logreader lf;
    memset(&lf, 0, sizeof(logreader));
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.pid = 4242;
    cfg.wfd = &wfd;
    lf.macos_es = &cfg;
    maximum_lines = 1000;
    int rc = -1;

    will_return(__wrap_can_read, 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "{\"event\":\"openssh_logout\"}\n");

    expect_string(__wrap_w_msg_hash_queues_push, str, "{\"event\":\"openssh_logout\"}");
    expect_string(__wrap_w_msg_hash_queues_push, file, MACOS_ES);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("{\"event\":\"openssh_logout\"}") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    /* Exit check: still running */
    expect_value(__wrap_waitpid, __pid, 4242);
    expect_value(__wrap_waitpid, __options, WNOHANG);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 0);

    void * ret = read_macos_es(&lf, &rc, 0);

    assert_null(ret);
}

void test_read_macos_es_warns_on_invalid_json(void ** state) {
    logreader lf;
    memset(&lf, 0, sizeof(logreader));
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.pid = 4242;
    cfg.wfd = &wfd;
    lf.macos_es = &cfg;
    maximum_lines = 1000;
    int rc = -1;

    will_return(__wrap_can_read, 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "not json\n");

    expect_string(__wrap__mwarn, formatted_msg, "(8024): macOS ES: Discarding non-JSON line: 'not json'.");

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    /* Exit check: still running */
    expect_value(__wrap_waitpid, __pid, 4242);
    expect_value(__wrap_waitpid, __options, WNOHANG);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 0);

    void * ret = read_macos_es(&lf, &rc, 0);

    assert_null(ret);
}

/* w_macos_es_check_exit */

void test_w_macos_es_check_exit_still_running(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.pid = 111;
    cfg.wfd = &wfd;
    lf.macos_es = &cfg;

    expect_value(__wrap_waitpid, __pid, 111);
    expect_value(__wrap_waitpid, __options, WNOHANG);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 0);

    w_macos_es_check_exit(&lf);

    assert_ptr_equal(cfg.wfd, &wfd); // untouched
    assert_int_equal(cfg.failures, 0);
}

void test_w_macos_es_check_exit_waitpid_error(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.pid = 111;
    cfg.wfd = &wfd;
    lf.macos_es = &cfg;

    expect_value(__wrap_waitpid, __pid, 111);
    expect_value(__wrap_waitpid, __options, WNOHANG);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, -1);

    expect_string(__wrap__merror, formatted_msg, "(1111): Error during waitpid()-call due to [(0)-(Success)].");

    w_macos_es_check_exit(&lf);

    assert_ptr_equal(cfg.wfd, &wfd); // untouched
}

void test_w_macos_es_check_exit_fast_crash_does_not_reset_failures(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.pid = 111;
    cfg.wfd = &wfd;
    cfg.failures = 2; // already failing repeatedly
    cfg.started_at = 1000;
    lf.macos_es = &cfg;

    expect_value(__wrap_waitpid, __pid, 111);
    expect_value(__wrap_waitpid, __options, WNOHANG);
    will_return(__wrap_waitpid, 1); // exit status (unused by the assertion)
    will_return(__wrap_waitpid, 111);

    will_return(__wrap_time, 1005); // uptime = 5s, well under the 60s healthy threshold

    expect_string(__wrap__merror, formatted_msg, "(1614): macOS ES 'eslogger' process exited, pid: 111, exit value: 1.");

    will_return(__wrap_time, 1005); // w_macos_es_note_failure's own time(NULL)

    expect_value(__wrap_kill, pid, 111);
    expect_value(__wrap_kill, sig, SIGTERM);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_es_check_exit(&lf);

    assert_int_equal(cfg.failures, 3); // NOT reset: this run did not stay up long enough
    assert_null(cfg.wfd);
}

void test_w_macos_es_check_exit_healthy_run_resets_failures(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.pid = 111;
    cfg.wfd = &wfd;
    cfg.failures = 5; // was previously failing a lot
    cfg.started_at = 1000;
    lf.macos_es = &cfg;

    expect_value(__wrap_waitpid, __pid, 111);
    expect_value(__wrap_waitpid, __options, WNOHANG);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 111);

    will_return(__wrap_time, 1000 + MACOS_ES_HEALTHY_UPTIME_SEC); // stayed up long enough

    expect_string(__wrap__merror, formatted_msg, "(1614): macOS ES 'eslogger' process exited, pid: 111, exit value: 0.");

    will_return(__wrap_time, 1000 + MACOS_ES_HEALTHY_UPTIME_SEC); // w_macos_es_note_failure's own time(NULL)

    expect_value(__wrap_kill, pid, 111);
    expect_value(__wrap_kill, sig, SIGTERM);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_es_check_exit(&lf);

    assert_int_equal(cfg.failures, 1); // reset to 0 by the healthy run, then +1 for this exit
    assert_null(cfg.wfd);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        // Tests w_macos_es_is_valid_json
        cmocka_unit_test(test_w_macos_es_is_valid_json_valid),
        cmocka_unit_test(test_w_macos_es_is_valid_json_invalid),
        // Tests w_macos_es_getlog
        cmocka_unit_test_setup_teardown(test_w_macos_es_getlog_no_data, setup_cfg, teardown_cfg),
        cmocka_unit_test_setup_teardown(test_w_macos_es_getlog_cannot_read, setup_cfg, teardown_cfg),
        cmocka_unit_test_setup_teardown(test_w_macos_es_getlog_partial_line, setup_cfg, teardown_cfg),
        cmocka_unit_test_setup_teardown(test_w_macos_es_getlog_split_across_reads, setup_cfg, teardown_cfg),
        cmocka_unit_test_setup_teardown(test_w_macos_es_getlog_two_records_in_one_chunk, setup_cfg, teardown_cfg),
        cmocka_unit_test_setup_teardown(test_w_macos_es_getlog_oversize_drop, setup_cfg, teardown_cfg),
        // Tests read_macos_es
        cmocka_unit_test(test_read_macos_es_wfd_null),
        cmocka_unit_test(test_read_macos_es_cannot_read),
        cmocka_unit_test(test_read_macos_es_pushes_valid_json),
        cmocka_unit_test(test_read_macos_es_warns_on_invalid_json),
        // Tests w_macos_es_check_exit
        cmocka_unit_test(test_w_macos_es_check_exit_still_running),
        cmocka_unit_test(test_w_macos_es_check_exit_waitpid_error),
        cmocka_unit_test(test_w_macos_es_check_exit_fast_crash_does_not_reset_failures),
        cmocka_unit_test(test_w_macos_es_check_exit_healthy_run_resets_failures),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
