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
#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/posix/signal_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"

bool w_macos_es_is_executable(void);
char ** w_macos_es_create_argv(const char * events);
wfd_t * w_macos_es_exec(char ** argv);

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

static int setup_wfd(void ** state) {
    wfd_t * wfd = calloc(1, sizeof(wfd_t));

    *state = wfd;

    return 0;
}

static int teardown_wfd(void ** state) {
    wfd_t * wfd = *state;

    free(wfd);

    return 0;
}

/* w_macos_es_is_executable */

void test_w_macos_es_is_executable_success(void ** state) {

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 0);

    bool ret = w_macos_es_is_executable();

    assert_true(ret);
}

void test_w_macos_es_is_executable_error_does_not_log(void ** state) {

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    bool ret = w_macos_es_is_executable();

    assert_false(ret);
}

/* w_macos_es_create_argv */

void test_w_macos_es_create_argv_single(void ** state) {

    char ** argv = w_macos_es_create_argv("openssh_logout");

    assert_string_equal(argv[0], "/usr/bin/eslogger");
    assert_string_equal(argv[1], "openssh_logout");
    assert_null(argv[2]);

    free_strarray(argv);
}

void test_w_macos_es_create_argv_multiple(void ** state) {

    char ** argv = w_macos_es_create_argv("authentication,login_login,openssh_logout");

    assert_string_equal(argv[0], "/usr/bin/eslogger");
    assert_string_equal(argv[1], "authentication");
    assert_string_equal(argv[2], "login_login");
    assert_string_equal(argv[3], "openssh_logout");
    assert_null(argv[4]);

    free_strarray(argv);
}

/* w_macos_es_exec */

void test_w_macos_es_exec_wpopenv_error(void ** state) {

    char * argv[] = { "/usr/bin/eslogger", "authentication", NULL };

    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1974): An error ocurred while calling wpopenv(): Success (0).");

    wfd_t * ret = w_macos_es_exec(argv);

    assert_null(ret);
}

void test_w_macos_es_exec_fileno_error(void ** state) {

    wfd_t * wfd = *state;
    wfd->file_out = (FILE *) 1234;
    char * argv[] = { "/usr/bin/eslogger", "authentication", NULL };

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 0);

    expect_string(__wrap__merror, formatted_msg,
                  "(1613): The file descriptor couldn't be obtained from the file pointer of the eslogger pipe: "
                  "Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_es_exec(argv);

    assert_null(ret);
}

void test_w_macos_es_exec_get_flags_error(void ** state) {

    wfd_t * wfd = *state;
    wfd->file_out = (FILE *) 1234;
    char * argv[] = { "/usr/bin/eslogger", "authentication", NULL };

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, -1);

    expect_string(__wrap__merror, formatted_msg,
                  "(1972): The flags couldn't be obtained from the file descriptor: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_es_exec(argv);

    assert_null(ret);
}

void test_w_macos_es_exec_set_flags_error(void ** state) {

    wfd_t * wfd = *state;
    wfd->file_out = (FILE *) 1234;
    char * argv[] = { "/usr/bin/eslogger", "authentication", NULL };

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, -1);

    expect_string(__wrap__merror, formatted_msg,
                  "(1973): The flags couldn't be set in the file descriptor: Success (0).");

    will_return(__wrap_wpclose, 0);

    wfd_t * ret = w_macos_es_exec(argv);

    assert_null(ret);
}

void test_w_macos_es_exec_success(void ** state) {

    wfd_t * wfd = *state;
    wfd->file_out = (FILE *) 1234;
    char * argv[] = { "/usr/bin/eslogger", "authentication", NULL };

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fileno, __stream, wfd->file_out);
    will_return(__wrap_fileno, 1);

    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);

    wfd_t * ret = w_macos_es_exec(argv);

    assert_ptr_equal(ret, wfd);

    assert_int_equal(wpopenv_captured_argc(), 2);
    assert_string_equal(wpopenv_captured_argv(0), "/usr/bin/eslogger");
    assert_string_equal(wpopenv_captured_argv(1), "authentication");
}

/* w_macos_es_note_failure */

void test_w_macos_es_note_failure_growth_and_cap(void ** state) {
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    const unsigned int expected_delay[] = { 5, 10, 20, 40, 80, 160, 300, 300 };
    size_t i;

    for (i = 0; i < sizeof(expected_delay) / sizeof(expected_delay[0]); i++) {
        will_return(__wrap_time, 1000 + (time_t) i * (MACOS_ES_WARN_THROTTLE_SEC + 1));

        bool should_log = w_macos_es_note_failure(&cfg);

        assert_true(should_log);
        assert_int_equal(cfg.next_spawn_at, 1000 + (time_t) i * (MACOS_ES_WARN_THROTTLE_SEC + 1) + expected_delay[i]);
    }

    assert_int_equal(cfg.failures, sizeof(expected_delay) / sizeof(expected_delay[0]));
}

void test_w_macos_es_note_failure_throttle(void ** state) {
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    will_return(__wrap_time, 1000);
    assert_true(w_macos_es_note_failure(&cfg));

    will_return(__wrap_time, 1005);
    assert_true(w_macos_es_note_failure(&cfg));

    will_return(__wrap_time, 1010);
    assert_true(w_macos_es_note_failure(&cfg));

    will_return(__wrap_time, 1015);
    assert_false(w_macos_es_note_failure(&cfg));

    will_return(__wrap_time, 1010 + MACOS_ES_WARN_THROTTLE_SEC);
    assert_true(w_macos_es_note_failure(&cfg));
}

/* w_macos_es_release */

void test_w_macos_es_release_null_macos_es(void ** state) {
    logreader lf;
    lf.macos_es = NULL;

    w_macos_es_release(&lf);
}

void test_w_macos_es_release_null_wfd(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    lf.macos_es = &cfg;

    w_macos_es_release(&lf);
}

void test_w_macos_es_release_running_process(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.pid = 555;
    cfg.wfd = &wfd;
    strcpy(cfg.ctxt_buffer, "{\"event\":");
    cfg.discarding = true;
    lf.macos_es = &cfg;

    expect_value(__wrap_kill, pid, 555);
    expect_value(__wrap_kill, sig, SIGTERM);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, 0);

    w_macos_es_release(&lf);

    assert_null(cfg.wfd);
    assert_string_equal(cfg.ctxt_buffer, "");
    assert_false(cfg.discarding);
}

/* w_macos_es_release_reaped */

void test_w_macos_es_release_reaped_null_wfd(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    lf.macos_es = &cfg;

    w_macos_es_release_reaped(&lf);
}

void test_w_macos_es_release_reaped_does_not_signal_or_wait(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t * wfd = calloc(1, sizeof(wfd_t));
    wfd->pid = 555;
    wfd->file_out = (FILE *) 1234;
    cfg.wfd = wfd;
    strcpy(cfg.ctxt_buffer, "{\"event\":");
    lf.macos_es = &cfg;

    expect_fclose((FILE *) 1234, 0);

    w_macos_es_release_reaped(&lf);

    assert_null(cfg.wfd);
    assert_string_equal(cfg.ctxt_buffer, "");
}

/* w_macos_es_ensure_running */

void test_w_macos_es_ensure_running_already_running(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    cfg.wfd = &wfd;
    lf.macos_es = &cfg;

    w_macos_es_ensure_running(&lf);

    assert_ptr_equal(cfg.wfd, &wfd);
}

void test_w_macos_es_ensure_running_backoff_not_elapsed(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.next_spawn_at = 2000;
    lf.macos_es = &cfg;

    will_return(__wrap_time, 1000);

    w_macos_es_ensure_running(&lf);

    assert_null(cfg.wfd);
}

void test_w_macos_es_ensure_running_not_executable(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    lf.macos_es = &cfg;
    lf.events = NULL;

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    will_return(__wrap_time, 1000);

    expect_string(__wrap__merror, formatted_msg, "(1250): Error trying to execute \"/usr/bin/eslogger\": Success (0).");

    w_macos_es_ensure_running(&lf);

    assert_null(cfg.wfd);
    assert_int_equal(cfg.failures, 1);
}

void test_w_macos_es_ensure_running_not_executable_throttled(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.failures = MACOS_ES_WARN_THROTTLE_AFTER;
    cfg.last_warn_at = 1000;
    lf.macos_es = &cfg;
    lf.events = NULL;

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    will_return(__wrap_time, 1010);

    w_macos_es_ensure_running(&lf);

    assert_null(cfg.wfd);
    assert_int_equal(cfg.failures, MACOS_ES_WARN_THROTTLE_AFTER + 1);
}

void test_w_macos_es_ensure_running_exec_fails(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    lf.macos_es = &cfg;
    lf.events = "authentication";

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 0);

    will_return(__wrap_wpopenv, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1974): An error ocurred while calling wpopenv(): Success (0).");

    will_return(__wrap_time, 1000);

    expect_string(__wrap__merror, formatted_msg,
                  "(1612): Error while trying to execute `eslogger` as follows: /usr/bin/eslogger authentication.");

    w_macos_es_ensure_running(&lf);

    assert_null(cfg.wfd);
    assert_int_equal(cfg.failures, 1);
}

void test_w_macos_es_ensure_running_success(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    lf.macos_es = &cfg;
    lf.events = "authentication";
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.file_out = (FILE *) 1234;

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 0);

    will_return(__wrap_wpopenv, &wfd);
    expect_value(__wrap_fileno, __stream, wfd.file_out);
    will_return(__wrap_fileno, 1);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);

    expect_string(__wrap__minfo, formatted_msg,
                  "(9205): Monitoring macOS Endpoint Security events with: /usr/bin/eslogger authentication.");

    will_return(__wrap_time, 1000);

    w_macos_es_ensure_running(&lf);

    assert_ptr_equal(cfg.wfd, &wfd);
    assert_int_equal(cfg.started_at, 1000);
    assert_int_equal(cfg.failures, 0);
}

void test_w_macos_es_ensure_running_respawn_after_failure_streak_logs_start(void ** state) {
    logreader lf;
    w_macos_es_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.failures = MACOS_ES_WARN_THROTTLE_AFTER + 1;
    cfg.next_spawn_at = 1000;
    lf.macos_es = &cfg;
    lf.events = "authentication";
    wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    wfd.file_out = (FILE *) 1234;

    will_return(__wrap_time, 1000);

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 0);

    will_return(__wrap_wpopenv, &wfd);
    expect_value(__wrap_fileno, __stream, wfd.file_out);
    will_return(__wrap_fileno, 1);
    will_return(__wrap_fcntl, 0);
    will_return(__wrap_fcntl, 0);

    expect_string(__wrap__minfo, formatted_msg,
                  "(9205): Monitoring macOS Endpoint Security events with: /usr/bin/eslogger authentication.");

    will_return(__wrap_time, 1000);

    w_macos_es_ensure_running(&lf);

    assert_ptr_equal(cfg.wfd, &wfd);
}

/* w_macos_es_create_env */

void test_w_macos_es_create_env_eslogger_missing(void ** state) {
    logreader lf;
    memset(&lf, 0, sizeof(lf));
    os_strdup("macos-es", lf.file);

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap__mwarn, formatted_msg,
                  "(8026): '/usr/bin/eslogger' not found. The 'macos-es' log format requires macOS 13 or later and "
                  "will be disabled.");

    w_macos_es_create_env(&lf);

    assert_null(lf.macos_es);
    assert_null(lf.file);
}

void test_w_macos_es_create_env_allocates_and_tries_first_spawn(void ** state) {
    logreader lf;
    memset(&lf, 0, sizeof(lf));
    os_strdup("macos-es", lf.file);

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    expect_string(__wrap_access, __name, "/usr/bin/eslogger");
    expect_value(__wrap_access, __type, X_OK);
    will_return(__wrap_access, 1);

    will_return(__wrap_time, 1000);

    expect_string(__wrap__merror, formatted_msg, "(1250): Error trying to execute \"/usr/bin/eslogger\": Success (0).");

    w_macos_es_create_env(&lf);

    assert_non_null(lf.macos_es);
    assert_null(lf.macos_es->wfd);
    assert_int_equal(lf.macos_es->failures, 1);
    assert_null(lf.file);

    os_free(lf.macos_es);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        // Tests w_macos_es_is_executable
        cmocka_unit_test(test_w_macos_es_is_executable_success),
        cmocka_unit_test(test_w_macos_es_is_executable_error_does_not_log),
        // Tests w_macos_es_create_argv
        cmocka_unit_test(test_w_macos_es_create_argv_single),
        cmocka_unit_test(test_w_macos_es_create_argv_multiple),
        // Tests w_macos_es_exec
        cmocka_unit_test_setup_teardown(test_w_macos_es_exec_wpopenv_error, setup_wfd, teardown_wfd),
        cmocka_unit_test_setup_teardown(test_w_macos_es_exec_fileno_error, setup_wfd, teardown_wfd),
        cmocka_unit_test_setup_teardown(test_w_macos_es_exec_get_flags_error, setup_wfd, teardown_wfd),
        cmocka_unit_test_setup_teardown(test_w_macos_es_exec_set_flags_error, setup_wfd, teardown_wfd),
        cmocka_unit_test_setup_teardown(test_w_macos_es_exec_success, setup_wfd, teardown_wfd),
        // Tests w_macos_es_note_failure
        cmocka_unit_test(test_w_macos_es_note_failure_growth_and_cap),
        cmocka_unit_test(test_w_macos_es_note_failure_throttle),
        // Tests w_macos_es_release
        cmocka_unit_test(test_w_macos_es_release_null_macos_es),
        cmocka_unit_test(test_w_macos_es_release_null_wfd),
        cmocka_unit_test(test_w_macos_es_release_running_process),
        // Tests w_macos_es_release_reaped
        cmocka_unit_test(test_w_macos_es_release_reaped_null_wfd),
        cmocka_unit_test(test_w_macos_es_release_reaped_does_not_signal_or_wait),
        // Tests w_macos_es_ensure_running
        cmocka_unit_test(test_w_macos_es_ensure_running_already_running),
        cmocka_unit_test(test_w_macos_es_ensure_running_backoff_not_elapsed),
        cmocka_unit_test(test_w_macos_es_ensure_running_not_executable),
        cmocka_unit_test(test_w_macos_es_ensure_running_not_executable_throttled),
        cmocka_unit_test(test_w_macos_es_ensure_running_exec_fails),
        cmocka_unit_test(test_w_macos_es_ensure_running_success),
        cmocka_unit_test(test_w_macos_es_ensure_running_respawn_after_failure_streak_logs_start),
        // Tests w_macos_es_create_env
        cmocka_unit_test(test_w_macos_es_create_env_eslogger_missing),
        cmocka_unit_test(test_w_macos_es_create_env_allocates_and_tries_first_spawn),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
