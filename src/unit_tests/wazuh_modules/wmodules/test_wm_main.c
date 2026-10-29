/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the wazuh-modulesd signal handler
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define main wm_main
#include "../../../wazuh_modules/src/main.c"
#undef main

static bool grace_wait_done = false;
static int shutdown_flag_during_grace_wait = -1;
static int stop_calls = 0;
static bool stopped_before_grace_wait = false;

// Replaces wm_handler()'s grace sleep(1).
unsigned int __wrap_sleep(unsigned int seconds) {
    check_expected(seconds);
    shutdown_flag_during_grace_wait = wm_shutdown_requested;
    grace_wait_done = true;
    return 0;
}

// exit() is noreturn: end the handler through expect_assert_failure(), as test_agentd.c does.
void __wrap_exit(int code) {
    check_expected(code);
    mock_assert(0, "exit called", __FILE__, __LINE__);
}

// wm_setup() collaborators: a configuration test must stop before the PID file and the children pool.
int __wrap_wm_config(void) {
    return 0;
}

int __wrap_wm_check(void) {
    return 0;
}

void __wrap_w_read_agent_batch(__attribute__((unused)) const char *cfgfile,
                               __attribute__((unused)) const char *sharedcfg,
                               __attribute__((unused)) agent_batch *batch) {
}

int __wrap_getDefine_Int_default(__attribute__((unused)) const char *high_name,
                                 __attribute__((unused)) const char *low_name,
                                 __attribute__((unused)) int min,
                                 __attribute__((unused)) int max,
                                 int default_val) {
    return default_val;
}

gid_t __wrap_Privsep_GetGroup(__attribute__((unused)) const char *name) {
    return getgid();
}

int __wrap_Privsep_SetGroup(__attribute__((unused)) gid_t gid) {
    return 0;
}

int __wrap_CreatePID(__attribute__((unused)) const char *name, __attribute__((unused)) int pid) {
    fail_msg("CreatePID() must not run under -t");
    return -1;
}

void __wrap_wm_children_pool_init(void) {
    fail_msg("wm_children_pool_init() must not run under -t");
}

static void record_stop(void * data) {
    (void)data;
    stop_calls++;
    if (!grace_wait_done) {
        stopped_before_grace_wait = true;
    }
}

// The flag must be up during the grace wait (wm_fim_query_json() and modulesSync() read it there),
// and the stop() callbacks must still run after the wait.
static void test_sigterm_raises_shutdown_flag_before_grace_wait(void ** state) {
    (void)state;
    static const wm_context context = { .name = "fake", .stop = record_stop };
    static wmodule module = { .context = &context };

    wmodules = &module;
    wm_shutdown_requested = 0;

    expect_value(__wrap_sleep, seconds, 1);
    expect_value(__wrap_exit, code, EXIT_SUCCESS);

    expect_assert_failure(wm_handler(SIGTERM));

    assert_int_equal(shutdown_flag_during_grace_wait, 1);
    assert_int_equal(stop_calls, 1);
    assert_false(stopped_before_grace_wait);

    wmodules = NULL;
}

// -t (configuration test) reads and validates only: it must neither write a PID file nor start the
// children pool, so a configuration check writes nothing under var/run.
static void test_setup_in_test_mode_creates_no_pid_file(void ** state) {
    (void)state;

    flag_test_config = 1;
    flag_foreground = 1;

    wm_setup();

    flag_test_config = 0;
    flag_foreground = 0;
}

int main(void) {
    // wm_handler() handles a single signal per process, so this binary holds a single handler test.
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_setup_in_test_mode_creates_no_pid_file),
        cmocka_unit_test(test_sigterm_raises_shutdown_flag_before_grace_wait),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
