/*
 * Copyright (C) 2015, Wazuh Inc.
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

static jmp_buf leave_handler;
static int shutdown_flag_during_grace_sleep = -1;
static bool grace_sleep_reached = false;

// wm_handler() ends in exit(): reaching it means the grace sleep was skipped and nothing was tested.
static void fail_if_grace_sleep_skipped(void) {
    if (!grace_sleep_reached) {
        fprintf(stderr, "wm_handler() exited without reaching its grace sleep\n");
        _exit(EXIT_FAILURE);
    }
}

// Runs inside wm_handler()'s grace sleep(1).
void __wrap_sleep_hook(unsigned int seconds) {
    (void)seconds;
    char * response = NULL;

    grace_sleep_reached = true;
    shutdown_flag_during_grace_sleep = wm_shutdown_requested;

    // agent-info keeps querying FIM, and wazuh-syscheckd got its SIGTERM in the same pass of
    // wazuh-control, so its socket is already closed.
    errno = ECONNREFUSED;
    wm_fim_query_json("{\"command\":\"pause\"}", &response);
    free(response);

    // The rest of wm_handler() stops the modules and calls exit().
    longjmp(leave_handler, 1);
}

// A FIM query in the second between SIGTERM and the module stops is part of the shutdown: DEBUG, not ERROR.
static void test_sigterm_fim_query_during_grace_sleep_is_not_an_error(void ** state) {
    (void)state;
    static char refused_msg[OS_SIZE_128];
    snprintf(refused_msg, sizeof(refused_msg), "WM_FIM_QUERY_JSON: Failed to connect to socket, errno=%d", ECONNREFUSED);

    wm_shutdown_requested = 0;

    expect_value(__wrap_sleep, seconds, 1);
    expect_string(__wrap__mdebug1, formatted_msg, "WM_FIM_QUERY_JSON: Attempting to connect to socket: " SYS_LOCAL_SOCK);
    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, OS_SOCKTERR);
    expect_string(__wrap__mdebug1, formatted_msg, refused_msg);

    atexit(fail_if_grace_sleep_skipped);

    if (setjmp(leave_handler) == 0) {
        wm_handler(SIGTERM);
    }

    assert_int_equal(shutdown_flag_during_grace_sleep, 1);
}

int main(void) {
    // wm_handler() handles a single signal per process, so this binary holds a single test.
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sigterm_fim_query_during_grace_sleep_is_not_an_error),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
