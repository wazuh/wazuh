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
#include <signal.h>

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "startup_gate_op.h"

/* startup_gate_wait_for_ready() is only meaningful on a CLIENT (agent) build;
 * on a manager build it must stay the no-op it always was. */
#if defined(CLIENT)

/* Real definition lives in wazuh_modules/src/wmodules.c. On agent/manager
 * this test binary doesn't link that object, so it provides its own stand-in
 * -- exactly what stop_wmodules()/local_start() flip in the real agent
 * (issue 38428). winagent's unit tests all link a monolithic aggregate of the
 * main build's object files (see winagent.cmake's DEPENDENCIES_O), which
 * already pulls in the real definition -- a second one here would conflict
 * with it at link time, so just reuse it. */
#if defined(TEST_WINAGENT)
extern volatile sig_atomic_t wm_shutdown_requested;
#else
volatile sig_atomic_t wm_shutdown_requested = 0;
#endif

static int teardown_shutdown_flag(void **state) {
    (void)state;
    wm_shutdown_requested = 0;
    return 0;
}

/* This is the core of the 38428 fix: a shutdown already in progress must be
 * reported back distinctly from "the gate genuinely opened", so every caller
 * (win_module_thread(), skthread(), the POSIX daemons' main()) can abort
 * startup instead of racing ahead into a module that's about to be torn
 * down. Before the fix this path returned void -- indistinguishable from a
 * real release. */
static void test_wait_for_ready_returns_shutdown_requested_without_polling(void **state) {
    (void)state;
    wm_shutdown_requested = 1;

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate: shutdown requested, aborting startup for 'wazuh-sca' without waiting for handshake.");

    startup_gate_wait_result_t result = startup_gate_wait_for_ready("wazuh-sca");

    assert_int_equal(result, STARTUP_GATE_SHUTDOWN_REQUESTED);
}

/* A NULL/empty module name must not crash the log line -- falls back to "module". */
static void test_wait_for_ready_shutdown_requested_defaults_module_name(void **state) {
    (void)state;
    wm_shutdown_requested = 1;

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate: shutdown requested, aborting startup for 'module' without waiting for handshake.");

    startup_gate_wait_result_t result = startup_gate_wait_for_ready(NULL);

    assert_int_equal(result, STARTUP_GATE_SHUTDOWN_REQUESTED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_wait_for_ready_returns_shutdown_requested_without_polling, teardown_shutdown_flag),
        cmocka_unit_test_teardown(test_wait_for_ready_shutdown_requested_defaults_module_name, teardown_shutdown_flag),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else

int main(void) {
    return 0;
}

#endif
