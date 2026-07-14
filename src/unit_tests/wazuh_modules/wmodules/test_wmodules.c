/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the wazuh-modulesd shared functions
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "wmodules.h"

static size_t echo(void * module, char * query, char ** output) {
    (void)module;
    *output = strdup(query);
    return strlen(query);
}

// Sync callback that always fails, to exercise the modulesSync() failure path.
static int sync_fail(const char * args, size_t length) {
    (void)args;
    (void)length;
    return -1;
}

static int setup_modules(void ** state) {
    static wm_context CONTEXTS[] = {
        { .name = "A", .query = echo },
        { .name = "B", .query = NULL },
        { .name = "sca", .sync = sync_fail },
    };

    wmodules = calloc(1, sizeof(wmodule));
    wmodules->context = &CONTEXTS[0];
    wmodules->next = calloc(1, sizeof(wmodule));
    wmodules->next->context = &CONTEXTS[1];
    wmodules->next->next = calloc(1, sizeof(wmodule));
    wmodules->next->next->context = &CONTEXTS[2];
    wmodules->next->next->tag = "sca";

    wm_shutdown_requested = 0;

    *state = NULL;
    return 0;
}

static int teardown_modules(void ** state) {
    free(*state);
    free(wmodules->next->next);
    free(wmodules->next);
    free(wmodules);

    wm_shutdown_requested = 0;

    return 0;
}

static void test_find_module_found(void ** state) {
    (void)state;

    wmodule * m = wm_find_module("A");

    assert_non_null(m);
    assert_string_equal(m->context->name, "A");

    m = wm_find_module("B");

    assert_non_null(m);
    assert_string_equal(m->context->name, "B");
}

static void test_find_module_not_found(void ** state) {
    (void)state;

    wmodule * m = wm_find_module("C");

    assert_null(m);
}

static void test_module_query_no_args(void ** state) {
    char input[] = "none";
    const char EXPECTED_OUTPUT[] = "err {\"error\":1,\"message\":\"Module query needs arguments\"}";

    size_t n = wm_module_query(input, (char **)state);

    assert_string_equal(*state, EXPECTED_OUTPUT);
    assert_int_equal(n, strlen(EXPECTED_OUTPUT));
}

static void test_module_query_no_module(void ** state) {
    char input[] = "C some-command";
    const char EXPECTED_OUTPUT[] = "err {\"error\":2,\"message\":\"Module not found or not configured\"}";

    size_t n = wm_module_query(input, (char **)state);

    assert_string_equal(*state, EXPECTED_OUTPUT);
    assert_int_equal(n, strlen(EXPECTED_OUTPUT));
}

static void test_module_query_no_queries(void ** state) {
    char input[] = "B some-command";
    const char EXPECTED_OUTPUT[] = "err {\"error\":3,\"message\":\"This module does not support queries\"}";

    size_t n = wm_module_query(input, (char **)state);

    assert_string_equal(*state, EXPECTED_OUTPUT);
    assert_int_equal(n, strlen(EXPECTED_OUTPUT));
}

static void test_module_query_echo(void ** state) {
    char input[] = "A echo";

    size_t n = wm_module_query(input, (char **)state);

    assert_string_equal(*state, "echo");
    assert_int_equal(n, 4);
}

// A sync command that keeps failing while the agent is running is a real error: after exhausting
// the retries, modulesSync() must log it at ERROR level.
static void test_modules_sync_failure_while_running(void ** state) {
    (void)state;
    char input[] = "sca_sync payload";

    // One "not ready" debug per retry (WM_MAX_ATTEMPTS attempts after the first one).
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 1");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 2");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 3");
    expect_string(__wrap__merror, formatted_msg, "At modulesSync(): Unable to sync module 'sca': (-1)");

    int ret = modulesSync(input, sizeof(input));

    assert_int_equal(ret, -1);
}

// The same failure during agent shutdown is expected (the module was already stopped on purpose):
// modulesSync() must not retry and must report it at DEBUG level, not ERROR.
static void test_modules_sync_failure_during_shutdown(void ** state) {
    (void)state;
    char input[] = "sca_sync payload";

    wm_shutdown_requested = 1;

    expect_string(__wrap__mdebug1, formatted_msg,
                  "At modulesSync(): skipping sync for module 'sca' (-1): the agent is shutting down.");

    int ret = modulesSync(input, sizeof(input));

    assert_int_equal(ret, -1);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_find_module_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_find_module_not_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_args, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_module, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_queries, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_echo, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_failure_while_running, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_failure_during_shutdown, setup_modules, teardown_modules),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
