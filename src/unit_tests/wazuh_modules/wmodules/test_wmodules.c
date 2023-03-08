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

#include "../../../wazuh_modules/wmodules.h"

static size_t echo(void * module, char * query, char ** output) {
    (void)module;
    *output = strdup(query);
    return strlen(query);
}

static int setup_modules(void ** state) {
    static wm_context CONTEXTS[] = {
        { .name = "A", .query = echo },
        { .name = "B", .query = NULL },
    };

    wmodules = calloc(1, sizeof(wmodule));
    wmodules->context = &CONTEXTS[0];
    wmodules->next = calloc(1, sizeof(wmodule));
    wmodules->next->context = &CONTEXTS[1];

    *state = NULL;
    return 0;
}

static int teardown_modules(void ** state) {
    free(*state);
    free(wmodules->next);
    free(wmodules);

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

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_find_module_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_find_module_not_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_args, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_module, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_queries, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_echo, setup_modules, teardown_modules),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
