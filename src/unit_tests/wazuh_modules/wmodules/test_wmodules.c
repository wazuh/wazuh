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

static void test_url_is_allowed_null_url(void ** state) {
    assert_false(wm_url_is_allowed(NULL, "api.github.com"));
}

static void test_url_is_allowed_matching_host(void ** state) {
    assert_true(wm_url_is_allowed("https://api.github.com/organizations/1/audit-log?after=x", "api.github.com"));
}

static void test_url_is_allowed_matching_host_no_path(void ** state) {
    assert_true(wm_url_is_allowed("https://api.github.com", "api.github.com"));
}

static void test_url_is_allowed_plain_http(void ** state) {
    assert_false(wm_url_is_allowed("http://api.github.com/audit-log", "api.github.com"));
}

static void test_url_is_allowed_other_scheme(void ** state) {
    assert_false(wm_url_is_allowed("file:///etc/passwd", "api.github.com"));
    assert_false(wm_url_is_allowed("gopher://api.github.com/", "api.github.com"));
}

static void test_url_is_allowed_other_host(void ** state) {
    assert_false(wm_url_is_allowed("https://evil.tld/audit-log", "api.github.com"));
}

static void test_url_is_allowed_host_as_suffix(void ** state) {
    assert_false(wm_url_is_allowed("https://api.github.com.evil.tld/audit-log", "api.github.com"));
}

static void test_url_is_allowed_host_as_prefix(void ** state) {
    assert_false(wm_url_is_allowed("https://api.github.co/audit-log", "api.github.com"));
}

static void test_url_is_allowed_host_in_userinfo(void ** state) {
    assert_false(wm_url_is_allowed("https://api.github.com@evil.tld/audit-log", "api.github.com"));
}

static void test_url_is_allowed_host_in_query(void ** state) {
    assert_false(wm_url_is_allowed("https://evil.tld/?next=https://api.github.com/", "api.github.com"));
}

static void test_url_is_allowed_no_host_accepts_any_https(void ** state) {
    assert_true(wm_url_is_allowed("https://manage.office.com/api/v1.0/content", NULL));
    assert_true(wm_url_is_allowed("https://any.host.tld/content", NULL));
}

static void test_url_is_allowed_no_host_rejects_non_https(void ** state) {
    assert_false(wm_url_is_allowed("http://any.host.tld/content", NULL));
    assert_false(wm_url_is_allowed("file:///etc/passwd", NULL));
}

static void test_url_is_allowed_matching_host_with_port(void ** state) {
    assert_true(wm_url_is_allowed("https://api.github.com:8443/audit-log", "api.github.com"));
}

static void test_url_is_allowed_empty_port(void ** state) {
    assert_false(wm_url_is_allowed("https://api.github.com:/audit-log", "api.github.com"));
}

static void test_url_is_allowed_port_then_userinfo(void ** state) {
    assert_false(wm_url_is_allowed("https://api.github.com:1234@evil.tld/", "api.github.com"));
}

static void test_url_is_allowed_matching_host_with_query(void ** state) {
    assert_true(wm_url_is_allowed("https://api.github.com?after=x", "api.github.com"));
}

static void test_url_is_allowed_matching_host_with_fragment(void ** state) {
    assert_true(wm_url_is_allowed("https://api.github.com#fragment", "api.github.com"));
}

static void test_url_is_allowed_case_insensitive(void ** state) {
    assert_true(wm_url_is_allowed("HTTPS://API.GITHUB.COM/audit-log", "api.github.com"));
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_find_module_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_find_module_not_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_args, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_module, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_no_queries, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_module_query_echo, setup_modules, teardown_modules),
        cmocka_unit_test(test_url_is_allowed_null_url),
        cmocka_unit_test(test_url_is_allowed_matching_host),
        cmocka_unit_test(test_url_is_allowed_matching_host_no_path),
        cmocka_unit_test(test_url_is_allowed_plain_http),
        cmocka_unit_test(test_url_is_allowed_other_scheme),
        cmocka_unit_test(test_url_is_allowed_other_host),
        cmocka_unit_test(test_url_is_allowed_host_as_suffix),
        cmocka_unit_test(test_url_is_allowed_host_as_prefix),
        cmocka_unit_test(test_url_is_allowed_host_in_userinfo),
        cmocka_unit_test(test_url_is_allowed_host_in_query),
        cmocka_unit_test(test_url_is_allowed_no_host_accepts_any_https),
        cmocka_unit_test(test_url_is_allowed_no_host_rejects_non_https),
        cmocka_unit_test(test_url_is_allowed_matching_host_with_port),
        cmocka_unit_test(test_url_is_allowed_empty_port),
        cmocka_unit_test(test_url_is_allowed_port_then_userinfo),
        cmocka_unit_test(test_url_is_allowed_matching_host_with_query),
        cmocka_unit_test(test_url_is_allowed_matching_host_with_fragment),
        cmocka_unit_test(test_url_is_allowed_case_insensitive),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
