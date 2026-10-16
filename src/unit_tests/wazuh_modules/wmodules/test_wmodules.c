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
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"

static size_t echo(void * module, char * query, char ** output) {
    (void)module;
    *output = strdup(query);
    return strlen(query);
}

static int sca_sync_calls;
static int syscollector_sync_calls;

static int sca_sync(const char * args) {
    (void)args;
    sca_sync_calls++;
    return 0;
}

static int syscollector_sync(const char * args) {
    (void)args;
    syscollector_sync_calls++;
    return 0;
}

// No module takes the frame, so modulesSync() retries before giving up.
static void expect_sync_retries_exhausted(void) {
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 1");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 2");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 3");
    expect_string(__wrap__merror, formatted_msg, "At modulesSync(): Unable to sync module '': (-1)");
}

static int setup_modules(void ** state) {
    static wm_context CONTEXTS[] = {
        { .name = "A", .query = echo },
        { .name = "B", .query = NULL },
        { .name = "sca", .sync = sca_sync },
        { .name = "syscollector", .sync = syscollector_sync },
    };

    wmodules = calloc(1, sizeof(wmodule));
    wmodules->context = &CONTEXTS[0];
    wmodules->next = calloc(1, sizeof(wmodule));
    wmodules->next->context = &CONTEXTS[1];
    wmodules->next->next = calloc(1, sizeof(wmodule));
    wmodules->next->next->context = &CONTEXTS[2];
    wmodules->next->next->tag = "sca";
    wmodules->next->next->next = calloc(1, sizeof(wmodule));
    wmodules->next->next->next->context = &CONTEXTS[3];
    wmodules->next->next->next->tag = "syscollector";

    sca_sync_calls = 0;
    syscollector_sync_calls = 0;

    *state = NULL;
    return 0;
}

static int teardown_modules(void ** state) {
    free(*state);
    free(wmodules->next->next->next);
    free(wmodules->next->next);
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

// The frame header alone names the destination module: a syscollector frame whose payload
// mentions another module (here "sca", which comes first in the list) must still reach syscollector.
static void test_modules_sync_routes_by_header(void ** state) {
    (void)state;
    char input[] = "syscollector_packages dbsync checksum_fail {\"begin\":\"sca\",\"end\":\"sca\"}";

    int ret = modulesSync(input);

    assert_int_equal(ret, 0);
    assert_int_equal(syscollector_sync_calls, 1);
    assert_int_equal(sca_sync_calls, 0);
}

// A module name anywhere but at the start of the frame does not route it there.
static void test_modules_sync_ignores_name_outside_header(void ** state) {
    (void)state;
    char input[] = "other_component dbsync syscollector_packages";

    expect_sync_retries_exhausted();

    int ret = modulesSync(input);

    assert_int_equal(ret, -1);
    assert_int_equal(syscollector_sync_calls, 0);
    assert_int_equal(sca_sync_calls, 0);
}

// A module name must be followed by the component separator: "scan_x" is not addressed to "sca".
static void test_modules_sync_requires_component_separator(void ** state) {
    (void)state;
    char input[] = "scan_packages dbsync checksum_fail {}";

    expect_sync_retries_exhausted();

    int ret = modulesSync(input);

    assert_int_equal(ret, -1);
    assert_int_equal(sca_sync_calls, 0);
}

// A frame addressed to a module but not carrying a dbsync command is accepted without syncing,
// even if "dbsync" appears in its payload.
static void test_modules_sync_requires_dbsync_token(void ** state) {
    (void)state;
    char input[] = "syscollector_packages other {\"dbsync\":1}";

    int ret = modulesSync(input);

    assert_int_equal(ret, 0);
    assert_int_equal(syscollector_sync_calls, 0);
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
        cmocka_unit_test_setup_teardown(test_modules_sync_routes_by_header, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_ignores_name_outside_header, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_requires_component_separator, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_requires_dbsync_token, setup_modules, teardown_modules),
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
