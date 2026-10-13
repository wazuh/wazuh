/*
 * Copyright (C) Wazuh Inc.
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

#include <cJSON.h>

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

static int sync_calls;

// Sync callback that records the call, to tell which module a frame was routed to.
static int sync_record(const char * args, size_t length) {
    (void)args;
    (void)length;
    sync_calls++;
    return 0;
}

static int setup_modules(void ** state) {
    static wm_context CONTEXTS[] = {
        { .name = "A", .query = echo },
        { .name = "B", .query = NULL },
        { .name = "sca", .sync = sync_fail },
        { .name = "syscollector", .sync = sync_record },
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

    wm_shutdown_requested = 0;
    sync_calls = 0;

    *state = NULL;
    return 0;
}

static int teardown_modules(void ** state) {
    free(*state);
    free(wmodules->next->next->next);
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

static void expect_fim_socket_refused(bool logged_as_error) {
    static char refused_msg[OS_SIZE_128];
    snprintf(refused_msg, sizeof(refused_msg), "WM_FIM_QUERY_JSON: Failed to connect to socket, errno=%d", ECONNREFUSED);

    expect_string(__wrap__mdebug1, formatted_msg, "WM_FIM_QUERY_JSON: Attempting to connect to socket: " SYS_LOCAL_SOCK);
    expect_string(__wrap_OS_ConnectUnixDomain, path, SYS_LOCAL_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, OS_SOCKTERR);

    if (logged_as_error) {
        expect_string(__wrap__merror, formatted_msg, refused_msg);
    } else {
        expect_string(__wrap__mdebug1, formatted_msg, refused_msg);
    }
}

// wazuh-syscheckd refusing the connection while the agent is running is a genuine fault: ERROR.
static void test_fim_query_connect_refused_while_running(void ** state) {
    (void)state;
    char * response = NULL;

    expect_fim_socket_refused(true);

    errno = ECONNREFUSED;
    size_t len = wm_fim_query_json("{\"command\":\"pause\"}", &response);

    assert_true(len > 0);
    assert_non_null(response);
    free(response);
}

// The same refusal once modulesd is shutting down is expected (syscheckd stops first): DEBUG.
static void test_fim_query_connect_refused_during_shutdown(void ** state) {
    (void)state;
    char * response = NULL;

    wm_shutdown_requested = 1;
    expect_fim_socket_refused(false);

    errno = ECONNREFUSED;
    size_t len = wm_fim_query_json("{\"command\":\"pause\"}", &response);

    assert_true(len > 0);
    assert_non_null(response);
    free(response);
}

// docs/ref/configuration/manager/README.md documents wazuh_modules.debug,
// wazuh_modules.max_eps, wazuh_modules.task_nice and wazuh_modules.kill_timeout
// as "Common Internal Options", but none of them had any test coverage. They
// are read from internal_options via getDefine_Int()/getDefine_Int_default()
// inside wm_config() (wmodules.c), which also drives module registration and
// ReadConfig() and so isn't a reasonable unit to exercise here. What can be
// tested directly and in isolation is getModulesInternalOptions() (wmodules.c),
// the pure function that reports the current value of each of those four
// globals (wm_task_nice/wm_max_eps/wm_kill_timeout/wm_debug_level, declared
// `extern` in wmodules.h) back out as cJSON under the exact same
// "wazuh_modules.*" keys documented in the manager README -- this is the
// function wmcom_dispatch()'s "getallconfig" answers with (see
// test_wmcom.c, which stubs it out via __wrap_getModulesInternalOptions
// instead of exercising the real implementation).
//
// wazuh_modules.rlimit_nofile is intentionally NOT covered here: it's read
// directly inside main() in main.c (never assigned to a module-level global,
// never surfaced through getModulesInternalOptions()), so there is no
// reasonable seam to unit test it without inventing untested infrastructure
// around main().
static void test_get_modules_internal_options_reports_all_common_options(void ** state) {
    (void) state;

    wm_task_nice = -5;
    wm_max_eps = 250;
    wm_kill_timeout = 45;
    wm_socket_timeout = 9;
    wm_debug_level = 2;

    cJSON * root = getModulesInternalOptions();
    assert_non_null(root);

    cJSON * internals = cJSON_GetObjectItem(root, "internal_options");
    assert_non_null(internals);

    cJSON * task_nice = cJSON_GetObjectItem(internals, "wazuh_modules.task_nice");
    assert_non_null(task_nice);
    assert_int_equal(task_nice->valueint, -5);

    cJSON * max_eps = cJSON_GetObjectItem(internals, "wazuh_modules.max_eps");
    assert_non_null(max_eps);
    assert_int_equal(max_eps->valueint, 250);

    cJSON * kill_timeout = cJSON_GetObjectItem(internals, "wazuh_modules.kill_timeout");
    assert_non_null(kill_timeout);
    assert_int_equal(kill_timeout->valueint, 45);

    cJSON * socket_timeout = cJSON_GetObjectItem(internals, "wazuh_modules.socket_timeout");
    assert_non_null(socket_timeout);
    assert_int_equal(socket_timeout->valueint, 9);

    cJSON * debug = cJSON_GetObjectItem(internals, "wazuh_modules.debug");
    assert_non_null(debug);
    assert_int_equal(debug->valueint, 2);

    cJSON_Delete(root);
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

// The frame header alone names the destination module: a syscollector frame whose payload
// mentions another module (here "sca", which comes first in the list) must still reach syscollector.
static void test_modules_sync_routes_by_header(void ** state) {
    (void)state;
    char input[] = "syscollector_sync {\"module\":\"sca\"}";

    int ret = modulesSync(input, sizeof(input));

    assert_int_equal(ret, 0);
    assert_int_equal(sync_calls, 1);
}

// The vulnerability detection stream of a module is routed to that same module.
static void test_modules_sync_routes_vd_header(void ** state) {
    (void)state;
    char input[] = "syscollector_vd_sync payload";

    int ret = modulesSync(input, sizeof(input));

    assert_int_equal(ret, 0);
    assert_int_equal(sync_calls, 1);
}

// A module name anywhere but at the start of the frame does not route it there.
static void test_modules_sync_ignores_name_outside_header(void ** state) {
    (void)state;
    char input[] = "other_sync syscollector_sync payload";

    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 1");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 2");
    expect_string(__wrap__mdebug1, formatted_msg, "WModules is not ready. Retry 3");
    expect_string(__wrap__merror, formatted_msg, "At modulesSync(): Unable to sync module '': (-1)");

    int ret = modulesSync(input, sizeof(input));

    assert_int_equal(ret, -1);
    assert_int_equal(sync_calls, 0);
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
        cmocka_unit_test_setup_teardown(test_modules_sync_failure_while_running, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_failure_during_shutdown, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_fim_query_connect_refused_while_running, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_fim_query_connect_refused_during_shutdown, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_routes_by_header, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_routes_vd_header, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_modules_sync_ignores_name_outside_header, setup_modules, teardown_modules),
        cmocka_unit_test(test_get_modules_internal_options_reports_all_common_options),
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
