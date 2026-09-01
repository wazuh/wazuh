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
#include "agentd.h"
#include <string.h>
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/common.h"
#include "../../data_provider/include/sysInfo.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "startup_gate_op.h"
#include "os_win.h"
#include "../wrappers/windows/handleapi_wrappers.h"

#ifdef TEST_WINAGENT

#define TIME_INCREMENT ((time_t)(60))

extern sysinfo_networks_func sysinfo_network_ptr;
extern sysinfo_free_result_func sysinfo_free_result_ptr;

static agent global_config = { .main_ip_update_interval = (int)TIME_INCREMENT };
static int test_case_selector = 0;
static int error_code_sysinfo_network = 0;

/* Every frame goes to the HTTPS module: the legacy egress is gone (#38030). */
int __wrap_w_https_client_submit_event(const char *frame, size_t length) {
    check_expected(frame);
    check_expected(length);
    return mock();
}

int mock_sysinfo_networks_func(cJSON **object) {

    static const char *ip_update_success =
    "{ \"iface\": [ { \"gateway\":\"mock_gateway\", \"IPv4\": [ { \"address\":\"111.222.333.444\" } ] } ] }";
    static const char *ipv6_gw_ipv4_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"fe80::\", \"IPv4\": [ { \"address\":\"111.222.333.444\" } ] } ] }";
    static const char *ipv6_gw_ipv6_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"fe80::\", \"IPv6\": [ { \"address\":\"fe80::a00:27ff:fee0:d046\" } ] } ] }";
    static const char *ipv4_gw_ipv4_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"192.168.1.1\", \"IPv4\": [ { \"address\":\"111.222.333.444\" } ] } ] }";
    static const char *ipv4_gw_ipv6_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"192.168.1.1\", \"IPv6\": [ { \"address\":\"fe80::a00:27ff:fee0:d046\" } ] } ] }";
    static const char *iface_bad_name = "{\"iface_fail\":[]}";
    static const char *iface_no_elements = "{\"iface\":[]";
    static const char *gateway_unknown = "{ \"iface\": [ { \"gateway\":\"unknown\" } ] }";
    const char *json_string = NULL;

    switch (test_case_selector) {
    case 1:
        json_string = ip_update_success;
        break;
    case 2:
        json_string = iface_bad_name;
        break;
    case 3:
        json_string = iface_no_elements;
        break;
    case 4:
        json_string = gateway_unknown;
        break;
    case 5:
        json_string = ipv6_gw_ipv4_addr_update_success;
        break;
    case 6:
        json_string = ipv6_gw_ipv6_addr_update_success;
        break;
    case 7:
        json_string = ipv4_gw_ipv4_addr_update_success;
        break;
    case  8:
        json_string = ipv4_gw_ipv6_addr_update_success;
        break;
    }

    *object = cJSON_Parse(json_string);

    return error_code_sysinfo_network;
}

void mock_sysinfo_free_result_func(cJSON **object) {
    cJSON_free(*object);
    return;
}

/* Defined in win_utils.c; in the real agent it's called from
 * OssecServiceStart() before the SCM can invoke stop_wmodules(). The tests
 * below call stop_wmodules()/wm_start_modules_unless_shutting_down()
 * directly, so wm_lifecycle_lock must be initialized here first -- entering
 * an uninitialized CRITICAL_SECTION is undefined behavior (issue 38428). */
extern void wm_lifecycle_lock_init(void);

static int setup_group(void **state) {
    agt = &global_config;
    time_mock_value = 0;
    sysinfo_network_ptr = mock_sysinfo_networks_func;
    sysinfo_free_result_ptr = mock_sysinfo_free_result_func;
    wm_lifecycle_lock_init();

    return 0;
}

static void test_get_agent_ip_legacy_win32_update_ip_success(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "111.222.333.444" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 1;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv6_success(void ** state) {

    const char * address = {"FE80:0000:0000:0000:0A00:27FF:FEE0:D046"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 6;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv4_success(void ** state) {

    const char * address = {"111.222.333.444"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 5;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv4_success(void ** state) {

    const char * address = {"111.222.333.444"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 7;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv6_success(void ** state) {

    const char * address = {"FE80:0000:0000:0000:0A00:27FF:FEE0:D046"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 8;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_sysinfo_error(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 2;
    test_case_selector = 1;
    expect_string(__wrap__merror, formatted_msg, "Unable to get system network information. Error code: 2.");
    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_iface_bad_name(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 2;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_iface_no_elements(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 3;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_gateway_unknown(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 4;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_no_update(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_SendMSGAction_mutex_abandoned(void **state) {

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_ABANDONED);

    expect_string(__wrap__merror, formatted_msg, "Error waiting mutex (abandoned).");

    int ret = SendMSG(0, "message", "locmsg", LOCALFILE_MQ);

    assert_int_equal(ret, -1);
}

static void test_SendMSGAction_mutex_error(void **state) {

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, -8);

    expect_string(__wrap__merror, formatted_msg, "Error waiting mutex.");

    int ret = SendMSG(0, "message", "locmsg", LOCALFILE_MQ);

    assert_int_equal(ret, -1);
}

static void test_SendMSGAction_non_escape(void **state) {


    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap_w_https_client_submit_event, frame, "1:locmsg:message");
    expect_value(__wrap_w_https_client_submit_event, length, strlen("1:locmsg:message"));
    will_return(__wrap_w_https_client_submit_event, 0);

    expect_any_always(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendMSG(0, "message", "locmsg", LOCALFILE_MQ);

    assert_int_equal(ret, 0);
}

static void test_SendMSGAction_escape(void **state) {


    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap_w_https_client_submit_event, frame, "1:loc||msg|:test:message");
    expect_value(__wrap_w_https_client_submit_event, length, strlen("1:loc||msg|:test:message"));
    will_return(__wrap_w_https_client_submit_event, 0);

    expect_any_always(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 0);
    expect_string(__wrap__merror, formatted_msg, "Error releasing mutex.");

    int ret = SendMSG(0, "message", "loc|msg:test", LOCALFILE_MQ);

    assert_int_equal(ret, 0);
}

static void test_SendMSGAction_multi_escape(void **state) {


    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap_w_https_client_submit_event, frame, "1:a||||a|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:a||||a:message");
    expect_value(__wrap_w_https_client_submit_event, length, strlen("1:a||||a|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:a||||a:message"));
    will_return(__wrap_w_https_client_submit_event, 0);

    expect_any_always(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendMSG(0, "message", "a||a::::::::::::::::a||a", LOCALFILE_MQ);

    assert_int_equal(ret, 0);
}

static void test_SendBinaryMSGAction_mutex_abandoned(void **state) {
    (void) state;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_ABANDONED);

    expect_string(__wrap__merror, formatted_msg, "Error waiting mutex (abandoned).");

    int ret = SendBinaryMSG(0, "data", 4, "locmsg", 's');
    assert_int_equal(ret, -1);
}

static void test_SendBinaryMSGAction_message_too_large(void **state) {
    (void) state;

    size_t payload_len = OS_MAXSTR;
    char payload[payload_len];
    memset(payload, 'A', payload_len);

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap__mwarn, formatted_msg, "Binary message is too large to be sent (65542 bytes required, 65536 max). Payload of 65536 bytes for module 'FIM' was dropped.");

    expect_any(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendBinaryMSG(0, payload, payload_len, "FIM", 's');
    assert_int_equal(ret, -1);
}

static void test_SendBinaryMSGAction_submits_the_binary_frame(void **state) {
    (void) state;


    const char payload[] = {'d', 'a', 't', 'a', '\0', 'm', 'o', 'r', 'e'};
    size_t payload_len = sizeof(payload);
    const char *locmsg = "FIM";
    char loc = 's';

    char expected_msg[100];
    char *p = expected_msg;
    strcpy(p, "s:FIM:");
    p += strlen("s:FIM:");
    memcpy(p, payload, payload_len);
    size_t total_len = strlen("s:FIM:") + payload_len;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    /* Binary payloads carry embedded NULs: the length must be the real one. */
    expect_memory(__wrap_w_https_client_submit_event, frame, expected_msg, total_len);
    expect_value(__wrap_w_https_client_submit_event, length, total_len);
    will_return(__wrap_w_https_client_submit_event, 0);

    expect_any(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendBinaryMSG(0, payload, payload_len, locmsg, loc);
    assert_int_equal(ret, 0);
}

/* --- issue 38428: startup vs. shutdown mutual exclusion ------------------ */

extern volatile sig_atomic_t wm_shutdown_requested;
extern wmodule *wmodules;
extern void wm_start_modules_unless_shutting_down(void);
extern void stop_wmodules(void);

startup_gate_wait_result_t __wrap_startup_gate_wait_for_ready(const char *module_name) {
    check_expected(module_name);
    return mock_type(startup_gate_wait_result_t);
}

int __wrap_wm_config(void) {
    return mock_type(int);
}

int __wrap_wm_check(void) {
    return mock_type(int);
}

static int teardown_wm_lifecycle(void **state) {
    (void)state;
    wm_shutdown_requested = 0;
    wmodules = NULL;
    return 0;
}

/* --- skthread(): must not start syscheck once a shutdown is in flight --- */

static void test_skthread_skips_start_on_shutdown_requested(void **state) {
    (void)state;
    expect_string(__wrap_startup_gate_wait_for_ready, module_name, "wazuh-syscheckd");
    will_return(__wrap_startup_gate_wait_for_ready, STARTUP_GATE_SHUTDOWN_REQUESTED);

    /* No expect_function_call(__wrap_Start_win32_Syscheck) queued: cmocka
     * fails this test if skthread() calls it anyway. */
    skthread(NULL);
}

static void test_skthread_starts_syscheck_when_gate_ready(void **state) {
    (void)state;
    expect_string(__wrap_startup_gate_wait_for_ready, module_name, "wazuh-syscheckd");
    will_return(__wrap_startup_gate_wait_for_ready, STARTUP_GATE_READY);

    expect_function_call(__wrap_Start_win32_Syscheck);
    will_return(__wrap_Start_win32_Syscheck, 0);

    skthread(NULL);
}

/* --- win_module_thread(): must not run a module's start routine once a
 * shutdown is in flight -- this is the exact mechanism behind issue 38428's
 * SCA scan_on_start being silently dropped: the thread had already been
 * spawned before the shutdown was requested, so closing the race requires
 * this check to happen here, not just at spawn time. */

static int test_routine_call_count = 0;

DWORD WINAPI test_module_routine(__attribute__((unused)) void *data) {
    test_routine_call_count++;
    return 0;
}

static int setup_module_routine_counter(void **state) {
    (void)state;
    test_routine_call_count = 0;
    return 0;
}

static void test_win_module_thread_skips_routine_on_shutdown_requested(void **state) {
    (void)state;
    win_module_start_ctx_t *ctx = NULL;
    os_calloc(1, sizeof(win_module_start_ctx_t), ctx);
    ctx->routine = test_module_routine;
    ctx->data = NULL;
    snprintf(ctx->name, sizeof(ctx->name), "wazuh-modulesd/test");

    expect_string(__wrap_startup_gate_wait_for_ready, module_name, "wazuh-modulesd/test");
    will_return(__wrap_startup_gate_wait_for_ready, STARTUP_GATE_SHUTDOWN_REQUESTED);

    win_module_thread(ctx);

    assert_int_equal(test_routine_call_count, 0);
}

static void test_win_module_thread_runs_routine_when_gate_ready(void **state) {
    (void)state;
    win_module_start_ctx_t *ctx = NULL;
    os_calloc(1, sizeof(win_module_start_ctx_t), ctx);
    ctx->routine = test_module_routine;
    ctx->data = NULL;
    snprintf(ctx->name, sizeof(ctx->name), "wazuh-modulesd/test");

    expect_string(__wrap_startup_gate_wait_for_ready, module_name, "wazuh-modulesd/test");
    will_return(__wrap_startup_gate_wait_for_ready, STARTUP_GATE_READY);

    win_module_thread(ctx);

    assert_int_equal(test_routine_call_count, 1);
}

/* --- wm_start_modules_unless_shutting_down(): the lock-guarded region that
 * replaces local_start()'s old unconditional wm_config()+spawn-loop. */

static void test_wm_start_modules_skips_everything_when_shutdown_already_requested(void **state) {
    (void)state;
    wm_shutdown_requested = 1;

    expect_string(__wrap__mdebug1, formatted_msg, "Shutdown already in progress; skipping wodle startup.");

    /* No will_return(__wrap_wm_config, ...) queued: cmocka fails this test
     * if wm_config() is called despite the shutdown flag already being set. */
    wm_start_modules_unless_shutting_down();

    assert_null(wmodules);
}

static void test_wm_start_modules_spawns_a_thread_per_module_when_not_shutting_down(void **state) {
    (void)state;
    wm_context ctx = {
        .name = "test-module",
        .start = test_module_routine,
    };
    wmodule mod = { .context = &ctx, .data = NULL, .next = NULL };
    wmodules = &mod;

    will_return(__wrap_wm_config, 0);
    will_return(__wrap_wm_check, 0);
    will_return(wrap_CreateThread, (HANDLE)0x1234);

    wm_start_modules_unless_shutting_down();

    assert_ptr_equal(mod.win_thread, (HANDLE)0x1234);
}

/* --- stop_wmodules(): sets the shutdown flag and joins every spawned module,
 * even when it never got a real thread (mid-startup race, issue 38428 §2). */

static void test_stop_wmodules_sets_shutdown_flag_and_skips_join_without_a_thread(void **state) {
    (void)state;
    wm_context ctx = { .name = "test-module" };
    wmodule mod = { .context = &ctx, .data = NULL, .win_thread = NULL, .next = NULL };
    wmodules = &mod;
    wm_shutdown_requested = 0;

    stop_wmodules();

    assert_int_equal(wm_shutdown_requested, 1);
}

static void test_stop_wmodules_joins_a_spawned_thread(void **state) {
    (void)state;
    wm_context ctx = { .name = "test-module" };
    wmodule mod = { .context = &ctx, .data = NULL, .win_thread = (HANDLE)0x5678, .next = NULL };
    wmodules = &mod;
    wm_shutdown_requested = 0;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_CloseHandle_call((HANDLE)0x5678, 1);

    stop_wmodules();

    assert_int_equal(wm_shutdown_requested, 1);
    assert_null(mod.win_thread);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ip_success), cmocka_unit_test(test_get_agent_ip_legacy_win32_sysinfo_error),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_iface_bad_name),    cmocka_unit_test(test_get_agent_ip_legacy_win32_iface_no_elements),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_gateway_unknown),   cmocka_unit_test(test_get_agent_ip_legacy_win32_no_update),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv6_success),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv4_success),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv4_success),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv6_success),
        cmocka_unit_test(test_SendMSGAction_mutex_abandoned), cmocka_unit_test(test_SendMSGAction_mutex_error),
        cmocka_unit_test(test_SendMSGAction_non_escape), cmocka_unit_test(test_SendMSGAction_escape),
        cmocka_unit_test(test_SendMSGAction_multi_escape),
        cmocka_unit_test(test_SendBinaryMSGAction_mutex_abandoned),
        cmocka_unit_test(test_SendBinaryMSGAction_message_too_large),
        cmocka_unit_test(test_SendBinaryMSGAction_submits_the_binary_frame),
        cmocka_unit_test(test_skthread_skips_start_on_shutdown_requested),
        cmocka_unit_test(test_skthread_starts_syscheck_when_gate_ready),
        cmocka_unit_test_setup(test_win_module_thread_skips_routine_on_shutdown_requested, setup_module_routine_counter),
        cmocka_unit_test_setup(test_win_module_thread_runs_routine_when_gate_ready, setup_module_routine_counter),
        cmocka_unit_test_teardown(test_wm_start_modules_skips_everything_when_shutdown_already_requested, teardown_wm_lifecycle),
        cmocka_unit_test_teardown(test_wm_start_modules_spawns_a_thread_per_module_when_not_shutting_down, teardown_wm_lifecycle),
        cmocka_unit_test_teardown(test_stop_wmodules_sets_shutdown_flag_and_skips_join_without_a_thread, teardown_wm_lifecycle),
        cmocka_unit_test_teardown(test_stop_wmodules_joins_a_spawned_thread, teardown_wm_lifecycle),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}

#endif
