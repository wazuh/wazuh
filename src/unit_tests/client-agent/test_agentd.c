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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/url_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "agentd.h"

#ifdef TEST_AGENT

/* agentd.c calls w_https_client_start()/w_https_client_stop(), which would drag
 * https_client_bridge.o (and its hc_* module references) into this test binary.
 * test_agentd does not exercise the client, so stub the two entry points. */
void __wrap_w_https_client_start(void) {}
void __wrap_w_https_client_stop(void) {}

static int setup_group(void **state) {
    curl_response *response;
    os_calloc(1, sizeof(curl_response), response);
    os_strdup("123abc456def", response->body);
    *state = response;

    return 0;
}

static int teardown_group(void **state) {
    curl_response *response = *state;

    if (response) {
        os_free(response->body);
        os_free(response);
    }

    return 0;
}

static int setup_config(void **state) {
    anti_tampering *atc;
    os_calloc(1, sizeof(anti_tampering), atc);
    atc->package_uninstallation = false;
    *state = atc;

    return 0;
}

static int teardown_config(void **state) {
    anti_tampering *atc = *state;

    os_free(atc);

    return 0;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------
// check_uninstall_permission

static void test_check_uninstall_permission_granted(void **state) {
    const char *token = "abcdefghijk";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, response);

    expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_GRANTED);

    expect_value(__wrap_wurl_free_response, response, response);

    bool ret = check_uninstall_permission(token, host, ssl_verify);
    assert_false(ret);
}

static void test_check_uninstall_permission_denied(void **state) {
    const char *token = "abcdefghijk";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 403;

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, response);

    expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_DENIED);

    expect_value(__wrap_wurl_free_response, response, response);

    bool ret = check_uninstall_permission(token, host, ssl_verify);
    assert_true(ret);
}

static void test_check_uninstall_permission_wrong_status(void **state) {
    const char *token = "abcdefghijk";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 0;

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, response);

    char error_log[128];
    sprintf(error_log, AG_API_ERROR_CODE, response->status_code);
    expect_string(__wrap__merror, formatted_msg, error_log);

    expect_value(__wrap_wurl_free_response, response, response);

    bool ret = check_uninstall_permission(token, host, ssl_verify);
    assert_true(ret);
}

static void test_check_uninstall_permission_no_response(void **state) {
    const char *token = "abcdefghijk";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, NULL);

    expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);

    bool ret = check_uninstall_permission(token, host, ssl_verify);
    assert_true(ret);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------
// authenticate_and_get_token

static void test_authenticate_and_get_token_successful(void **state) {
    const char *userpass = "user:pass";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_wrap_wurl_http_request(WURL_POST_METHOD, headers, "https://localhost:55000/security/user/authenticate?raw=true", NULL, OS_SIZE_8192, 30, userpass, ssl_verify, response);

    expect_value(__wrap_wurl_free_response, response, response);

    char *token = authenticate_and_get_token(userpass, host, ssl_verify);
    int wrong_token = strcmp(token, "123abc456def");
    os_free(token);

    if (wrong_token) {
        fail();
    }
}

static void test_authenticate_and_get_token_error_status(void **state) {
    const char *userpass = "user:pass";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 400;

    expect_wrap_wurl_http_request(WURL_POST_METHOD, headers, "https://localhost:55000/security/user/authenticate?raw=true", NULL, OS_SIZE_8192, 30, userpass, ssl_verify, response);

    char error_log[128];
    sprintf(error_log, AG_API_ERROR_CODE, response->status_code);
    expect_string(__wrap__merror, formatted_msg, error_log);

    expect_value(__wrap_wurl_free_response, response, response);

    char *token = authenticate_and_get_token(userpass, host, ssl_verify);
    assert_null(token);
}

static void test_authenticate_and_get_token_no_response(void **state) {
    const char *userpass = "user:pass";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { NULL };

    expect_wrap_wurl_http_request(WURL_POST_METHOD, headers, "https://localhost:55000/security/user/authenticate?raw=true", NULL, OS_SIZE_8192, 30, userpass, ssl_verify, NULL);

    expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);

    char *token = authenticate_and_get_token(userpass, host, ssl_verify);
    assert_null(token);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------
// package_uninstall_validation

static void test_package_uninstall_validation_token_success(void **state) {
    const char *uninstall_auth_token = "abcdefghijk";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, response);

        expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_GRANTED);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    bool ret = package_uninstall_validation(uninstall_auth_token, NULL, host, ssl_verify);
    assert_false(ret);
}

static void test_package_uninstall_validation_token_denied(void **state) {
    const char *uninstall_auth_token = "abcdefghijk";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 403;

    expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, response);

        expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_DENIED);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    bool ret = package_uninstall_validation(uninstall_auth_token, NULL, host, ssl_verify);
    assert_true(ret);
}

static void test_package_uninstall_validation_login_success(void **state) {
    const char *uninstall_auth_login = "user:pass";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer 123abc456def", NULL };
    char* empty_headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // authenticate_and_get_token
    {
        expect_wrap_wurl_http_request(WURL_POST_METHOD, empty_headers, "https://localhost:55000/security/user/authenticate?raw=true", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, response);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, uninstall_auth_login, ssl_verify, response);

        expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_GRANTED);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    bool ret = package_uninstall_validation(NULL, uninstall_auth_login, host, ssl_verify);
    assert_false(ret);
}

static void test_package_uninstall_validation_login_denied(void **state) {
    const char *uninstall_auth_login = "user:pass";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer 123abc456def", NULL };
    char* empty_headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // authenticate_and_get_token
    {
        expect_wrap_wurl_http_request(WURL_POST_METHOD, empty_headers, "https://localhost:55000/security/user/authenticate?raw=true", NULL, OS_SIZE_8192, 30, NULL, ssl_verify, response);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/agents/uninstall", NULL, OS_SIZE_8192, 30, uninstall_auth_login, ssl_verify, NULL);

        expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);
    }

    bool ret = package_uninstall_validation(NULL, uninstall_auth_login, host, ssl_verify);
    assert_true(ret);
}

static void test_package_uninstall_validation_login_no_token(void **state) {
    const char *uninstall_auth_login = "user:pass";
    const char *host = "localhost:55000";
    bool ssl_verify = 1;
    char* headers[] = { "Authorization: Bearer 123abc456def", NULL };
    char* empty_headers[] = { NULL };

    expect_string(__wrap__mdebug1, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // authenticate_and_get_token
    {
        expect_wrap_wurl_http_request(WURL_POST_METHOD, empty_headers, "https://localhost:55000/security/user/authenticate?raw=true", NULL, OS_SIZE_8192, 30, uninstall_auth_login, ssl_verify, NULL);

        expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);
    }

    char error_log[128];
    sprintf(error_log, AG_TOKEN_FAIL, uninstall_auth_login);
    expect_string(__wrap__merror, formatted_msg, error_log);

    bool ret = package_uninstall_validation(NULL, uninstall_auth_login, host, ssl_verify);
    assert_true(ret);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------
// config Read_AntiTampering

void test_read_configuration_yes(void** state) {
    char *test_path = "test_anti_tampering.conf";
    anti_tampering *atc = *state;

    assert_int_equal(ReadConfig(ATAMPERING, test_path, atc, NULL), 0);
    assert_true(atc->package_uninstallation);
}

void test_read_configuration_no(void** state) {
    char *test_path = "test_anti_tampering_no.conf";
    anti_tampering *atc = *state;

    assert_int_equal(ReadConfig(ATAMPERING, test_path, atc, NULL), 0);
    assert_false(atc->package_uninstallation);
}

void test_read_configuration_invalid(void** state) {
    char *test_path = "test_anti_tampering_invalid.conf";
    anti_tampering *atc = *state;

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'package_uninstallation'.");
    expect_string(__wrap__merror, formatted_msg, "(1202): Configuration error at 'test_anti_tampering_invalid.conf'.");

    assert_int_equal(ReadConfig(ATAMPERING, test_path, atc, NULL), -1);
    assert_false(atc->package_uninstallation);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------
// ClientConf: <config_report> default posture

static int setup_client_conf(void** state)
{
    (void)state;
    os_calloc(1, sizeof(agent), agt);
    os_calloc(1, sizeof(anti_tampering), atc);

    return 0;
}

static int teardown_client_conf(void** state)
{
    (void)state;
    Free_Agent(agt);

    /* ClientConf() always allocates an enrollment context, but Free_Agent() does
     * not own it (a running agent keeps it for the process lifetime) -- so the
     * test has to tear it down itself instead of leaking it under LeakSanitizer. */
    if (agt->enrollment_cfg)
    {
        w_enrollment_target_destroy(agt->enrollment_cfg->target_cfg);
        w_enrollment_cert_destroy(agt->enrollment_cfg->cert_cfg);
        w_enrollment_destroy(agt->enrollment_cfg);
    }

    os_free(agt);
    os_free(atc);

    return 0;
}

static void expect_valid_server_ip(void)
{
    expect_string(__wrap_OS_IsValidIP, ip_address, "10.0.0.1");
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
}

/* <config_report> absent -> ClientConf() must leave it enabled, with the
 * effective intervals (not zero) visible directly on agt: the manager still
 * needs the periodic /config snapshot from a config nobody touched, and
 * anything reading agt directly (e.g. the /config JSON dump) should see the
 * real cadence instead of the transport module's zero-means-unset sentinel. */
static void test_config_report_enabled_when_absent(void** state)
{
    (void)state;
    expect_valid_server_ip();
    will_return(__wrap_getDefine_Int, 1); // <agent><recv_timeout>
    will_return(__wrap_getDefine_Int, 0); // <agent><remote_conf>

    assert_int_equal(ClientConf("test_config_report_default.conf"), 1);
    assert_int_equal(agt->config_report.enabled, 1);
    assert_int_equal(agt->config_report.interval, 3600);
    assert_int_equal(agt->stats_report.interval, 60);
}

/* An explicit <enabled>no</enabled> must still be able to turn it off. */
static void test_config_report_explicit_no_is_respected(void** state)
{
    (void)state;
    expect_valid_server_ip();
    will_return(__wrap_getDefine_Int, 1); // <agent><recv_timeout>
    will_return(__wrap_getDefine_Int, 0); // <agent><remote_conf>

    assert_int_equal(ClientConf("test_config_report_disabled.conf"), 1);
    assert_int_equal(agt->config_report.enabled, 0);
    assert_int_equal(agt->config_report.interval, 3600); // Default untouched: no <interval> tag in this fixture.
}

/* An explicit <interval> must still override the default ClientConf() seeds. */
static void test_config_report_custom_interval_is_respected(void** state)
{
    (void)state;
    expect_valid_server_ip();
    will_return(__wrap_getDefine_Int, 1); // <agent><recv_timeout>
    will_return(__wrap_getDefine_Int, 0); // <agent><remote_conf>

    assert_int_equal(ClientConf("test_config_report_custom_interval.conf"), 1);
    assert_int_equal(agt->config_report.enabled, 1);     // No <enabled> tag: stays on the default.
    assert_int_equal(agt->config_report.interval, 1800); // 30m, overriding the 3600s default.
}

#endif // TEST_AGENT

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_AGENT
        // check_uninstall_permission
        cmocka_unit_test_setup_teardown(test_check_uninstall_permission_granted, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_check_uninstall_permission_denied, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_check_uninstall_permission_wrong_status, setup_group, teardown_group),
        cmocka_unit_test(test_check_uninstall_permission_no_response),

        // authenticate_and_get_token
        cmocka_unit_test_setup_teardown(test_authenticate_and_get_token_successful, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_authenticate_and_get_token_error_status, setup_group, teardown_group),
        cmocka_unit_test(test_authenticate_and_get_token_no_response),

        // package_uninstall_validation
        cmocka_unit_test_setup_teardown(test_package_uninstall_validation_token_success, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_package_uninstall_validation_token_denied, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_package_uninstall_validation_login_success, setup_group, teardown_group),
        cmocka_unit_test_setup_teardown(test_package_uninstall_validation_login_denied, setup_group, teardown_group),
        cmocka_unit_test(test_package_uninstall_validation_login_no_token),

        // config
        cmocka_unit_test_setup_teardown(test_read_configuration_yes, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_read_configuration_no, setup_config, teardown_config),
        cmocka_unit_test_setup_teardown(test_read_configuration_invalid, setup_config, teardown_config),

        // ClientConf: <config_report> default posture
        cmocka_unit_test_setup_teardown(
            test_config_report_enabled_when_absent, setup_client_conf, teardown_client_conf),
        cmocka_unit_test_setup_teardown(
            test_config_report_explicit_no_is_respected, setup_client_conf, teardown_client_conf),
        cmocka_unit_test_setup_teardown(
            test_config_report_custom_interval_is_respected, setup_client_conf, teardown_client_conf),

#endif // TEST_AGENT
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
