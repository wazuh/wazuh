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

#include "../client-agent/agentd.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/url_wrappers.h"

#ifdef TEST_AGENT

static int setup_group(void **state) {
    curl_response *response;
    os_calloc(1, sizeof(curl_response), response);
    os_strdup("{\"data\":{\"token\":\"123abc456def\"},\"error\":\"0\"}", response->body);
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

// ----------------------------------------------------------------------------------------------------------------------------------------------
// check_uninstall_permission

static void test_check_uninstall_permission_granted(void **state) {
    const char *token = "abcdefghijk";
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, response);

    expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_GRANTED);

    expect_value(__wrap_wurl_free_response, response, response);

    bool ret = check_uninstall_permission(token);
    assert_true(ret);
}

static void test_check_uninstall_permission_denied(void **state) {
    const char *token = "abcdefghijk";
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 403;

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, response);

    expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_DENIED);

    expect_value(__wrap_wurl_free_response, response, response);

    bool ret = check_uninstall_permission(token);
    assert_false(ret);
}

static void test_check_uninstall_permission_wrong_status(void **state) {
    const char *token = "abcdefghijk";
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 0;

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, response);

    char error_log[128];
    sprintf(error_log, AG_API_ERROR_CODE, response->status_code);
    expect_string(__wrap__merror, formatted_msg, error_log);

    expect_value(__wrap_wurl_free_response, response, response);

    bool ret = check_uninstall_permission(token);
    assert_false(ret);
}

static void test_check_uninstall_permission_no_response(void **state) {
    const char *token = "abcdefghijk";
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };

    expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, NULL);

    expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);

    bool ret = check_uninstall_permission(token);
    assert_false(ret);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------
// authenticate_and_get_token

static void test_authenticate_and_get_token_successful(void **state) {
    const char *userpass = "user:pass";
    char* headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_wrap_wurl_http_request(WURL_POST_METHOD, headers, "https://localhost:55000/security/user/authenticate?raw=true", userpass, OS_SIZE_8192, 30, response);

    expect_value(__wrap_wurl_free_response, response, response);

    char *token = authenticate_and_get_token(userpass);
    int wrong_token = strcmp(token, "123abc456def");
    os_free(token);

    if (wrong_token) {
        fail();
    }
}

static void test_authenticate_and_get_token_error_status(void **state) {
    const char *userpass = "user:pass";
    char* headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 400;

    expect_wrap_wurl_http_request(WURL_POST_METHOD, headers, "https://localhost:55000/security/user/authenticate?raw=true", userpass, OS_SIZE_8192, 30, response);

    char error_log[128];
    sprintf(error_log, AG_API_ERROR_CODE, response->status_code);
    expect_string(__wrap__merror, formatted_msg, error_log);

    expect_value(__wrap_wurl_free_response, response, response);

    char *token = authenticate_and_get_token(userpass);
    assert_null(token);
}

static void test_authenticate_and_get_token_no_response(void **state) {
    const char *userpass = "user:pass";
    char* headers[] = { NULL };

    expect_wrap_wurl_http_request(WURL_POST_METHOD, headers, "https://localhost:55000/security/user/authenticate?raw=true", userpass, OS_SIZE_8192, 30, NULL);

    expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);

    char *token = authenticate_and_get_token(userpass);
    assert_null(token);
}

// ----------------------------------------------------------------------------------------------------------------------------------------------
// package_uninstall_validation

static void test_package_uninstall_validation_token_success(void **state) {
    const char *uninstall_auth_token = "abcdefghijk";
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, response);

        expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_GRANTED);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    bool ret = package_uninstall_validation(uninstall_auth_token, NULL);
    assert_true(ret);
}

static void test_package_uninstall_validation_token_denied(void **state) {
    const char *uninstall_auth_token = "abcdefghijk";
    char* headers[] = { "Authorization: Bearer abcdefghijk", NULL };
    curl_response *response = *state;
    response->status_code = 403;

    expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, response);

        expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_DENIED);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    bool ret = package_uninstall_validation(uninstall_auth_token, NULL);
    assert_false(ret);
}

static void test_package_uninstall_validation_login_success(void **state) {
    const char *uninstall_auth_login = "user:pass";
    char* headers[] = { "Authorization: Bearer 123abc456def", NULL };
    char* empty_headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // authenticate_and_get_token
    {
        expect_wrap_wurl_http_request(WURL_POST_METHOD, empty_headers, "https://localhost:55000/security/user/authenticate?raw=true", uninstall_auth_login, OS_SIZE_8192, 30, response);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, response);

        expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_GRANTED);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    bool ret = package_uninstall_validation(NULL, uninstall_auth_login);
    assert_true(ret);
}

static void test_package_uninstall_validation_login_denied(void **state) {
    const char *uninstall_auth_login = "user:pass";
    char* headers[] = { "Authorization: Bearer 123abc456def", NULL };
    char* empty_headers[] = { NULL };
    curl_response *response = *state;
    response->status_code = 200;

    expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // authenticate_and_get_token
    {
        expect_wrap_wurl_http_request(WURL_POST_METHOD, empty_headers, "https://localhost:55000/security/user/authenticate?raw=true", uninstall_auth_login, OS_SIZE_8192, 30, response);

        expect_value(__wrap_wurl_free_response, response, response);
    }

    // check_uninstall_permission
    {
        expect_wrap_wurl_http_request(WURL_GET_METHOD, headers, "https://localhost:55000/uninstall_permission", NULL, OS_SIZE_8192, 30, NULL);

        expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);
    }

    bool ret = package_uninstall_validation(NULL, uninstall_auth_login);
    assert_false(ret);
}

static void test_package_uninstall_validation_login_no_token(void **state) {
    const char *uninstall_auth_login = "user:pass";
    char* headers[] = { "Authorization: Bearer 123abc456def", NULL };
    char* empty_headers[] = { NULL };

    expect_string(__wrap__minfo, formatted_msg, AG_UNINSTALL_VALIDATION_START);

    // authenticate_and_get_token
    {
        expect_wrap_wurl_http_request(WURL_POST_METHOD, empty_headers, "https://localhost:55000/security/user/authenticate?raw=true", uninstall_auth_login, OS_SIZE_8192, 30, NULL);

        expect_string(__wrap__merror, formatted_msg, AG_REQUEST_FAIL);
    }

    char error_log[128];
    sprintf(error_log, AG_TOKEN_FAIL, uninstall_auth_login);
    expect_string(__wrap__merror, formatted_msg, error_log);

    bool ret = package_uninstall_validation(NULL, uninstall_auth_login);
    assert_false(ret);
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

#endif // TEST_AGENT
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
