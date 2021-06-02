/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include "headers/shared.h"
#include "../wrappers/common.h"

curl_response* wurl_http_get_with_header(const char *header, const char* url);

/* setup/teardown */
static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* tests */

// Test wurl_http_get_with_header
void test_wurl_http_get_with_header_init_failure(void **state)
{
    curl_response *response = NULL;
    CURL* curl = NULL;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl initialization failure");

    response = wurl_http_get_with_header(NULL, NULL);
    assert_null(response);
}

void test_wurl_http_get_with_header_header_null(void **state)
{
    curl_response *response = NULL;
    CURL *curl = (CURL *) 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);
        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);
        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl header NULL");

    response = wurl_http_get_with_header(NULL, NULL);
    assert_null(response);
}

void test_wurl_http_get_with_header_no_https_add_header_error(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = NULL;
    CURL *curl = (CURL *) 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl append header failure");

    response = wurl_http_get_with_header("headers", "http://test.com");
    assert_null(response);
}

void test_wurl_http_get_with_header_no_https_add_headertmp_error(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist *) 1;
    struct curl_slist* headers_tmp = NULL;
    CURL *curl = (CURL *) 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

        expect_string(wrap_curl_slist_append, string, "headers");
        expect_value(wrap_curl_slist_append, list, headers);
        will_return(wrap_curl_slist_append, headers_tmp);

        expect_value(wrap_curl_easy_cleanup, curl, curl);

        expect_value(wrap_curl_slist_free_all, list, headers);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

        expect_string(__wrap_curl_slist_append, string, "headers");
        expect_value(__wrap_curl_slist_append, list, headers);
        will_return(__wrap_curl_slist_append, headers_tmp);

        expect_value(__wrap_curl_easy_cleanup, curl, curl);

        expect_value(__wrap_curl_slist_free_all, list, headers);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl append header failure");

    response = wurl_http_get_with_header("headers", "http://test.com");
    assert_null(response);
}

void test_wurl_http_get_with_header_perform_fail(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist *) 1;
    struct curl_slist* headers_tmp = (struct curl_slist *) 1;
    CURL *curl = (CURL *) 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

        expect_string(wrap_curl_slist_append, string, "headers");
        expect_value(wrap_curl_slist_append, list, headers);
        will_return(wrap_curl_slist_append, headers_tmp);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_WRITEFUNCTION);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_WRITEDATA);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_HTTPHEADER);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_HEADERFUNCTION);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_HEADERDATA);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_URL);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_perform, curl, curl);
        will_return(wrap_curl_easy_perform, (CURLcode) 9);

        expect_value(wrap_curl_slist_free_all, list, headers);

        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

        expect_string(__wrap_curl_slist_append, string, "headers");
        expect_value(__wrap_curl_slist_append, list, headers);
        will_return(__wrap_curl_slist_append, headers_tmp);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_WRITEFUNCTION);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_WRITEDATA);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_HTTPHEADER);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_HEADERFUNCTION);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_HEADERDATA);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_URL);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_perform, curl, curl);
        will_return(__wrap_curl_easy_perform, (CURLcode) 9);

        expect_value(__wrap_curl_slist_free_all, list, headers);

        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl_easy_perform() failed: Access denied to remote resource");

    response = wurl_http_get_with_header("headers", "http://test.com");
    assert_null(response);
}

void test_wurl_http_get_with_header_success(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist *) 1;
    struct curl_slist* headers_tmp = (struct curl_slist *) 1;
    CURL *curl = (CURL *) 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

        expect_string(wrap_curl_slist_append, string, "headers");
        expect_value(wrap_curl_slist_append, list, headers);
        will_return(wrap_curl_slist_append, headers_tmp);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_WRITEFUNCTION);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_WRITEDATA);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_HTTPHEADER);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_HEADERFUNCTION);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_HEADERDATA);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_URL);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_perform, curl, curl);
        will_return(wrap_curl_easy_perform, CURLE_OK);

        expect_value(wrap_curl_easy_getinfo, curl, curl);
        expect_value(wrap_curl_easy_getinfo, option, CURLINFO_RESPONSE_CODE);
        will_return(wrap_curl_easy_getinfo, CURLE_OK);

        expect_value(wrap_curl_slist_free_all, list, headers);
        expect_value(wrap_curl_easy_cleanup, curl, curl);

    #else

        will_return(__wrap_curl_easy_init, curl);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CAINFO);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, string, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

        expect_string(__wrap_curl_slist_append, string, "headers");
        expect_value(__wrap_curl_slist_append, list, headers);
        will_return(__wrap_curl_slist_append, headers_tmp);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_WRITEFUNCTION);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_WRITEDATA);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_HTTPHEADER);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_HEADERFUNCTION);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_HEADERDATA);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_URL);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_perform, curl, curl);
        will_return(__wrap_curl_easy_perform, CURLE_OK);

        expect_value(__wrap_curl_easy_getinfo, curl, curl);
        expect_value(__wrap_curl_easy_getinfo, option, CURLINFO_RESPONSE_CODE);
        will_return(__wrap_curl_easy_getinfo, CURLE_OK);

        expect_value(__wrap_curl_slist_free_all, list, headers);
        expect_value(__wrap_curl_easy_cleanup, curl, curl);

    #endif

    response = wurl_http_get_with_header("headers", "https://test.com");
    assert_non_null(response);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests wurl_http_get_with_header
        cmocka_unit_test(test_wurl_http_get_with_header_init_failure),
        cmocka_unit_test(test_wurl_http_get_with_header_header_null),
        cmocka_unit_test(test_wurl_http_get_with_header_no_https_add_header_error),
        cmocka_unit_test(test_wurl_http_get_with_header_no_https_add_headertmp_error),
        cmocka_unit_test(test_wurl_http_get_with_header_perform_fail),
        cmocka_unit_test(test_wurl_http_get_with_header_success),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}