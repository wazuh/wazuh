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
#include <stdio.h>
#include <stdlib.h>
#include "../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

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
// Test wurl_http_request
void test_wurl_http_request_url_null(void **state)
{
    curl_response *response = NULL;
    char **headers = NULL;
    char *url = NULL;
    size_t max_size = 1;

    expect_string(__wrap__mdebug1, formatted_msg, "url not defined");

    response = wurl_http_request(NULL, headers, url, NULL, max_size, 0);
    assert_null(response);
}

void test_wurl_http_request_init_failure(void **state)
{
    curl_response *response = NULL;
    CURL* curl = NULL;
    char **headers = NULL;
    char *url = "http://test.com";
    size_t max_size = 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl initialization failure");

    response = wurl_http_request(NULL, headers, url, NULL, max_size, 0);
    assert_null(response);
}

void test_wurl_http_request_headers_list_null(void **state)
{
    curl_response *response = NULL;
    CURL *curl = (CURL *) 1;
    char **headers = NULL;
    char *url = "https://test.com";
    size_t max_size = 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_FileSize("/etc/ssl/certs/ca-certificates.crt", 1);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CAINFO);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl append header failure");

    response = wurl_http_request(NULL, headers, url, NULL, max_size, 0);
    assert_null(response);
}

void test_wurl_http_request_headers_tmp_null(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist*) 1;
    CURL *curl = (CURL *) 1;
    char *pheaders = "headers";
    char *url = "http://test.com";
    size_t max_size = 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

        expect_string(wrap_curl_slist_append, data, "headers");
        expect_value(wrap_curl_slist_append, list, headers);
        will_return(wrap_curl_slist_append, NULL);

        expect_value(wrap_curl_slist_free_all, list, headers);
        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_FileSize("/etc/ssl/certs/ca-certificates.crt", 1);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

        expect_string(__wrap_curl_slist_append, data, "headers");
        expect_value(__wrap_curl_slist_append, list, headers);
        will_return(__wrap_curl_slist_append, NULL);

        expect_value(__wrap_curl_slist_free_all, list, headers);
        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl append custom header failure");

    response = wurl_http_request(NULL, &pheaders, url, NULL, max_size, 0);

    assert_null(response);
}

void test_wurl_http_request_curl_easy_perform_fail_with_headers(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist*) 1;
    CURL *curl = (CURL *) 1;
    char *url = "http://test.com";
    size_t max_size = 1;

    char auth_header[OS_SIZE_8192];
    snprintf(auth_header, OS_SIZE_8192 -1, "Content-Type: application/x-www-form-urlencoded");
    char **pheaders = NULL;
    os_calloc(2, sizeof(char*), pheaders);
    pheaders[0] = auth_header;
    pheaders[1] = NULL;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

        expect_string(wrap_curl_slist_append, data, "Content-Type: application/x-www-form-urlencoded");
        expect_value(wrap_curl_slist_append, list, headers);
        will_return(wrap_curl_slist_append, headers);

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

        expect_FileSize("/etc/ssl/certs/ca-certificates.crt", 1);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

        expect_string(__wrap_curl_slist_append, data, "Content-Type: application/x-www-form-urlencoded");
        expect_value(__wrap_curl_slist_append, list, headers);
        will_return(__wrap_curl_slist_append, headers);

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

    response = wurl_http_request(NULL, pheaders, url, NULL, max_size, 0);
    os_free(pheaders);
    assert_null(response);
}

void test_wurl_http_request_curl_easy_perform_fail_with_payload(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist*) 1;
    CURL *curl = (CURL *) 1;
    char *pheaders = NULL;
    char *url = "http://test.com";
    const char *payload = "payload test";
    size_t max_size = 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

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

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_perform, curl, curl);
        will_return(wrap_curl_easy_perform, (CURLcode) 9);

        expect_value(wrap_curl_slist_free_all, list, headers);
        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_FileSize("/etc/ssl/certs/ca-certificates.crt", 1);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

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

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_perform, curl, curl);
        will_return(__wrap_curl_easy_perform, (CURLcode) 9);

        expect_value(__wrap_curl_slist_free_all, list, headers);
        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl_easy_perform() failed: Access denied to remote resource");

    response = wurl_http_request(NULL, &pheaders, url, payload, max_size, 0);
    assert_null(response);
}

void test_wurl_http_request_curl_easy_perform_fail_timeout(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist*) 1;
    CURL *curl = (CURL *) 1;
    char *pheaders = NULL;
    char *url = "http://test.com";
    const char *payload = "payload test";
    size_t max_size = 1;
    long timeout = 1L;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

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

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_TIMEOUT);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_value(wrap_curl_easy_perform, curl, curl);
        will_return(wrap_curl_easy_perform, (CURLcode) 28);

        expect_value(wrap_curl_slist_free_all, list, headers);
        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_FileSize("/etc/ssl/certs/ca-certificates.crt", 1);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

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

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_TIMEOUT);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_value(__wrap_curl_easy_perform, curl, curl);
        will_return(__wrap_curl_easy_perform, (CURLcode) 28);

        expect_value(__wrap_curl_slist_free_all, list, headers);
        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "curl_easy_perform() failed: Timeout was reached");

    response = wurl_http_request(NULL, &pheaders, url, payload, max_size, 1);
    assert_null(response);
}

void test_wurl_http_request_curl_easy_setopt_fail(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist*) 1;
    CURL *curl = (CURL *) 1;
    char *pheaders = NULL;
    char *url = "http://test.com";
    const char *payload = "payload test";
    size_t max_size = 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

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

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, (CURLcode) 49);

        expect_value(wrap_curl_slist_free_all, list, headers);
        expect_value(wrap_curl_easy_cleanup, curl, curl);
    #else
        will_return(__wrap_curl_easy_init, curl);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_FileSize("/etc/ssl/certs/ca-certificates.crt", 1);

        expect_string(__wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

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

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, (CURLcode) 49);

        expect_value(__wrap_curl_slist_free_all, list, headers);
        expect_value(__wrap_curl_easy_cleanup, curl, curl);
    #endif

    expect_string(__wrap__mdebug1, formatted_msg, "Parameter setup error at CURL");

    response = wurl_http_request(NULL, &pheaders, url, payload, max_size, 0);
    assert_null(response);
}

void test_wurl_http_request_success(void **state)
{
    curl_response *response = NULL;
    struct curl_slist* headers = (struct curl_slist*) 1;
    CURL *curl = (CURL *) 1;
    char *pheaders = NULL;
    char *url = "http://test.com";
    const char *payload = "payload test";
    size_t max_size = 1;

    #ifdef TEST_WINAGENT
        will_return(wrap_curl_easy_init, curl);

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(wrap_curl_easy_setopt, curl, curl);
        will_return(wrap_curl_easy_setopt, CURLE_OK);

        expect_string(wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(wrap_curl_slist_append, list, NULL);
        will_return(wrap_curl_slist_append, headers);

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

        expect_value(wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
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

        expect_FileSize("/etc/ssl/certs/ca-certificates.crt", 1);

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_CUSTOMREQUEST);
        expect_value(__wrap_curl_easy_setopt, curl, curl);
        will_return(__wrap_curl_easy_setopt, CURLE_OK);

        expect_string(__wrap_curl_slist_append, data, "User-Agent: curl/7.58.0");
        expect_value(__wrap_curl_slist_append, list, NULL);
        will_return(__wrap_curl_slist_append, headers);

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

        expect_value(__wrap_curl_easy_setopt, option, CURLOPT_POSTFIELDS);
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

    response = wurl_http_request(NULL, &pheaders, url, payload, max_size, 0);
    assert_non_null(response);
    os_free(response->header);
    os_free(response->body);
    os_free(response);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests wurl_http_request
        cmocka_unit_test(test_wurl_http_request_url_null),
        cmocka_unit_test(test_wurl_http_request_init_failure),
        cmocka_unit_test(test_wurl_http_request_headers_list_null),
        cmocka_unit_test(test_wurl_http_request_headers_tmp_null),
        cmocka_unit_test(test_wurl_http_request_curl_easy_perform_fail_with_headers),
        cmocka_unit_test(test_wurl_http_request_curl_easy_perform_fail_with_payload),
        cmocka_unit_test(test_wurl_http_request_curl_easy_perform_fail_timeout),
        cmocka_unit_test(test_wurl_http_request_curl_easy_setopt_fail),
        cmocka_unit_test(test_wurl_http_request_success),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
