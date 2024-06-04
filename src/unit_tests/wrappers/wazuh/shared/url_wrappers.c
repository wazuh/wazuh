/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "url_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"

int __wrap_wurl_request(const char * url,
                        const char * dest,
                        const char *header,
                        const char *data,
                        const long timeout) {
    if (url) {
        check_expected(url);
    }

    if (dest) {
        check_expected(dest);
    }

    if (header) {
        check_expected(header);
    }

    if (data) {
        check_expected(data);
    }

    if (timeout) {
        check_expected(timeout);
    }

    return mock();
}

char* __wrap_wurl_http_get(const char * url, __attribute__((unused)) size_t max_size, long timeout) {
    check_expected(url);

    check_expected(timeout);

    return mock_type(char *);
}

curl_response* __wrap_wurl_http_request(char *method, char **headers, const char* url, const char *payload, size_t max_size, long timeout) {
    check_expected(method);

    char** ptr = headers;
    for (char* header = *ptr; header; header=*++ptr) {
        check_expected(header);
    }

    check_expected(url);

    if (payload) {
        check_expected(payload);
    }

    check_expected(max_size);

    check_expected(timeout);

    return mock_type(curl_response*);
}

CURL* __wrap_curl_easy_init() {
    return mock_type(CURL *);
}

void __wrap_curl_easy_cleanup(CURL *curl) {
    check_expected_ptr(curl);
}

CURLcode __wrap_curl_easy_setopt(CURL *curl, CURLoption option, __attribute__ ((__unused__)) void *parameter) {
    check_expected(option);
    check_expected_ptr(curl);

    return mock_type(CURLcode);
}

struct curl_slist* __wrap_curl_slist_append(struct curl_slist *list, const char *data) {
    check_expected(data);
    check_expected_ptr(list);

    return mock_type(struct curl_slist *);
}

CURLcode __wrap_curl_easy_perform(CURL *curl) {
    check_expected_ptr(curl);

    return mock_type(CURLcode);
}

void __wrap_curl_slist_free_all(struct curl_slist *list) {
    check_expected_ptr(list);
}

CURLcode __wrap_curl_easy_getinfo(CURL *curl, CURLoption option, __attribute__ ((__unused__)) void *parameter) {

    check_expected(option);
    check_expected_ptr(curl);

    return mock_type(CURLcode);
}

void __wrap_wurl_free_response(curl_response* response) {
    check_expected_ptr(response);
}
