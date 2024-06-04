/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef URL_WRAPPERS_H
#define URL_WRAPPERS_H

#include "../../../../headers/shared.h"
#include "../../../../headers/url.h"

int __wrap_wurl_request(const char * url, const char * dest, const char *header, const char *data, const long timeout);

char* __wrap_wurl_http_get(const char * url, size_t max_size, long timeout);

curl_response* __wrap_wurl_http_request(char *method, char **headers, const char* url, const char *payload, size_t max_size, long timeout);

CURL* __wrap_curl_easy_init();

void __wrap_curl_easy_cleanup(CURL* curl);

CURLcode __wrap_curl_easy_setopt(CURL *curl, CURLoption option, void *parameter);

struct curl_slist* __wrap_curl_slist_append(struct curl_slist *list, const char *string);

CURLcode __wrap_curl_easy_perform(CURL *curl);

void __wrap_curl_slist_free_all(struct curl_slist *list);

CURLcode __wrap_curl_easy_getinfo(CURL *curl, CURLoption option, void *parameter);

void __wrap_wurl_free_response(curl_response* response);

#endif
