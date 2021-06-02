/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef URL_WRAPPERS_H
#define URL_WRAPPERS_H

#include "headers/url.h"

#define curl_easy_init wrap_curl_easy_init
#define curl_easy_cleanup wrap_curl_easy_cleanup
#undef curl_easy_setopt
#define curl_easy_setopt wrap_curl_easy_setopt
#define curl_slist_append wrap_curl_slist_append
#define curl_easy_perform wrap_curl_easy_perform
#define curl_slist_free_all wrap_curl_slist_free_all
#undef curl_easy_getinfo
#define curl_easy_getinfo wrap_curl_easy_getinfo

CURL* wrap_curl_easy_init();

void wrap_curl_easy_cleanup(CURL* curl);

CURLcode wrap_curl_easy_setopt(CURL *curl, CURLoption option, void *parameter);

struct curl_slist* wrap_curl_slist_append(struct curl_slist *list, const char *string);

CURLcode wrap_curl_easy_perform(CURL *curl);

void wrap_curl_slist_free_all(struct curl_slist *list);

int wrap_wurl_request(const char * url, const char * dest, const char *header, const char *data, const long timeout);

char* wrap_wurl_http_get(const char * url);

curl_response* wrap_wurl_http_get_with_header(const char *header, const char* url);

CURLcode wrap_curl_easy_getinfo(CURL *curl, CURLoption option, void *parameter);

#endif
