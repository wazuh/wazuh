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

#include "headers/shared.h"

int __wrap_wurl_request(const char * url, const char * dest, const char *header, const char *data, const long timeout);

char* __wrap_wurl_http_get(const char * url);

curl_response* __wrap_wurl_http_get_with_header(const char *header, const char* url);

#endif
