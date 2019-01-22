/*
 * URL download support library
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef URL_GET_H_
#define URL_GET_H_

#if (defined(_MSC_VER) && !defined(__INTEL_COMPILER))
#include <curl/curl.h>
#else
#include <external/curl/include/curl/curl.h>
#endif

#define WURL_WRITE_FILE_ERROR "Failed opening file '%s'"
#define WURL_DOWNLOAD_FILE_ERROR "Failed to download file '%s' from url: %s"
#define WURL_HTTP_GET_ERROR "Failed to get a response from '%s'"

int wurl_get(const char * url, const char * dest);
int w_download_status(int status,const char *url,const char *dest);
// Request download
int wurl_request(const char * url, const char * dest);
int wurl_http_get(const char * url, char * data);

#endif /* CUSTOM_OUTPUT_SEARCH_H_ */
