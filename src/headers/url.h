/*
 * URL download support library
 * Copyright (C) 2015, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef URL_GET_H_
#define URL_GET_H_

#include "../external/curl/include/curl/curl.h"

#define WURL_WRITE_FILE_ERROR "Cannot open file '%s'"
#define WURL_DOWNLOAD_FILE_ERROR "Cannot download file '%s' from URL: '%s'"
#define WURL_TIMEOUT_ERROR  "Timeout reached when downloading file '%s' from URL: '%s'"

#define WURL_GET_METHOD "GET"
#define WURL_POST_METHOD "POST"

typedef struct curl_response {
    char *header;               /* Response header */
    char *body;                 /* Response body */
    long status_code;           /* Response code (200, 404, 500...) */
    bool max_size_reached;      /* Response incomplete, limit buffer reached */
} curl_response;

int wurl_get(const char * url, const char * dest, const char * header, const char *data, const long timeout);
int w_download_status(int status,const char *url,const char *dest);
// Request download
int wurl_request(const char * url, const char * dest, const char *header, const char *data, const long timeout);
int wurl_request_gz(const char * url, const char * dest, const char * header, const char * data, const long timeout, char *sha256);

/**
 * @brief Make a HTTP GET request
 * @param url URL to request
 * @param max_size Max response size allowed
 * @param timeout Maximum time allowed for the request
 * @return Request response (body)
 */
char * wurl_http_get(const char * url, size_t max_size, const long timeout);

/**
 * @brief Make a HTTP request
 * @param method HTTP method
 * @param headers Request headers
 * @param url URL to request
 * @param payload Request body
 * @param max_size Max response size allowed
 * @param timeout Maximum time allowed for the request
 * @return Request response (status_code, headers and body)
 */
curl_response *wurl_http_request(char *method, char **headers, const char *url, const char *payload, size_t max_size, const long timeout);

void wurl_free_response(curl_response* response);
#ifndef CLIENT
int wurl_request_bz2(const char * url, const char * dest, const char * header, const char * data, const long timeout, char *sha256);
int wurl_request_uncompress_bz2_gz(const char * url, const char * dest, const char * header, const char * data, const long timeout, char *sha256);
#endif

/* Check download module availability */
int wurl_check_connection();

#endif /* CUSTOM_OUTPUT_SEARCH_H_ */
