/*
 * URL download support library
 * Copyright (C) 2015-2020, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef URL_GET_H_
#define URL_GET_H_

#include <external/curl/include/curl/curl.h>

#define WURL_WRITE_FILE_ERROR "Failed opening file '%s'"
#define WURL_DOWNLOAD_FILE_ERROR "Failed to download file '%s' from url: %s"
#define WURL_HTTP_GET_ERROR "Failed to get a response from '%s'"

/**
 * @brief HTTP response data structure.
 *
 * HTTP response data structure managed by the URL shared library.
 */
typedef struct whttp_response_t {
  unsigned long status_code; /**<  Status code. */
  char* header; /**<  Jump line separated headers contained in the response. */
  size_t header_size; /**<  Header size. */
  char* body; /**<  Body contents in the response. */
  size_t body_size; /**<  Body size. */
} whttp_response_t;

int wurl_get(const char * url, const char * dest, const char * header, const char *data);
int w_download_status(int status,const char *url,const char *dest);
// Request download
int wurl_request(const char * url, const char * dest, const char *header, const char *data);
int wurl_request_gz(const char * url, const char * dest, const char * header, const char * data);

/**
 * @brief HTTP request function.
 *
 * This function performs an HTTP request by using libcurl.
 * @param method Mandatory. HTTP method to use in the request. Valid ones are GET and POST as of now.
 * @param url Mandatory. Address for the HTTP request.
 * @param header Optional. Jump line separated headers to include in the request.
 * @param data  Optional. Payload to include in the request.
 * @param timeout Mandatory. Timeout for the request. Use 0 to wait indefinitely.
 */
whttp_response_t* whttp_request(const char* method, const char* url, const char* header, const char* data, long timeout);

/* Check download module availability */
int wurl_check_connection();

#endif /* CUSTOM_OUTPUT_SEARCH_H_ */
