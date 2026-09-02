/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "http_op_wrappers.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

/* The buffer the client under test installed, remembered so __wrap_uhttp_post() can deliver the
 * body through it rather than inventing one. A single slot is enough: these clients are used one
 * request at a time, on one thread. */
static char *response_buffer = NULL;
static size_t response_capacity = 0;

/* What the last uhttp_client_new() was asked for. See the header for why it is a copy. */
static uhttp_captured_options_t captured = {0};

static void capture_string(char *destination, size_t capacity, const char *source) {
    if (source == NULL) {
        destination[0] = '\0';
        return;
    }

    strncpy(destination, source, capacity - 1);
    destination[capacity - 1] = '\0';
}

const uhttp_captured_options_t* uhttp_wrappers_last_options(void) {
    return &captured;
}

void uhttp_wrappers_reset(void) {
    memset(&captured, 0, sizeof(captured));
}

uhttp_client_t* __wrap_uhttp_client_new(const uhttp_options_t* opt) {
    if (opt != NULL) {
        capture_string(captured.url, sizeof(captured.url), opt->url);
        capture_string(captured.unix_socket_path, sizeof(captured.unix_socket_path), opt->unix_socket_path);
        capture_string(captured.content_type, sizeof(captured.content_type), opt->content_type);
        captured.timeout_ms = opt->timeout_ms;
        captured.connect_timeout_ms = opt->connect_timeout_ms;
    }

    ++captured.calls;

    return (uhttp_client_t*)mock_ptr_type(void*);
}

void __wrap_uhttp_client_free(uhttp_client_t* c) {
    (void)c;
    response_buffer = NULL;
    response_capacity = 0;
}

void __wrap_uhttp_client_set_response_buffer(uhttp_client_t* c, char* buf, size_t cap) {
    (void)c;
    response_buffer = buf;
    response_capacity = cap;
}

int __wrap_uhttp_post(uhttp_client_t* c, const void* data, size_t len, uhttp_result_t* out) {
    (void)c;
    (void)data;
    (void)len;

    const char *body = mock_ptr_type(char*);

    if (body != NULL && response_buffer != NULL && response_capacity > 0) {
        /* Truncates rather than overflowing, which is what the real write callback does once the
         * caller's buffer is full. */
        const size_t copied = strnlen(body, response_capacity - 1);
        memcpy(response_buffer, body, copied);
        response_buffer[copied] = '\0';
    }

    const int retval = mock_type(int);

    if (out != NULL) {
        out->http_status = mock_type(long);
        out->curl_code = 0;
    }

    return retval;
}
