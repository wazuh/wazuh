/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef HTTP_OP_WRAPPERS_H
#define HTTP_OP_WRAPPERS_H

#include "../../../../shared/include/http_op.h"

/*
 * Mocks for the uhttp_* client, for the daemons that reach a local HTTP-over-UDS service.
 *
 * The response body is delivered through the caller's own buffer, the way the real client does:
 * a test queues the body with will_return(__wrap_uhttp_post, body) and the wrapper copies it into
 * whatever buffer uhttp_client_set_response_buffer() was last given. That keeps the truncation
 * behaviour observable -- a body longer than the buffer is cut, exactly as libcurl's write
 * callback would cut it -- instead of handing the caller a pointer it never asked for.
 */

/**
 * @brief A copy of what the client under test asked for.
 *
 * Copied rather than kept by pointer: every caller builds its uhttp_options_t as a stack local and
 * some build the url into another local, both of which are gone by the time a test asserts. This
 * is what lets a test check the REQUEST, not only the response -- and the url in particular, which
 * libcurl requires to be absolute and which no mock will complain about on its own.
 */
typedef struct {
    char url[512];
    char unix_socket_path[512];
    char content_type[128];
    long timeout_ms;
    long connect_timeout_ms;
    int calls; ///< How many clients have been built since the last reset.
} uhttp_captured_options_t;

/// @brief The options from the most recent uhttp_client_new(). Never NULL.
const uhttp_captured_options_t* uhttp_wrappers_last_options(void);

/// @brief Forget every captured option. Call from a test setup that asserts on `calls`.
void uhttp_wrappers_reset(void);

uhttp_client_t* __wrap_uhttp_client_new(const uhttp_options_t* opt);

void __wrap_uhttp_client_free(uhttp_client_t* c);

void __wrap_uhttp_client_set_response_buffer(uhttp_client_t* c, char* buf, size_t cap);

/**
 * @brief Mocked POST.
 *
 * Queue, in order: the response body (a string, or NULL for none), then the value to return, then
 * the HTTP status to report in `out`.
 */
int __wrap_uhttp_post(uhttp_client_t* c, const void* data, size_t len, uhttp_result_t* out);

#endif
