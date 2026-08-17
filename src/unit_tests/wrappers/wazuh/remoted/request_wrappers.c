/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include "request_wrappers.h"

int __wrap_req_save(const char * counter, const char * buffer, size_t length) {
    check_expected(counter);
    check_expected(buffer);
    check_expected(length);
    return mock();
}

int __wrap_req_send_and_wait(const char * agent_id, const char * payload, size_t length, char ** response, int timeout_sec) {
    check_expected(agent_id);
    check_expected(payload);
    check_expected(length);
    check_expected(timeout_sec);

    char * mocked_response = mock_ptr_type(char *);

    if (mocked_response) {
        *response = strdup(mocked_response);
    } else {
        *response = NULL;
    }

    return mock_type(int);
}
