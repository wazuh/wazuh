/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wmodules_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>

int __wrap_wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {
    check_expected(usec);
    check_expected(queue);
    check_expected(message);
    check_expected(locmsg);
    check_expected(loc);

    return mock();
}

int __wrap_wm_state_io(const char * tag,
                       int op,
                       void *state,
                       size_t size) {
    check_expected(tag);
    check_expected(op);
    check_expected_ptr(state);
    check_expected(size);
    int ret = mock();
    if (!ret) {
        memcpy(state, mock_type(void *), sizeof(*state));
    }
    return ret;
}
