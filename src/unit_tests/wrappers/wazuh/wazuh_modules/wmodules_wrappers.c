/* Copyright (C) 2015-2020, Wazuh Inc.
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
#include <cmocka.h>

int __wrap_wm_sendmsg(__attribute__((unused)) int usec,
                      __attribute__((unused)) int queue,
                      __attribute__((unused)) const char *message,
                      __attribute__((unused)) const char *locmsg,
                      __attribute__((unused)) char loc) {
    return 0;
}

int __wrap_wm_state_io(const char * tag,
                       int op,
                       void *state,
                       size_t size) {
    check_expected(tag);
    check_expected(op);
    check_expected_ptr(state);
    check_expected(size);

    return mock();
}
