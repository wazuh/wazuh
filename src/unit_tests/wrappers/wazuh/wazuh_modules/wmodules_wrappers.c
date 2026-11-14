/* Copyright (C) Wazuh Inc.
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

// Checks the descriptor the caller passes in under the name "queue", like __wrap_wm_sendmsg().
int __wrap_wm_sendmsg_with_reconnect(int usec, int *queue_ptr, const char *message, const char *locmsg, char loc, const char *tag) {
    int queue = *queue_ptr;

    check_expected(usec);
    check_expected(queue);
    check_expected(message);
    check_expected(locmsg);
    check_expected(loc);
    check_expected(tag);

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

int __wrap_wm_validate_command(const char *command, const char *digest, crypto_type ctype) {
    check_expected(command);
    check_expected(digest);
    check_expected(ctype);

    return mock_type(int);
}

void expect_wm_validate_command(const char *command, const char *digest, crypto_type ctype, int ret) {
    expect_string(__wrap_wm_validate_command, command, command);
    expect_string(__wrap_wm_validate_command, digest, digest);
    expect_value(__wrap_wm_validate_command, ctype, ctype);
    will_return(__wrap_wm_validate_command, ret);
}
