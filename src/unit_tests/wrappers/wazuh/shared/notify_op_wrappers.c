/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#include "notify_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_wnotify_modify(wnotify_t * notify, int fd, const woperation_t op) {
    check_expected_ptr(notify);
    check_expected(fd);
    check_expected(op);
    return mock();
}

int __wrap_wnotify_add(wnotify_t * notify, int fd, const woperation_t op) {
    check_expected_ptr(notify);
    check_expected(fd);
    check_expected(op);
    return mock();
}

#endif
