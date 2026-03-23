/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "bqueue_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_bqueue_push(bqueue_t * queue, const void * data, size_t length, unsigned flags) {
    check_expected_ptr(queue);
    check_expected(data);
    check_expected(length);
    check_expected(flags);
    return mock();
}

size_t __wrap_bqueue_peek(bqueue_t * queue, char * buffer, size_t length, unsigned flags) {
    check_expected_ptr(queue);
    check_expected(flags);
    if (mock()) {
        memcpy(buffer, mock_type(char *), length);
    }
    return mock();
}

int __wrap_bqueue_drop(bqueue_t * queue, size_t length) {
    check_expected_ptr(queue);
    check_expected(length);
    return mock();
}

void __wrap_bqueue_clear(bqueue_t * queue) {
    check_expected_ptr(queue);
}

size_t __wrap_bqueue_used(bqueue_t * queue) {
    check_expected_ptr(queue);
    return mock();
}
