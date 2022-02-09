/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "atomic_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_atomic_int_get(atomic_int_t *atomic) {
    check_expected_ptr(atomic);
    return mock();
}

void __wrap_atomic_int_set(atomic_int_t *atomic, __attribute__((unused)) int value) {
    check_expected_ptr(atomic);
    atomic->data = mock();
}

int __wrap_atomic_int_inc(atomic_int_t *atomic) {
    check_expected_ptr(atomic);
    return mock();
}

int __wrap_atomic_int_dec(atomic_int_t *atomic) {
    check_expected_ptr(atomic);
    return mock();
}
