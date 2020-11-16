/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "vector_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_W_Vector_insert_unique(W_Vector *v, const char *element) {
    check_expected_ptr(v);
    check_expected(element);

    return mock();
}

int __wrap_W_Vector_length(__attribute__((unused)) W_Vector *v) {
    return mock();
}
