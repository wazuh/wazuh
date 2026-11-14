/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wait_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_os_wait_predicate(bool (*fn_ptr)()) {
    check_expected_ptr(fn_ptr);
}

bool __wrap_os_iswait(void) {
    return mock_type(bool);
}
