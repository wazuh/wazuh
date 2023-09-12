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
#include "limits_op_wrappers.h"

bool __wrap_limit_reached(__attribute__((unused)) void *limits, unsigned int *value) {
    *value = mock_type(unsigned int);
    return mock_type(bool);
}
