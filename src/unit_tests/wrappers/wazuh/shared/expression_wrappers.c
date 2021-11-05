/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "expression_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

bool __wrap_w_expression_match(__attribute__((unused))w_expression_t * expression, __attribute__((unused))const char * str_test, 
                               __attribute__((unused))const char ** end_match, __attribute__((unused))regex_matching * regex_match) {
    return mock_type(bool);
}
