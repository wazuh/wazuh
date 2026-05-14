/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "json_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

cJSON * __wrap_json_fread(const char * path, __attribute__((unused)) char retry) {
    if (path) check_expected(path);
    return mock_type(cJSON *);
}

int __wrap_json_fwrite(const char * path, const cJSON * item) {
    check_expected(path);
    check_expected(item);
    return mock_type(int);
}

int* __wrap_json_parse_agents(__attribute__((unused))const cJSON* agents) {
    return mock_ptr_type(int*);
}
