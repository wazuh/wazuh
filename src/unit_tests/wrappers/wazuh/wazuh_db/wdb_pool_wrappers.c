/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "wdb_pool_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

wdb_t * __wrap_wdb_pool_get(const char * name) {
    check_expected(name);
    return mock_ptr_type(wdb_t*);
}

wdb_t * __wrap_wdb_pool_get_or_create(const char * name) {
    check_expected(name);
    return mock_ptr_type(wdb_t*);
}

void __wrap_wdb_pool_leave(__attribute__((unused))wdb_t * node) {
    function_called();
}

char ** __wrap_wdb_pool_keys() {
    return mock_type(char **);
}

void __wrap_wdb_pool_clean() {
    function_called();
}
