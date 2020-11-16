/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_metadata_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_wdb_metadata_table_check(__attribute__((unused)) wdb_t * wdb,
                                    const char * key) {
    check_expected(key);
    return mock();
}

int __wrap_wdb_metadata_get_entry (__attribute__((unused)) wdb_t * wdb,
                                   const char *key,
                                   char *output) {
    check_expected(key);
    snprintf(output, OS_SIZE_256 + 1, "%s", mock_ptr_type(char*));
    return mock();
}

