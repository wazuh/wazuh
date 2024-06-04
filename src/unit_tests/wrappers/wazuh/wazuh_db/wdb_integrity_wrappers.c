/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_integrity_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_wdbi_remove_by_pk(__attribute__((unused))wdb_t *wdb,
                              wdb_component_t component,
                              const char *pk_value) {
    check_expected(component);
    if (pk_value) {
        check_expected(pk_value);
    }
}