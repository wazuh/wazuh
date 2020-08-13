/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "rehash_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


int __wrap_readlink(__attribute__((unused)) void **state) {
    return mock();
}

int __wrap_symlink(const char *path1, const char *path2) {
    check_expected(path1);
    check_expected(path2);
    return mock();
}
