/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "version_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_compare_wazuh_versions(const char *version1, const char *version2, bool compare_patch) {
    check_expected(version1);
    check_expected(version2);
    check_expected(compare_patch);

    return mock();
}
