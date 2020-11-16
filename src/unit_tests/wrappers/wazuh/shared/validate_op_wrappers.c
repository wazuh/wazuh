/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "validate_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_getDefine_Int(__attribute__((unused)) const char *high_name,
                         __attribute__((unused)) const char *low_name,
                         __attribute__((unused)) int min,
                         __attribute__((unused)) int max) {
    // For SCA
    if (!strcmp(low_name, "request_db_interval")) {
        return 5;
    }

    // For SCA
    if (!strcmp(low_name, "commands_timeout")) {
        return 300;
    }

    return mock();
}

int __wrap_OS_IsValidIP(const char *ip_address, os_ip *final_ip) {
    check_expected(ip_address);
    check_expected(final_ip);

    return mock_type(int);
}
