/* Copyright (C) 2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "cloud_limits_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


int __wrap_load_limits_file(const char *daemon_name, cJSON ** daemon_obj) {
    check_expected(daemon_name);

    *daemon_obj = mock_ptr_type(cJSON*);

    return mock();
}