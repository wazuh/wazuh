/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <time.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "headers/defs.h"

time_t time_mock_value;
int test_mode = 0;
int activate_full_db = 0;

int FOREVER() {
    return 1;
}

int __wrap_FOREVER() {
    return mock();
}

time_t wrap_time (__attribute__ ((__unused__)) time_t *t) {
    return time_mock_value;
}
