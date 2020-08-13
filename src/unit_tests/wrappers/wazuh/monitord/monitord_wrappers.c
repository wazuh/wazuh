/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "monitord_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_w_rotate_log(__attribute__((unused)) int compress,
                         __attribute__((unused)) int keep_log_days,
                         __attribute__((unused)) int new_day,
                         __attribute__((unused)) int rotate_json,
                         __attribute__((unused)) int daily_rotations) {
    return;
}
