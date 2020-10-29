/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "run_realtime_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_realtime_adddir(const char *dir, int whodata, __attribute__((unused)) int followsl) {
    check_expected(dir);
    check_expected(whodata);

    return mock();
}

int __wrap_realtime_start() {
    return 0;
}
