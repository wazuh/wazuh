/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "schedule_scan_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


time_t __wrap_sched_scan_get_time_until_next_scan(sched_scan_config *config,
                                                  const char *MODULE_TAG,
                                                  const int run_on_start) {
    check_expected_ptr(config);
    check_expected(MODULE_TAG);
    check_expected(run_on_start);

    return mock_type(time_t);
}
