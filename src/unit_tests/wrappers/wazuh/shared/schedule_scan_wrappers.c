/* Copyright (C) 2015, Wazuh Inc.
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
#include <stdint.h>
#include <cmocka.h>


void __wrap_sched_scan_dump(const sched_scan_config* scan_config,
                            cJSON *cjson_object) {
    check_expected_ptr(scan_config);
    check_expected_ptr(cjson_object);
}

time_t __wrap_sched_scan_get_time_until_next_scan(sched_scan_config *config,
                                                  const char *MODULE_TAG,
                                                  const int run_on_start) {
    check_expected_ptr(config);
    check_expected(MODULE_TAG);
    check_expected(run_on_start);

    return mock_type(time_t);
}

int __wrap_sched_scan_read(__attribute__((unused)) sched_scan_config *scan_config,
                           xml_node **nodes,
                           const char *MODULE_NAME) {
    check_expected_ptr(nodes);
    check_expected(MODULE_NAME);

    return mock();
}
