/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SCHEDULE_SCAN_WRAPPERS_H
#define SCHEDULE_SCAN_WRAPPERS_H

#include <time.h>
#include "shared.h"

void __wrap_sched_scan_dump(const sched_scan_config* scan_config,
                            cJSON *cjson_object);

time_t __wrap_sched_scan_get_time_until_next_scan(sched_scan_config *config,
                                                  const char *MODULE_TAG,
                                                  const int run_on_start);

int __wrap_sched_scan_read(sched_scan_config *scan_config,
                           xml_node **nodes,
                           const char *MODULE_NAME);

#endif
