/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

time_t __wrap_sched_scan_get_time_until_next_scan(sched_scan_config *config,
                                                  const char *MODULE_TAG,
                                                  const int run_on_start);

#endif
