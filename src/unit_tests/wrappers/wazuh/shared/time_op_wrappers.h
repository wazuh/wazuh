/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef TIME_OP_WRAPPERS_H
#define TIME_OP_WRAPPERS_H

#include <time.h>

void __wrap_w_sleep_until(const time_t new_time);

void __wrap_w_time_delay(unsigned long int msec);

char* __wrap_w_get_timestamp(time_t time);

extern time_t current_time;

#endif
