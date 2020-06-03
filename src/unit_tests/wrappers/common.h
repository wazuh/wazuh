/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef COMMON_H
#define COMMON_H

#include <time.h>

int FOREVER();

int __wrap_FOREVER();

time_t wrap_time (time_t *t);

#ifdef WIN32
extern time_t time_mock_value;

#define time(x) wrap_time(x)
#endif

#endif /* COMMON_H */

