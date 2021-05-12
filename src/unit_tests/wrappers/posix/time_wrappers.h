/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef TIME_WRAPPERS_H
#define TIME_WRAPPERS_H

#include <time.h>

time_t __wrap_time(time_t *t);

#endif // TIME_WRAPPERS_H
