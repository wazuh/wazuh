/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef RUN_REALTIME_WRAPPERS_H
#define RUN_REALTIME_WRAPPERS_H

int __wrap_realtime_adddir(const char *dir, int whodata, int followsl);

int __wrap_realtime_start();

#endif
