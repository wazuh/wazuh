/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef MONITORD_WRAPPERS_H
#define MONITORD_WRAPPERS_H

void __wrap_w_rotate_log(int compress, int keep_log_days, int new_day, int rotate_json, int daily_rotations);

#endif
