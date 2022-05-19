/* Copyright (C) 2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CLOUD_LIMITS_WRAPPERS_H
#define CLOUD_LIMITS_WRAPPERS_H

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "shared.h"

int __wrap_load_limits_file(const char *daemon_name, cJSON ** daemon_obj);

#endif