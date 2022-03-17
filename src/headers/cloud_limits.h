/* Copyright (C) 2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LIMITS_H
#define LIMITS_H

#include "shared.h"

int load_limits_file(void);
void clean_limits_objects(void);
cJSON * get_deamon_limits(const char *deamon_name);


#endif
