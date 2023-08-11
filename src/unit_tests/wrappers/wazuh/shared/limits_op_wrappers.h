/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Aug 24, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ASYS_LIMITS_OP_WRAPPERS_H
#define ASYS_LIMITS_OP_WRAPPERS_H

#include <stdbool.h>

bool __wrap_limit_reached(__attribute__((unused)) void *limits, unsigned int *value);

#endif /* ASYS_LIMITS_OP_WRAPPERS_H */
