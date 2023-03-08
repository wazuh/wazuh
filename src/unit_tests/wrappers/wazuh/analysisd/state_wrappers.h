/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 30, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ASYS_STATE_WRAPPERS_H
#define ASYS_STATE_WRAPPERS_H

#include <cJSON.h>

cJSON* __wrap_asys_create_state_json();

cJSON* __wrap_asys_create_agents_state_json(int *agents_ids);

#endif /* ASYS_STATE_WRAPPERS_H */
