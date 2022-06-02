/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 1, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_STATE_WRAPPERS_H
#define WDB_STATE_WRAPPERS_H

#include <cJSON.h>

cJSON* __wrap_wdb_create_state_json();

#endif /* WDB_STATE_WRAPPERS_H */
