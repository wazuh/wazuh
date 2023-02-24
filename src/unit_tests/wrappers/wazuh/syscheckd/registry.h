/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#include <cJSON.h>

#ifndef WIN_REGISTRY_WRAPPERS_H
#define WIN_REGISTRY_WRAPPERS_H

void __wrap_fim_registry_scan();

cJSON* __wrap_fim_dbsync_registry_value_json_event();

#endif
