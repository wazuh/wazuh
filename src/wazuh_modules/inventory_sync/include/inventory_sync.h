/*
 * Wazuh Inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * May 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_H
#define _INVENTORY_SYNC_H

// Define EXPORTED for any platform

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <external/cJSON/cJSON.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "commonDefs.h"
#include "logging_helper.h"

    EXPORTED void inventory_sync_start(full_log_fnc_t callbackLog, const cJSON* configuration);

    EXPORTED void inventory_sync_stop();

#ifdef __cplusplus
}
#endif

typedef void (*inventory_sync_start_func)(full_log_fnc_t callbackLog, const cJSON* configuration);

typedef void (*inventory_sync_stop_func)();

#endif // _INVENTORY_SYNC_H
