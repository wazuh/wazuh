/*
 * Wazuh Module for routing messages to the right module
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WM_INVENTORY_HARVESTER_H
#define _WM_INVENTORY_HARVESTER_H

#define WM_INVENTORY_HARVESTER_LOGTAG ARGV0 ":inventory-harvester"

#include "wmodules.h"

extern const wm_context WM_INVENTORY_HARVESTER_CONTEXT;

typedef struct wm_inventory_harvester_t
{
    cJSON* inventory_harvester;
} wm_inventory_harvester_t;

wmodule* wm_inventory_harvester_read();

#endif /* _WM_INVENTORY_HARVESTER_H */
