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

#ifndef _WM_INVENTORY_SYNC_H
#define _WM_INVENTORY_SYNC_H

#define WM_INVENTORY_SYNC_LOGTAG ARGV0 ":inventory-sync"

#include "wmodules.h"

extern const wm_context WM_INVENTORY_SYNC_CONTEXT;

typedef struct wm_inventory_sync_t
{
    cJSON* inventory_sync;
} wm_inventory_sync_t;

wmodule* wm_inventory_sync_read();

#endif /* _WM_INVENTORY_SYNC_H */
