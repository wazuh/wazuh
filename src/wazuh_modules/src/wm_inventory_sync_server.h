/*
 * Wazuh Module for the inventory sync server (HTTP over Unix domain socket)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WM_INVENTORY_SYNC_SERVER_H
#define _WM_INVENTORY_SYNC_SERVER_H

/* Distinct from WM_INVENTORY_SYNC_LOGTAG on purpose: both modules run in this same daemon during
 * the migration, so an operator has to be able to tell their lines apart in ossec.log. */
#define WM_INVENTORY_SYNC_SERVER_LOGTAG ARGV0 ":inventory-sync-server"

#include "wmodules.h"

extern const wm_context WM_INVENTORY_SYNC_SERVER_CONTEXT;

typedef struct wm_inventory_sync_server_t
{
    cJSON* inventory_sync_server;
} wm_inventory_sync_server_t;

wmodule* wm_inventory_sync_server_read();

#endif /* _WM_INVENTORY_SYNC_SERVER_H */
