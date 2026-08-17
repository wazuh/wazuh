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

/* Forward declaration, deliberately NOT an #include of the module's C-ABI header.
 * This header is pulled in (via wmodules.h) by translation units all over the tree, including ones
 * that have no business knowing about this module and do not carry its include directory. */
struct inventory_sync_server_config_t;

extern const wm_context WM_INVENTORY_SYNC_SERVER_CONTEXT;

/**
 * @brief The module's tunables, read in wm_inventory_sync_server_read() and carried to its main
 *        routine through wmodule::data.
 *
 * The numeric fields are filled from internal options, and that is the whole reason this struct is
 * populated in _read() rather than in the module's thread: getDefine_Int_default() calls
 * merror_exit() -- exit(1) for the whole daemon -- on an out-of-range value, and _read() runs inside
 * wm_config(), which happens BEFORE `wazuh-modulesd -t` returns and before goDaemon(). Reading them in
 * the module thread instead meant a typo in one option killed modulesd seconds after a start that the
 * init script had already reported as successful, and `-t` could not detect it at all.
 *
 * `cluster_name` and `indexer` are deliberately NOT filled here: they come from the XML
 * configuration, whose parse order relative to this call is not something this module should depend
 * on. The main routine fills them in immediately before start().
 */
typedef struct wm_inventory_sync_server_t
{
    /// Heap-allocated so this header does not need the module's C-ABI definition. Owned here; freed
    /// by wm_inventory_sync_server_destroy().
    struct inventory_sync_server_config_t* config;
} wm_inventory_sync_server_t;

wmodule* wm_inventory_sync_server_read();

#endif /* _WM_INVENTORY_SYNC_SERVER_H */
