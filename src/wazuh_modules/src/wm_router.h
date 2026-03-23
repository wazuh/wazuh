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

#ifndef _WM_ROUTER
#define _WM_ROUTER

#define WM_ROUTER_LOGTAG ARGV0 ":router"

#include "wmodules.h"

extern const wm_context WM_ROUTER_CONTEXT;

typedef struct wm_router_t
{
} wm_router_t;

wmodule* wm_router_read();

#endif /* _WM_ROUTER */
