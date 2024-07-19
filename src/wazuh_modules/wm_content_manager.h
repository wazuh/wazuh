/*
 * Wazuh Module for update content for modules.
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WM_CONTENT_MANAGER
#define _WM_CONTENT_MANAGER

#define WM_CONTENT_MANAGER_LOGTAG ARGV0 ":content_manager"

#include "wmodules.h"

extern const wm_context WM_CONTENT_MANAGER_CONTEXT;

typedef struct wm_content_manager_t
{
    unsigned int enabled : 1;
    unsigned int run_on_start : 1;
} wm_content_manager_t;

wmodule* wm_content_manager_read();

#endif /* _WM_CONTENT_MANAGER */
