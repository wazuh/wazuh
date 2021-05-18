/*
 * Wazuh Module for Office365 events
 * Copyright (C) 2015-2021, Wazuh Inc.
 * May 18, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_OFFICE365_H
#define WM_OFFICE365_H

#define WM_OFFICE365_LOGTAG ARGV0 ":" OFFICE365_WM_NAME

#define WM_OFFICE365_DEFAULT_ENABLED 1


typedef struct wm_office365 {
    int enabled;
} wm_office365;

extern const wm_context WM_OFFICE365_CONTEXT;  // Context

// Parse XML
int wm_office365_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
