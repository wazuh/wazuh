/*
 * Wazuh Module for GitHub logs
 * Copyright (C) 2015-2021, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_GITHUB_H
#define WM_GITHUB_H

int wm_github_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

extern const wm_context WM_GITHUB_CONTEXT;   // Context

typedef struct _wm_github {
    int enabled;
} wm_github;

#define WM_GITHUB_LOGTAG ARGV0 ":" GITHUB_WM_NAME

#endif
