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

#define WM_GITHUB_LOGTAG ARGV0 ":" GITHUB_WM_NAME

#define WM_GITHUB_DEFAULT_ENABLED 0
#define WM_GITHUB_DEFAULT_RUN_ON_START 1
#define WM_GITHUB_DEFAULT_ONLY_FUTURE_EVENTS 0
#define WM_GITHUB_DEFAULT_INTERVAL 600
#define WM_GITHUB_DEFAULT_DELAY 1

typedef struct wm_github_auth {
    char *org_name;                         // Organization name
    char *api_token;                        // Personal access token
    struct wm_github_auth *next;
} wm_github_auth;

typedef struct wm_github {
    int enabled;
    int run_on_start;
    int only_future_events;
    time_t interval;                        // Interval betweeen events in seconds
    time_t time_delay;
    wm_github_auth *auth;
    // api_parameters
    char *event_type;                       // Event types to include: web/git/all
} wm_github;

extern const wm_context WM_GITHUB_CONTEXT;  // Context

// Parse XML
int wm_github_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
