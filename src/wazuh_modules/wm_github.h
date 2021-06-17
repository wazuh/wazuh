/*
 * Wazuh Module for GitHub logs
 * Copyright (C) 2015-2021, Wazuh Inc.
 * May 3, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_GITHUB_H
#define WM_GITHUB_H

#define WM_GITHUB_LOGTAG ARGV0 ":" GITHUB_WM_NAME

#define WM_GITHUB_DEFAULT_ENABLED 1
#define WM_GITHUB_DEFAULT_ONLY_FUTURE_EVENTS 1
#define WM_GITHUB_DEFAULT_INTERVAL 600
#define WM_GITHUB_DEFAULT_DELAY 1
#define WM_GITHUB_MSG_DELAY 1000000 / wm_max_eps
#define WM_GITHUB_DEFAULT_CURL_MAX_SIZE 1048576L

#define ITEM_PER_PAGE 100
#define RETRIES_TO_SEND_ERROR 3
#define GITHUB_NEXT_PAGE_REGEX "<(\\S+)>;\\s*rel=\"next\""

#define GITHUB_API_URL "https://api.github.com/orgs/%s/audit-log?phrase=created:%s..%s&include=%s&order=asc&per_page=%d"

typedef struct wm_github_auth {
    char *org_name;                         // Organization name
    char *api_token;                        // Personal access token
    struct wm_github_auth *next;
} wm_github_auth;

typedef struct wm_github_state {
    time_t last_log_time;                      // Absolute time of last scan
} wm_github_state;

typedef struct wm_github_fail {
    int fails;
    char *org_name;
    struct wm_github_fail *next;
} wm_github_fail;

typedef struct wm_github {
    int enabled;
    int only_future_events;
    time_t interval;                        // Interval betweeen events in seconds
    time_t time_delay;
    ssize_t curl_max_size;
    wm_github_auth *auth;
    char *event_type;                       // Event types to include: web/git/all
    wm_github_fail *fails;
    int queue_fd;
} wm_github;

extern const wm_context WM_GITHUB_CONTEXT;  // Context

// Parse XML
int wm_github_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
