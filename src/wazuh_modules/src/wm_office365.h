/*
 * Wazuh Module for Office365 events
 * Copyright (C) 2015, Wazuh Inc.
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
#define WM_OFFICE365_DEFAULT_ONLY_FUTURE_EVENTS 1
#define WM_OFFICE365_DEFAULT_INTERVAL 60
#define WM_OFFICE365_DEFAULT_CURL_MAX_SIZE 1048576L
#define WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT 60L
#define WM_OFFICE365_DEFAULT_API_LOGIN_FQDN "login.microsoftonline.com"
#define WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN "manage.office.com"

#define WM_OFFICE365_GCC_API_LOGIN_FQDN "login.microsoftonline.com"
#define WM_OFFICE365_GCC_API_MANAGEMENT_FQDN "manage-gcc.office.com"

#define WM_OFFICE365_GCC_HIGH_API_LOGIN_FQDN "login.microsoftonline.us"
#define WM_OFFICE365_GCC_HIGH_API_MANAGEMENT_FQDN "manage.office365.us"

#define WM_OFFICE365_MSG_DELAY 1000000 / wm_max_eps
#define WM_OFFICE365_RETRIES_TO_SEND_ERROR 3
#define WM_OFFICE365_NEXT_PAGE_REGEX "NextPageUri:\\s*(\\S+)"

#define WM_OFFICE365_API_ACCESS_TOKEN_URL "https://%s/%s/oauth2/v2.0/token"
#define WM_OFFICE365_API_SUBSCRIPTION_URL "https://%s/api/v1.0/%s/activity/feed/subscriptions/%s?contentType=%s"
#define WM_OFFICE365_API_CONTENT_BLOB_URL "https://%s/api/v1.0/%s/activity/feed/subscriptions/content?contentType=%s&startTime=%s&endTime=%s"

#define WM_OFFICE365_API_ACCESS_TOKEN_PAYLOAD "client_id=%s&scope=https://%s/.default&grant_type=client_credentials&client_secret=%s"

#define WM_OFFICE365_API_SUBSCRIPTION_START "start"
#define WM_OFFICE365_API_SUBSCRIPTION_STOP "stop"

typedef struct wm_office365_auth {
    char *tenant_id;
    char *client_id;
    char *client_secret_path;
    char *client_secret;
    char *login_fqdn;
    char *management_fqdn;
    struct wm_office365_auth *next;
} wm_office365_auth;

typedef struct wm_office365_subscription {
    char *subscription_name;
    struct wm_office365_subscription *next;
} wm_office365_subscription;

typedef struct wm_office365_state {
    time_t last_log_time;
} wm_office365_state;

typedef struct wm_office365_fail {
    int fails;
    char *tenant_id;
    char *subscription_name;
    struct wm_office365_fail *next;
} wm_office365_fail;

typedef struct wm_office365 {
    int enabled;
    int only_future_events;
    time_t interval;                        // Interval betweeen events in seconds
    ssize_t curl_max_size;
    wm_office365_auth *auth;
    wm_office365_subscription *subscription;
    wm_office365_fail *fails;
    int queue_fd;
} wm_office365;

extern const wm_context WM_OFFICE365_CONTEXT;  // Context

// Parse XML
int wm_office365_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
