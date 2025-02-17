/*
 * Wazuh Module for Microsoft Graph
 * Copyright (C) 2023, InfoDefense Inc.
 * March, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_MS_GRAPH_H
#define WM_MS_GRAPH_H

#define WM_MS_GRAPH_LOGTAG ARGV0 ":" MS_GRAPH_WM_NAME

#define WM_MS_GRAPH_SCRIPT_PATH "wodles/ms_graph/ms-graph-logs"

#define WM_MS_GRAPH_DEFAULT_ENABLED true
#define WM_MS_GRAPH_DEFAULT_ONLY_FUTURE_EVENTS true
#define WM_MS_GRAPH_DEFAULT_CURL_MAX_SIZE 1048576L
#define WM_MS_GRAPH_DEFAULT_RUN_ON_START true
#define WM_MS_GRAPH_DEFAULT_VERSION "v1.0"

#define WM_MS_GRAPH_DEFAULT_TIMEOUT 60L
#define WM_MS_GRAPH_TIMESTAMP_SIZE_80 80

#define WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN "login.microsoftonline.com"
#define WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN "graph.microsoft.com"
#define WM_MS_GRAPH_GCC_HIGH_API_LOGIN_FQDN "login.microsoftonline.us"
#define WM_MS_GRAPH_GCC_HIGH_API_QUERY_FQDN "graph.microsoft.us"
#define WM_MS_GRAPH_DOD_API_LOGIN_FQDN "login.microsoftonline.us"
#define WM_MS_GRAPH_DOD_API_QUERY_FQDN "dod-graph.microsoft.us"


#define WM_MS_GRAPH_API_URL "https://%s/%s/%s/%s?$top=%d"
#define WM_MS_GRAPH_API_URL_FILTER_CREATED_DATE WM_MS_GRAPH_API_URL "&$filter=createdDateTime+ge+%s+and+createdDateTime+lt+%s"
#define WM_MS_GRAPH_API_URL_FILTER_ACTIVITY_DATE WM_MS_GRAPH_API_URL "&$filter=activityDateTime+ge+%s+and+activityDateTime+lt+%s"
#define WM_MS_GRAPH_ACCESS_TOKEN_URL "https://%s/%s/oauth2/v2.0/token"
#define WM_MS_GRAPH_ACCESS_TOKEN_PAYLOAD "scope=https://%s/.default&grant_type=client_credentials&client_id=%s&client_secret=%s"
#define WM_MS_GRAPH_ITEM_PER_PAGE 100

// MDM Intune
#define WM_MS_GRAPH_API_URL_DEVICES_EXPANDED "https://%s/%s/%s/%s/%s/%s?$top=%d"
#define WM_MS_GRAPH_API_URL_FILTER_DEVICE_FIELDS WM_MS_GRAPH_API_URL_DEVICES_EXPANDED "&$select=id,deviceName"
#define WM_MS_GRAPH_RESOURCE_DEVICE_MANAGEMENT "deviceManagement"
#define WM_MS_GRAPH_RELATIONSHIP_AUDIT_EVENTS "auditEvents"
#define WM_MS_GRAPH_RELATIONSHIP_MANAGED_DEVICES "managedDevices"
#define WM_MS_GRAPH_RELATIONSHIP_DETECTED_APPS "detectedApps"

typedef struct wm_ms_graph_state_t {
	time_t next_time;
} wm_ms_graph_state_t;

typedef struct wm_ms_graph_auth {
	char* client_id;
	char* tenant_id;
	char* secret_value;
	char* login_fqdn;
	char* query_fqdn;
	char* access_token;
	time_t token_expiration_time;
} wm_ms_graph_auth;

typedef struct wm_ms_graph_resource {
	char* name;
	char** relationships;
	unsigned int num_relationships;
} wm_ms_graph_resource;

typedef struct wm_ms_graph {
	bool enabled;
	bool only_future_events;
	ssize_t curl_max_size;
	unsigned int page_size;
	bool run_on_start;
	char* version;
	sched_scan_config scan_config;
	wm_ms_graph_auth **auth_config;
	wm_ms_graph_resource* resources;
	unsigned int num_resources;
	wm_ms_graph_state_t state;
} wm_ms_graph;

extern const wm_context WM_MS_GRAPH_CONTEXT; // Context

// Parse XML
int wm_ms_graph_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_MS_GRAPH_H
