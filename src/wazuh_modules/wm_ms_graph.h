/*
 * Wazuh Module for Microsoft Graph
 * Copyright (C) 2015, Wazuh Inc.
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

#define WM_MS_GRAPH_SCRIPT_PATH "wodles/ms-graph/ms-graph-logs"

#define WM_MS_GRAPH_DEFAULT_ENABLED true
#define WM_MS_GRAPH_DEFAULT_ONLY_FUTURE_EVENTS true
#define WM_MS_GRAPH_DEFAULT_CURL_MAX_SIZE 1048576L
#define WM_MS_GRAPH_DEFAULT_RUN_ON_START true
#define WM_MS_GRAPH_DEFAULT_VERSION "v1.0"

#define WM_MS_GRAPH_DEFAULT_TIMEOUT 60L

#define WM_MS_GRAPH_API_URL "https://graph.microsoft.com/%s/%s/%s?$filter=createdDateTime+gt+%s"
#define WM_MS_GRAPH_ACCESS_TOKEN_URL "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
#define WM_MS_GRAPH_ACCESS_TOKEN_PAYLOAD "scope=https://graph.microsoft.com/.default&grant_type=client_credentials&client_id=%s&client_secret=%s"

typedef struct wm_ms_graph_state_t {
	time_t next_time;
} wm_ms_graph_state_t;

typedef struct wm_ms_graph_auth {
	char* client_id;
	char* tenant_id;
	char* secret_value;
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
	bool run_on_start;
	char* version;
	sched_scan_config scan_config;
	wm_ms_graph_auth auth_config;
	wm_ms_graph_resource* resources;
	unsigned int num_resources;
	wm_ms_graph_state_t state;
} wm_ms_graph;

extern const wm_context WM_MS_GRAPH_CONTEXT; // Context

// Parse XML
int wm_ms_graph_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_MS_GRAPH_H
