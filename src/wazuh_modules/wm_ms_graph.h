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

#define WM_MS_GRAPH_H_LOGTAG ARGV0 ":" MS_GRAPH_WM_NAME

#define WM_MS_GRAPH_SCRIPT_PATH "wodles/ms-graph/ms-graph-logs"

typedef struct wm_ms_graph_state_t {
	timet_t next_time;
} wm_ms_graph_state_t;

typedef struct wm_ms_graph_auth {
	char* client_id;
	char* tenant_id;
	char* secret_value;
	char* access_token;
} wm_ms_graph_auth;

typedef struct wm_ms_graph_resource {
	char* name;
	char** resources;
} wm_ms_graph_resource;

typedef struct wm_ms_graph {
	bool enabled;
	bool run_on_start;
	char* version;
	sched_scan_config scan_config;
	wm_ms_graph_resource** resources;
	wm_ms_graph_auth auth_config;
	wm_ms_graph_state_t state;
};

extern const wm_context WM_MS_GRAPH_CONTEXT; // Context

// Parse XML
int wm_ms_graph_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_MS_GRAPH_H
