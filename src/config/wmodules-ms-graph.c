/*
 * Wazuh Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * March, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined WIN32 || defined __linux__ || defined __MACH__

#include "wazuh_modules/wmodules.h"

static const char* XML_ENABLED = "enabled";
static const char* XML_ONLY_FUTURE_EVENTS = "only_future_events";
static const char* XML_CURL_MAX_SIZE = "curl_max_size";
static const char* XML_RUN_ON_START = "run_on_start";

static const char* XML_VERSION = "version";
static const char* XML_RESOURCE = "resource";

static const char* XML_CLIENT_ID = "client_id";
static const char* XML_TENANT_ID = "tenant_id";
static const char* XML_SECRET_VALUE = "secret_value";

static const char* XML_RESOURCE_NAME = "name";
static const char* XML_RESOURCE_RELATIONSHIP = "relationship";

int wm_ms_graph_read(const OS_XML* xml, xml_node** nodes, wmodule* module) {

	int i = 0;
	wm_ms_graph* ms_graph;
	wm_ms_graph_auth* auth_config;
	wm_ms_graph_resource** resources;

	if (!nodes) {
		// TODO: Implement context in wm_ms_graph.c
		mwarn("Empty configuration found in module '%s.'", WM_MS_GRAPH_CONTEXT.name);
		return OS_INVALID;
	}

	// Init module
	os_malloc(sizeof(wm_ms_graph), ms_graph);
	ms_graph->enabled = WM_MS_GRAPH_DEFAULT_ENABLED;
	ms_graph->only_future_events = WM_MS_GRAPH_DEFAULT_ONLY_FUTURE_EVENTS;
	ms_graph->curl_max_size = WM_MS_GRAPH_DEFAULT_CURL_MAX_SIZE;
	ms_graph->run_on_start = WM_MS_GRAPH_DEFAULT_RUN_ON_START;
	ms_graph->version = WM_MS_GRAPH_DEFAULT_VERSION;
	sched_scan_init(&(ms_graph->scan_config));
	ms_graph->scan_config.interval = WM_DEF_INTERVAL;
	module->context = &WM_MS_GRAPH_CONTEXT;
	module->tag = strndup(module->context->name, 8); // "ms-graph"
	module->data = ms_graph;

	for (i; nodes[i]; i++) {
		if (!nodes[i]->element) {
			merror(XML_VALUENULL);
			return OS_INVALID;
		}
		else if (!strncmp(nodes[i]->element, XML_ENABLED, sizeof(XML_ENABLED) - 1) {
			if (!strncmp(nodes[i]->content, "yes", sizeof("yes") - 1)) {
				ms_graph->enabled = true;
			}
			else if (!strncmp(nodes[i]->content, "no", sizeof("no") - 1)) {
				ms_graph->enabled = false;
			}
			else {
				merror("Module '%s' has invalid content in tag '%s'.", WM_MS_GRAPH_CONTEXT.name, XML_ENABLED);
				return OS_INVALID;
			}
		}
		else if (!strncmp(nodes[i]->element, XML_ONLY_FUTURE_EVENTS, sizeof(XML_ONLY_FUTURE_EVENTS) - 1) {
			if (!strncmp(nodes[i]->content, "yes", sizeof("yes") - 1)) {
				ms_graph->only_future_events = true;
			}
			else if (!strncmp(nodes[i]->content, "no", sizeof("no") - 1)) {
				ms_graph->only_future_events = false;
			}
			else {
				merror("Module '%s' has invalid content in tag '%s'.", WM_MS_GRAPH_CONTEXT.name, XML_ONLY_FUTURE_EVENTS);
				return OS_INVALID;
			}
		}
		else if (!strncmp(nodes[i]->element, XML_CURL_MAX_SIZE, sizeof(XML_CURL_MAX_SIZE) - 1) {
			ms_graph->curl_max_size = w_parse_time(nodes[i]->content);
			// TODO: Find a good minimum size
			if (ms_graph->curl_max_size < 1024L) {
				merror("Module '%s' has invalid content in tag '%s': the minimum size is 1KB.", WM_MS_GRAPH_CONTEXT.name, XML_CURL_MAX_SIZE);
				// Necessary?
				ms_graph->curl_max_size = WM_MS_GRAPH_DEFAULT_CURL_MAX_SIZE;
				return OS_INVALID;
			}
		}
		else if (!strncmp(nodes[i]->element, XML_RUN_ON_START, sizeof(XML_RUN_ON_START) - 1) {
			if (!strncmp(nodes[i]->content, "yes", sizeof("yes") - 1)) {
				ms_graph->run_on_start = true;
			}
			else if (!strncmp(nodes[i]->content, "no", sizeof("no") - 1)) {
				ms_graph->run_on_start = false;
			}
			else {
				merror("Module '%s' has invalid content in tag '%s'.", WM_MS_GRAPH_CONTEXT.name, XML_RUN_ON_START);
					return OS_INVALID;
			}
		}
		// TODO: rest of code

	}

	return OS_SUCCESS;
}

#endif // WIN32 || defined __linux__ || defined __MACH__
