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
static const char* XML_API_AUTH = "api_auth";
static const char* XML_RESOURCE = "resource";

static const char* XML_CLIENT_ID = "client_id";
static const char* XML_TENANT_ID = "tenant_id";
static const char* XML_SECRET_VALUE = "secret_value";

static const char* XML_RESOURCE_NAME = "name";
static const char* XML_RESOURCE_RELATIONSHIP = "relationship";

int wm_ms_graph_read(const OS_XML* xml, xml_node** nodes, wmodule* module) {

	wm_ms_graph* ms_graph;
	wm_ms_graph_resource** resources;

	if (!nodes) {
		// TODO: Implement context in wm_ms_graph.c
		mwarn("Empty configuration found in module '%s.'", WM_MS_GRAPH_CONTEXT.name);
		return OS_CFGERR;
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
	os_malloc(sizeof(wm_ms_graph_resource) * 2, resources);
	ms_graph->resources = resources;
	module->context = &WM_MS_GRAPH_CONTEXT;
	module->tag = strndup(module->context->name, 8); // "ms-graph"
	module->data = ms_graph;

	for (int i = 0; nodes[i]; i++) {
		XML_NODE children = NULL;

		if (!nodes[i]->element) {
			merror(XML_ELEMNULL);
			return OS_CFGERR;
		}
		else if (!nodes[i]->content) {
			merror(XML_ELEMNULL);
			return OS_CFGERR;
		}
		else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
			if (!strcmp(nodes[i]->content, "yes")) {
				ms_graph->enabled = true;
			}
			else if (!strcmp(nodes[i]->content, "no")) {
				ms_graph->enabled = false;
			}
			else {
				merror(XML_INVALID, XML_ENABLED, WM_MS_GRAPH_CONTEXT.name);
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_ONLY_FUTURE_EVENTS)) {
			if (!strcmp(nodes[i]->content, "yes")) {
				ms_graph->only_future_events = true;
			}
			else if (!strcmp(nodes[i]->content, "no")) {
				ms_graph->only_future_events = false;
			}
			else {
				merror(XML_INVALID, XML_ONLY_FUTURE_EVENTS, WM_MS_GRAPH_CONTEXT.name);
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_CURL_MAX_SIZE)) {
			ms_graph->curl_max_size = w_parse_time(nodes[i]->content);
			// TODO: Find a good minimum size
			if (ms_graph->curl_max_size < 1024L) {
				merror("Module '%s' has invalid content in tag '%s': the minimum size is 1KB.", WM_MS_GRAPH_CONTEXT.name, XML_CURL_MAX_SIZE);
				// Necessary?
				ms_graph->curl_max_size = WM_MS_GRAPH_DEFAULT_CURL_MAX_SIZE;
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
			if (!strcmp(nodes[i]->content, "yes")) {
				ms_graph->run_on_start = true;
			}
			else if (!strcmp(nodes[i]->content, "no")) {
				ms_graph->run_on_start = false;
			}
			else {
				merror(XML_INVALID, XML_RUN_ON_START, WM_MS_GRAPH_CONTEXT.name);
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_VERSION)) {
			if (!strcmp(nodes[i]->content, "v1.0") || !strcmp(nodes[i]->content, "beta")) {
				os_strdup(nodes[i]->content, ms_graph->version);
			}
			else {
				merror(XML_INVALID, XML_RUN_ON_START, WM_MS_GRAPH_CONTEXT.name);
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_API_AUTH)) {
			if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
				OS_ClearNode(children);
				merror(XML_INVALID, XML_API_AUTH, WM_MS_GRAPH_CONTEXT.name);
				return OS_CFGERR;
			}
			for (int j = 0; children[j]; j++) {
				if (!strcmp(children[j]->element, XML_CLIENT_ID)) {
					if (sizeof(children[j]->content) == 37 ) {
						os_strdup(children[j]->content, ms_graph->auth_config.client_id);
					}
					else {
						merror(XML_INVALID, XML_CLIENT_ID, WM_MS_GRAPH_CONTEXT.name);
						return OS_CFGERR;
					}
				}
				else if (!strcmp(children[j]->element, XML_TENANT_ID)) {
					if (sizeof(children[j]->content) == 37) {
						os_strdup(children[j]->content, ms_graph->auth_config.tenant_id);
					}
					else {
						merror(XML_INVALID, XML_TENANT_ID, WM_MS_GRAPH_CONTEXT.name);
						return OS_CFGERR;
					}
				}
				else if (!strcmp(children[j]->element, XML_SECRET_VALUE)) {
					if (sizeof(children[j]->content) == 35) {
						os_strdup(children[j]->content, ms_graph->auth_config.secret_value);
					}
					else {
						merror(XML_INVALID, XML_SECRET_VALUE, WM_MS_GRAPH_CONTEXT.name);
						return OS_CFGERR;
					}
				}
				else {
					OS_ClearNode(children);
					merror(XML_INVATTR, children[i]->element, WM_MS_GRAPH_CONTEXT.name);
					return OS_CFGERR;
				}
			}
			OS_ClearNode(children);
		}
		else if (!strcmp(nodes[i]->element, XML_RESOURCE)) {
			if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
				OS_ClearNode(children);
				merror(XML_INVALID, XML_API_AUTH, WM_MS_GRAPH_CONTEXT.name);
				return OS_CFGERR;
			}
			for (int j = 0; children[j]; j++) {
				if (!strcmp(children[j]->element, XML_RESOURCE_NAME)) {
					if(sizeof(children[j]->content) > 0){
						os_strdup(children[j]->content, ms_graph->resources[ms_graph->num_resources++].name);
						// Check if power of 2
						if (ms_graph->num_resources > 1 && !(ms_graph->num_resources & (ms_graph->num_resources - 1))) {
							os_realloc(ms_graph->resources, ms_graph->num_resources * 2, ms_graph->resources);
						}
					}
					else{
						merror(XML_INVALID, XML_RESOURCE_NAME, WM_MS_GRAPH_CONTEXT.name);
						return OS_CFGERR;
					}
				}
				if(!strcmp(children[j]->element, XML_RESOURCE_RELATIONSHIP)) {
					if(sizeof(children[j]->content) > 0){
						os_strdup(children[j]->content, ms_graph->resources[ms_graph->num_resources - 1].relationships[ms_graph->resources->num_relationships++]);
						// Check if power of 2
						if (ms_graph->resources->num_relationships > 1 && !(ms_graph->resources->num_relationships & (ms_graph->resources->num_relationships - 1))) {
							os_realloc(ms_graph->resources->relationships, ms_graph->resources->num_relationships * 2, ms_graph->resources->relationships);
						}
					}
					else{
						merror(XML_INVALID, XML_RESOURCE_NAME, WM_MS_GRAPH_CONTEXT.name);
						return OS_CFGERR;
					}
				}
				else {
					OS_ClearNode(children);
					merror(XML_INVATTR, children[i]->element, WM_MS_GRAPH_CONTEXT.name);
					return OS_CFGERR;
				}
			}
			OS_ClearNode(children);
		}
		else {
			merror(XML_INVATTR, nodes[i]->element, WM_MS_GRAPH_CONTEXT.name);
			return OS_CFGERR;
		}
	}

    if (sched_scan_read(&(ms_graph->scan_config), nodes, module->context->name) != 0) {
        return OS_INVALID;
    }

	return OS_SUCCESS;
}

#endif // WIN32 || defined __linux__ || defined __MACH__
