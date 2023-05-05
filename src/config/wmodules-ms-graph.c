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

	if (!nodes) {
		merror("Empty configuration found in module '%s'.", WM_MS_GRAPH_CONTEXT.name);
		return OS_CFGERR;
	}

	// Init module
	os_malloc(sizeof(wm_ms_graph), ms_graph);
	ms_graph->enabled = WM_MS_GRAPH_DEFAULT_ENABLED;
	ms_graph->only_future_events = WM_MS_GRAPH_DEFAULT_ONLY_FUTURE_EVENTS;
	ms_graph->curl_max_size = WM_MS_GRAPH_DEFAULT_CURL_MAX_SIZE;
	ms_graph->run_on_start = WM_MS_GRAPH_DEFAULT_RUN_ON_START;
	os_strdup(WM_MS_GRAPH_DEFAULT_VERSION, ms_graph->version);

	sched_scan_init(&(ms_graph->scan_config));
	ms_graph->scan_config.interval = WM_DEF_INTERVAL;

	ms_graph->auth_config.client_id = NULL;
	ms_graph->auth_config.tenant_id = NULL;
	ms_graph->auth_config.secret_value = NULL;
	ms_graph->auth_config.access_token = NULL;

	os_malloc(sizeof(wm_ms_graph_resource) * 2, ms_graph->resources);
	ms_graph->num_resources = 0;

	module->context = &WM_MS_GRAPH_CONTEXT;
	os_strdup(module->context->name, module->tag);
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
				merror(XML_VALUEERR, XML_ENABLED, nodes[i]->content);
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
				merror(XML_VALUEERR, XML_ONLY_FUTURE_EVENTS, nodes[i]->content);
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_CURL_MAX_SIZE)) {
			ms_graph->curl_max_size = w_parse_size(nodes[i]->content);
			if (ms_graph->curl_max_size < 1024L) {
				merror("Module '%s' has invalid content in tag '%s': the minimum size is 1KB.", WM_MS_GRAPH_CONTEXT.name, XML_CURL_MAX_SIZE);
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
				merror(XML_VALUEERR, XML_RUN_ON_START, nodes[i]->content);
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_VERSION)) {
			if (!strcmp(nodes[i]->content, "v1.0") || !strcmp(nodes[i]->content, "beta")) {
				os_free(ms_graph->version);
				os_strdup(nodes[i]->content, ms_graph->version);
			}
			else {
				merror(XML_VALUEERR, XML_VERSION, nodes[i]->content);
				return OS_CFGERR;
			}
		}
		else if (!strcmp(nodes[i]->element, XML_API_AUTH)) {
			if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
				OS_ClearNode(children);
				merror(XML_VALUEERR, XML_API_AUTH, nodes[i]->content);
				return OS_CFGERR;
			}
			for (int j = 0; children[j]; j++) {
				if (!strcmp(children[j]->element, XML_CLIENT_ID)) {
					if (strlen(children[j]->content) > 1 ) {
						os_strdup(children[j]->content, ms_graph->auth_config.client_id);
					}
					else {
						merror(XML_VALUEERR, XML_CLIENT_ID, children[j]->content);
						OS_ClearNode(children);
						return OS_CFGERR;
					}
				}
				else if (!strcmp(children[j]->element, XML_TENANT_ID)) {
					if (strlen(children[j]->content) > 1) {
						os_strdup(children[j]->content, ms_graph->auth_config.tenant_id);
					}
					else {
						merror(XML_VALUEERR, XML_TENANT_ID, children[j]->content);
						OS_ClearNode(children);
						return OS_CFGERR;
					}
				}
				else if (!strcmp(children[j]->element, XML_SECRET_VALUE)) {
					if (strlen(children[j]->content) > 1) {
						os_strdup(children[j]->content, ms_graph->auth_config.secret_value);
					}
					else {
						merror(XML_VALUEERR, XML_SECRET_VALUE, children[j]->content);
						OS_ClearNode(children);
						return OS_CFGERR;
					}
				}
				else {
					merror(XML_INVATTR, children[j]->element, WM_MS_GRAPH_CONTEXT.name);
					OS_ClearNode(children);
					return OS_CFGERR;
				}
			}
			OS_ClearNode(children);

			if(!ms_graph->auth_config.client_id){
				merror(XML_NO_ELEM, XML_CLIENT_ID);
				return OS_NOTFOUND; // OS_MISVALUE?
			}
			else if (!ms_graph->auth_config.tenant_id){
				merror(XML_NO_ELEM, XML_TENANT_ID);
				return OS_NOTFOUND; // OS_MISVALUE?
			}
			else if (!ms_graph->auth_config.secret_value){
				merror(XML_NO_ELEM, XML_SECRET_VALUE);
				return OS_NOTFOUND; // OS_MISVALUE?
			}

		}
		else if (!strcmp(nodes[i]->element, XML_RESOURCE)) {
			if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
				merror(XML_VALUEERR, XML_RESOURCE, nodes[i]->content);
				OS_ClearNode(children);
				return OS_CFGERR;
			}
			// Construct a new resource entry
			os_malloc(sizeof(char*) * 2, ms_graph->resources[ms_graph->num_resources].relationships);
			ms_graph->resources[ms_graph->num_resources].name = NULL;
			bool name_set = false;
			ms_graph->resources[ms_graph->num_resources++].num_relationships = 0;
			// Check if power of 2
			if (ms_graph->num_resources > 1 && !(ms_graph->num_resources & (ms_graph->num_resources - 1))) {
				os_realloc(ms_graph->resources, (ms_graph->num_resources * 2) * sizeof(wm_ms_graph_resource), ms_graph->resources);
			}

			for (int j = 0; children[j]; j++) {
				if (!strcmp(children[j]->element, XML_RESOURCE_NAME)) {
					if(strlen(children[j]->content) > 0){
						name_set = true;
						os_strdup(children[j]->content, ms_graph->resources[ms_graph->num_resources - 1].name);
					}
					else{
						merror(XML_VALUEERR, XML_RESOURCE_NAME, children[j]->content);
						OS_ClearNode(children);
						return OS_CFGERR;
					}
				}
				else if(!strcmp(children[j]->element, XML_RESOURCE_RELATIONSHIP)) {
					if(strlen(children[j]->content) > 0){
						os_strdup(children[j]->content, ms_graph->resources[ms_graph->num_resources - 1].relationships[ms_graph->resources[ms_graph->num_resources - 1].num_relationships++]);
						// Check if power of 2
						if (ms_graph->resources[ms_graph->num_resources - 1].num_relationships > 1 && !(ms_graph->resources[ms_graph->num_resources - 1].num_relationships & (ms_graph->resources[ms_graph->num_resources - 1].num_relationships - 1))) {
							os_realloc(ms_graph->resources[ms_graph->num_resources - 1].relationships, (ms_graph->resources->num_relationships * 2) * sizeof(char*), ms_graph->resources[ms_graph->num_resources - 1].relationships);
						}
					}
					else{
						merror(XML_VALUEERR, XML_RESOURCE_RELATIONSHIP, children[j]->content);
						OS_ClearNode(children);
						return OS_CFGERR;
					}
				}
				else {
					merror(XML_INVATTR, children[j]->element, WM_MS_GRAPH_CONTEXT.name);
					OS_ClearNode(children);
					return OS_CFGERR;
				}
			}
			OS_ClearNode(children);

			if(!name_set){
				// Set the value to NULL to avoid complicating destruction logic
				merror(XML_NO_ELEM, XML_RESOURCE_NAME);
				return OS_NOTFOUND; // OS_MISVALUE?
			}
			else if (ms_graph->resources[ms_graph->num_resources - 1].num_relationships == 0){
				merror(XML_NO_ELEM, XML_RESOURCE_RELATIONSHIP);
				return OS_NOTFOUND; // OS_MISVALUE?
			}
		}
		else if (!is_sched_tag(nodes[i]->element)) {
			merror(XML_INVATTR, nodes[i]->element, WM_MS_GRAPH_CONTEXT.name);
			return OS_CFGERR;
		}
	}

    if (sched_scan_read(&(ms_graph->scan_config), nodes, module->context->name) != 0) {
		merror("Unable to read scheduling configuration for module '%s'.", WM_MS_GRAPH_CONTEXT.name);
        return OS_INVALID;
    }
	
	if(!ms_graph->auth_config.client_id && !ms_graph->auth_config.tenant_id && !ms_graph->auth_config.secret_value){
		merror(XML_NO_ELEM, XML_API_AUTH);
		return OS_NOTFOUND; // OS_MISVALUE?
	}

	if(ms_graph->num_resources == 0){
		merror(XML_NO_ELEM, XML_RESOURCE);
		return OS_NOTFOUND; // OS_MISVALUE?
	}

	return OS_SUCCESS;
}

#endif // WIN32 || defined __linux__ || defined __MACH__
