/*
 * Wazuh Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * December, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef ENABLE_CISCAT
#include "wazuh_modules/wmodules.h"

static const char *XML_CONTENT = "content";
static const char *XML_CONTENT_TYPE = "type";
static const char *XML_XCCDF = "xccdf";
static const char *XML_OVAL = "oval";
static const char *XML_PATH = "path";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_SCAN_ON_START = "scan-on-start";
static const char *XML_PROFILE = "profile";
static const char *XML_JAVA_PATH = "java_path";
static const char *XML_CISCAT_PATH = "ciscat_path";
static const char *XML_CISCAT_BINARY = "ciscat_binary";
static const char *XML_DISABLED = "disabled";

// Parse XML

int wm_ciscat_read(const OS_XML *xml, xml_node **nodes, wmodule *module)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_ciscat *ciscat;
    wm_ciscat_eval *cur_eval = NULL;


    // Create module

    os_calloc(1, sizeof(wm_ciscat), ciscat);
    ciscat->flags.enabled = 1;
    ciscat->flags.scan_on_start = 1;
    sched_scan_init(&(ciscat->scan_config));
    ciscat->scan_config.interval = WM_DEF_INTERVAL;
    
    // Set default ciscat binary
    #ifdef WIN32
        os_strdup(WM_CISCAT_V3_BINARY_WIN, ciscat->ciscat_binary);
    #else
        os_strdup(WM_CISCAT_V3_BINARY, ciscat->ciscat_binary);
    #endif
    module->context = &WM_CISCAT_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = ciscat;

    if (!nodes)
        return 0;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            ciscat->timeout = atol(nodes[i]->content);

            if (ciscat->timeout <= 0 || ciscat->timeout >= UINT_MAX) {
                merror("Invalid timeout at module '%s'", WM_CISCAT_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CONTENT)) {

            // Create policy node

            if (cur_eval) {
                os_calloc(1, sizeof(wm_ciscat_eval), cur_eval->next);
                cur_eval = cur_eval->next;
            } else {
                // First policy
                os_calloc(1, sizeof(wm_ciscat_eval), cur_eval);
                ciscat->evals = cur_eval;
            }

            // Parse policy attributes

            for (j = 0; nodes[i]->attributes && nodes[i]->attributes[j]; j++) {
                if (!strcmp(nodes[i]->attributes[j], XML_PATH))
                    cur_eval->path = strdup(nodes[i]->values[j]);
                else if (!strcmp(nodes[i]->attributes[j], XML_CONTENT_TYPE)) {
                    if (!strcmp(nodes[i]->values[j], XML_XCCDF))
                        cur_eval->type = WM_CISCAT_XCCDF;
                    else if (!strcmp(nodes[i]->values[j], XML_OVAL))
                        cur_eval->type = WM_CISCAT_OVAL;
                    else {
                        merror("Invalid content for attribute '%s' at module '%s'.", XML_CONTENT_TYPE, WM_CISCAT_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute '%s' at module '%s'.", nodes[i]->attributes[0], WM_CISCAT_CONTEXT.name);
                    return OS_INVALID;
                }
            }

            // Set 'xccdf' type by default.

            if (!cur_eval->type) {
                cur_eval->type = WM_CISCAT_XCCDF;
            }

            // Expand policy children (optional)

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            for (j = 0; children[j]; j++) {
                if (!children[j]->element) {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                if (!strcmp(children[j]->element, XML_PROFILE)) {
                    if (cur_eval->type != WM_CISCAT_XCCDF) {
                        merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_CISCAT_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->profile = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_TIMEOUT)) {
                    cur_eval->timeout = atol(children[j]->content);

                    if (cur_eval->timeout <= 0 || cur_eval->timeout >= UINT_MAX) {
                        merror("Invalid timeout at module '%s'", WM_CISCAT_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_PATH)) {
                    if (cur_eval->path) {
                        mwarn("Duplicate path for content at module '%s'", WM_CISCAT_CONTEXT.name);
                        free(cur_eval->path);
                    }

                    cur_eval->path = strdup(children[j]->content);
                } else {
                    merror("No such tag '%s' at module '%s'.", children[j]->element, WM_CISCAT_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

            if (!cur_eval->path) {
                merror("No such content path at module '%s'.", WM_CISCAT_CONTEXT.name);
                return OS_INVALID;
            }

        } else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                ciscat->flags.scan_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                ciscat->flags.scan_on_start = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SCAN_ON_START, WM_CISCAT_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                ciscat->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                ciscat->flags.enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_CISCAT_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_JAVA_PATH)) {
            ciscat->java_path = strdup(nodes[i]->content);
        } else if (!strcmp(nodes[i]->element, XML_CISCAT_PATH)) {
            ciscat->ciscat_path = strdup(nodes[i]->content);
        } else if (!strcmp(nodes[i]->element, XML_CISCAT_BINARY)) {
            // Free the old string (having the default value) before setting a new one.
            os_free(ciscat->ciscat_binary);
            ciscat->ciscat_binary = strdup(nodes[i]->content);
            #ifdef WIN32
                if (strcmp(ciscat->ciscat_binary, WM_CISCAT_V3_BINARY_WIN) && strcmp(ciscat->ciscat_binary, WM_CISCAT_V4_BINARY_WIN)) {
                    mterror(WM_CISCAT_LOGTAG, "Unsupported CIS-CAT Binary '%s'.", ciscat->ciscat_binary);
                    return OS_INVALID;
                }
            #else
                if (strcmp(ciscat->ciscat_binary, WM_CISCAT_V3_BINARY) && strcmp(ciscat->ciscat_binary, WM_CISCAT_V4_BINARY)) {
                    mterror(WM_CISCAT_LOGTAG, "Unsupported CIS-CAT Binary '%s'.", ciscat->ciscat_binary);
                    return OS_INVALID;
                }
            #endif
        } else if (is_sched_tag(nodes[i]->element)) {
            // Do nothing
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_CISCAT_CONTEXT.name);	
            return OS_INVALID;
        }
    }

    return sched_scan_read(&(ciscat->scan_config), nodes, module->context->name);
}
#endif
