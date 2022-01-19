/*
 * Wazuh Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * April 27, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_CONTENT = "content";
static const char *XML_CONTENT_TYPE = "type";
static const char *XML_XCCDF = "xccdf";
static const char *XML_OVAL = "oval";
static const char *XML_PATH = "path";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_SCAN_ON_START = "scan-on-start";
static const char *XML_PROFILE = "profile";
static const char *XML_XCCDF_ID = "xccdf-id";
static const char *XML_DS_ID = "datastream-id";
static const char *XML_CPE = "cpe";
static const char *XML_OVAL_ID = "oval-id";
static const char *XML_DISABLED = "disabled";

// Parse XML

int wm_oscap_read(const OS_XML *xml, xml_node **nodes, wmodule *module)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_oscap *oscap;
    wm_oscap_eval *cur_eval = NULL;
    wm_oscap_profile *cur_profile;

    // Create module

    os_calloc(1, sizeof(wm_oscap), oscap);
    oscap->flags.enabled = 1;
    oscap->flags.scan_on_start = 1;
    sched_scan_init(&(oscap->scan_config));
    oscap->scan_config.interval = WM_DEF_INTERVAL;
    module->context = &WM_OSCAP_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = oscap;

    if (!nodes)
        return 0;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            oscap->timeout = atol(nodes[i]->content);

            if (oscap->timeout <= 0 || oscap->timeout >= UINT_MAX) {
                merror("Invalid timeout at module '%s'", WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CONTENT)) {

            // Create policy node

            if (cur_eval) {
                os_calloc(1, sizeof(wm_oscap_eval), cur_eval->next);
                cur_eval = cur_eval->next;
            } else {
                // First policy
                os_calloc(1, sizeof(wm_oscap_eval), cur_eval);
                oscap->evals = cur_eval;
            }

            // Parse policy attributes

            for (j = 0; nodes[i]->attributes && nodes[i]->attributes[j]; j++) {
                if (!strcmp(nodes[i]->attributes[j], XML_PATH))
                    cur_eval->path = strdup(nodes[i]->values[j]);
                else if (!strcmp(nodes[i]->attributes[j], XML_CONTENT_TYPE)) {
                    if (!strcmp(nodes[i]->values[j], XML_XCCDF))
                        cur_eval->type = WM_OSCAP_XCCDF;
                    else if (!strcmp(nodes[i]->values[j], XML_OVAL))
                        cur_eval->type = WM_OSCAP_OVAL;
                    else {
                        merror("Invalid content for attribute '%s' at module '%s'.", XML_CONTENT_TYPE, WM_OSCAP_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute '%s' at module '%s'.", nodes[i]->attributes[0], WM_OSCAP_CONTEXT.name);
                    return OS_INVALID;
                }
            }

            if (!cur_eval->path) {
                merror("No such attribute '%s' at module '%s'.", XML_PATH, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

            if (!cur_eval->type) {
                merror("No such attribute '%s' at module '%s'.", XML_CONTENT_TYPE, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

            // Expand policy children (optional)

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            cur_profile = NULL;

            for (j = 0; children[j]; j++) {
                if (!children[j]->element) {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                if (!strcmp(children[j]->element, XML_PROFILE)) {
                    if (cur_eval->type != WM_OSCAP_XCCDF) {
                        merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    if (cur_profile) {
                        os_calloc(1, sizeof(wm_oscap_profile), cur_profile->next);
                        cur_profile = cur_profile->next;
                    } else {
                        // First profile
                        os_calloc(1, sizeof(wm_oscap_profile), cur_profile);
                        cur_eval->profiles = cur_profile;
                    }

                    cur_profile->name = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_TIMEOUT)) {
                    cur_eval->timeout = atol(children[j]->content);

                    if (cur_eval->timeout <= 0 || cur_eval->timeout >= UINT_MAX) {
                        merror("Invalid timeout at module '%s'", WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_XCCDF_ID)) {
                    if (cur_eval->type != WM_OSCAP_XCCDF) {
                        merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    free(cur_eval->xccdf_id);

                    if (!strlen(children[j]->content)) {
                        merror("Invalid content for tag '%s' at module '%s'.", XML_XCCDF_ID, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->xccdf_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_OVAL_ID)) {
                    if (cur_eval->type != WM_OSCAP_OVAL) {
                        merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    free(cur_eval->oval_id);

                    if (!strlen(children[j]->content)) {
                        merror("Invalid content for tag '%s' at module '%s'.", XML_XCCDF_ID, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->oval_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_DS_ID)) {
                    free(cur_eval->ds_id);

                    if (!strlen(children[j]->content)) {
                        merror("Invalid content for tag '%s' at module '%s'.", XML_DS_ID, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->ds_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_CPE)) {
                    if (cur_eval->type != WM_OSCAP_XCCDF) {
                        merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    free(cur_eval->cpe);

                    if (!strlen(children[j]->content)) {
                        merror("Invalid content for tag '%s' at module '%s'.", XML_CPE, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->cpe = strdup(children[j]->content);
                } else {
                    merror("No such tag '%s' at module '%s'.", children[j]->element, WM_OSCAP_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                oscap->flags.scan_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                oscap->flags.scan_on_start = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SCAN_ON_START, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                oscap->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                oscap->flags.enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (is_sched_tag(nodes[i]->element)) {
            // Do nothing
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_OSCAP_CONTEXT.name);	
            return OS_INVALID;
        }
    }

    const int sched_read = sched_scan_read(&(oscap->scan_config), nodes, module->context->name);
    if ( sched_read != 0 ) {
        return OS_INVALID;
    }

    return 0;
}
