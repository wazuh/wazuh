/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2019, Wazuh Inc.
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
static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_ON_START = "scan-on-start";
static const char *XML_PROFILE = "profile";
static const char *XML_XCCDF_ID = "xccdf-id";
static const char *XML_DS_ID = "datastream-id";
static const char *XML_CPE = "cpe";
static const char *XML_OVAL_ID = "oval-id";
static const char *XML_DISABLED = "disabled";

// Parse XML

int wm_oscap_read(const OS_XML *xml, xml_node **nodes, wmodule *module, char **output)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_oscap *oscap;
    wm_oscap_eval *cur_eval = NULL;
    wm_oscap_profile *cur_profile;
    char message[OS_FLSIZE];

    // Create module

    os_calloc(1, sizeof(wm_oscap), oscap);
    oscap->flags.enabled = 1;
    oscap->flags.scan_on_start = 1;
    oscap->interval = WM_OSCAP_DEF_INTERVAL;
    module->context = &WM_OSCAP_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = oscap;

    if (!nodes)
        return 0;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            if (!output) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            oscap->timeout = atol(nodes[i]->content);

            if (oscap->timeout <= 0 || oscap->timeout >= UINT_MAX) {
                if (!output) {
                    merror("Invalid timeout at module '%s'", WM_OSCAP_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid timeout at module '%s'",
                        WM_OSCAP_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
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
                    else if (output) {
                        snprintf(message, OS_FLSIZE,
                            "Invalid content for attribute '%s' at module '%s'.",
                            XML_CONTENT_TYPE, WM_OSCAP_CONTEXT.name);
                        wm_strcat(output, message, '\n');
                        return OS_INVALID;
                    } else {
                        merror("Invalid content for attribute '%s' at module '%s'.", XML_CONTENT_TYPE, WM_OSCAP_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else if (output) {
                    snprintf(message, OS_FLSIZE,
                        "Invalid attribute '%s' at module '%s'.",
                        nodes[i]->attributes[0], WM_OSCAP_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                    return OS_INVALID;
                } else {
                    merror("Invalid attribute '%s' at module '%s'.", nodes[i]->attributes[0], WM_OSCAP_CONTEXT.name);
                    return OS_INVALID;
                }
            }

            if (!cur_eval->path) {
                if (output){
                    snprintf(message, OS_FLSIZE,
                        "No such attribute '%s' at module '%s'.",
                        XML_PATH, WM_OSCAP_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                } else {
                    merror("No such attribute '%s' at module '%s'.", XML_PATH, WM_OSCAP_CONTEXT.name);
                }
                return OS_INVALID;
            }

            if (!cur_eval->type) {
                if (output){
                    snprintf(message, OS_FLSIZE,
                        "No such attribute '%s' at module '%s'.",
                        XML_CONTENT_TYPE, WM_OSCAP_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                } else {
                    merror("No such attribute '%s' at module '%s'.", XML_CONTENT_TYPE, WM_OSCAP_CONTEXT.name);
                }
                return OS_INVALID;
            }

            // Expand policy children (optional)

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            cur_profile = NULL;

            for (j = 0; children[j]; j++) {
                if (!children[j]->element) {
                    if (output) {
                        wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
                    } else {
                        merror(XML_ELEMNULL);
                    }
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                if (!strcmp(children[j]->element, XML_PROFILE)) {
                    if (cur_eval->type != WM_OSCAP_XCCDF) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Tag '%s' on incorrect content type at module '%s'",
                                children[j]->element, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        }
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
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Invalid timeout at module '%s'",
                                WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Invalid timeout at module '%s'", WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_XCCDF_ID)) {
                    if (cur_eval->type != WM_OSCAP_XCCDF) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Tag '%s' on incorrect content type at module '%s'",
                                children[j]->element, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    free(cur_eval->xccdf_id);

                    if (!strlen(children[j]->content)) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Invalid content for tag '%s' at module '%s'.",
                                XML_XCCDF_ID, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Invalid content for tag '%s' at module '%s'.", XML_XCCDF_ID, WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->xccdf_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_OVAL_ID)) {
                    if (cur_eval->type != WM_OSCAP_OVAL) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Tag '%s' on incorrect content type at module '%s'",
                                children[j]->element, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    free(cur_eval->oval_id);

                    if (!strlen(children[j]->content)) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Invalid content for tag '%s' at module '%s'.",
                                XML_XCCDF_ID, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Invalid content for tag '%s' at module '%s'.", XML_XCCDF_ID, WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->oval_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_DS_ID)) {
                    free(cur_eval->ds_id);

                    if (!strlen(children[j]->content)) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Invalid content for tag '%s' at module '%s'.",
                                XML_DS_ID, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Invalid content for tag '%s' at module '%s'.", XML_DS_ID, WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->ds_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_CPE)) {
                    if (cur_eval->type != WM_OSCAP_XCCDF) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Tag '%s' on incorrect content type at module '%s'",
                                children[j]->element, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Tag '%s' on incorrect content type at module '%s'", children[j]->element, WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    free(cur_eval->cpe);

                    if (!strlen(children[j]->content)) {
                        if (output){
                            snprintf(message, OS_FLSIZE,
                                "Invalid content for tag '%s' at module '%s'.",
                                XML_CPE, WM_OSCAP_CONTEXT.name);
                            wm_strcat(output, message, '\n');
                        } else {
                            merror("Invalid content for tag '%s' at module '%s'.", XML_CPE, WM_OSCAP_CONTEXT.name);
                        }
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->cpe = strdup(children[j]->content);
                } else if (output) {
                    snprintf(message, OS_FLSIZE,
                        "No such tag '%s' at module '%s'.",
                        children[j]->element, WM_OSCAP_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                    OS_ClearNode(children);
                    return OS_INVALID;
                } else {
                    merror("No such tag '%s' at module '%s'.", children[j]->element, WM_OSCAP_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            oscap->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (oscap->interval <= 0 || oscap->interval >= UINT_MAX) {
                if (output) {
                    snprintf(message, OS_FLSIZE,
                        "Invalid interval at module '%s'",
                        WM_OSCAP_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                } else {
                    merror("Invalid interval at module '%s'", WM_OSCAP_CONTEXT.name);
                }
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                oscap->interval *= 86400;
                break;
            case 'h':
                oscap->interval *= 3600;
                break;
            case 'm':
                oscap->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                if (output) {
                    snprintf(message, OS_FLSIZE, "Invalid interval at module '%s'", WM_OSCAP_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                } else {
                    merror("Invalid interval at module '%s'", WM_OSCAP_CONTEXT.name);
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                oscap->flags.scan_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                oscap->flags.scan_on_start = 0;
            else if (output) {
                snprintf(message, OS_FLSIZE,
                    "Invalid content for tag '%s' at module '%s'.",
                    XML_SCAN_ON_START, WM_OSCAP_CONTEXT.name);
                wm_strcat(output, message, '\n');
                return OS_INVALID;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SCAN_ON_START, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                oscap->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                oscap->flags.enabled = 1;
            else if (output) {
                snprintf(message, OS_FLSIZE,
                    "Invalid content for tag '%s' at module '%s'.",
                    XML_DISABLED, WM_OSCAP_CONTEXT.name);
                wm_strcat(output, message, '\n');
                return OS_INVALID;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (output) {
            snprintf(message, OS_FLSIZE,
                "No such tag '%s' at module '%s'.",
                nodes[i]->element, WM_OSCAP_CONTEXT.name);
            wm_strcat(output, message, '\n');
            return OS_INVALID;
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_OSCAP_CONTEXT.name);
            return OS_INVALID;
        }
    }

    return 0;
}
