/*
 * Wazuh Module Configuration
 * Copyright (C) 2016 Wazuh Inc.
 * April 27, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_EVAL = "eval";
static const char *XML_POLICY = "policy";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_ON_START = "scan-on-start";
static const char *XML_PROFILE = "profile";
static const char *XML_SKIP_RESULT = "skip-result";
static const char *XML_SKIP_SEVERITY = "skip-severity";
static const char *XML_XCCDF_ID = "xccdf-id";
static const char *XML_DS_ID = "datastream-id";
static const char *XML_CPE = "cpe";

static int wm_oscap_parse_skip_result(const char *content, wm_oscap_flags *flags);
static int wm_oscap_parse_skip_severity(const char *content, wm_oscap_flags *flags);

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
    oscap->flags.skip_result = WM_DEF_SKIP_RESULT;
    oscap->flags.scan_on_start = 1;
    module->context = &WM_OSCAP_CONTEXT;
    module->data = oscap;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL, __local_name);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            oscap->timeout = strtoul(nodes[i]->content, NULL, 0);

            if (oscap->timeout == 0 || oscap->timeout == UINT_MAX) {
                merror("%s: ERROR: Invalid timeout at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

        } else if (!strcmp(nodes[i]->element, XML_EVAL)) {

            // Create policy node

            if (cur_eval) {
                os_calloc(1, sizeof(wm_oscap_eval), cur_eval->next);
                cur_eval = cur_eval->next;
            } else {
                // First policy
                os_calloc(1, sizeof(wm_oscap_eval), cur_eval);
                oscap->evals = cur_eval;
            }

            cur_eval->flags.skip_result = WM_DEF_SKIP_RESULT;

            // Parse policy attributes

            for (j = 0; nodes[i]->attributes[j]; j++) {
                if (!strcmp(nodes[i]->attributes[j], XML_POLICY))
                    cur_eval->policy = strdup(nodes[i]->values[j]);
                else if (!strcmp(nodes[i]->attributes[j], XML_TIMEOUT)) {
                    cur_eval->timeout = strtoul(nodes[i]->values[j], NULL, 0);

                    if (cur_eval->timeout == 0 || cur_eval->timeout == UINT_MAX) {
                        merror("%s: ERROR: Invalid timeout at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
                        return OS_INVALID;
                    }
                }
                else {
                    merror("%s: ERROR: Invalid attribute '%s' at module '%s'.", __local_name, nodes[i]->attributes[0], WM_OSCAP_CONTEXT.name);
                    return OS_INVALID;
                }
            }

            if (!cur_eval->policy) {
                merror("%s: ERROR: No such attribute '%s' at module '%s'.", __local_name, XML_POLICY, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }

            // Expand policy children (optional)

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            cur_profile = NULL;

            for (j = 0; children[j]; j++) {
                if (!children[j]->element) {
                    merror(XML_ELEMNULL, __local_name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                if (!strcmp(children[j]->element, XML_PROFILE)) {
                    if (cur_profile) {
                        os_calloc(1, sizeof(wm_oscap_profile), cur_profile->next);
                        cur_profile = cur_profile->next;

                    } else {
                        // First profile
                        os_calloc(1, sizeof(wm_oscap_profile), cur_profile);
                        cur_eval->profiles = cur_profile;
                    }

                    cur_profile->name = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_SKIP_RESULT)) {
                    cur_eval->flags.custom_result_flags = 1;

                    if (wm_oscap_parse_skip_result(children[j]->content, &cur_eval->flags) < 0) {
                        merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_RESULT, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_SKIP_SEVERITY)) {
                    cur_eval->flags.custom_severity_flags = 1;

                    if (wm_oscap_parse_skip_severity(children[j]->content, &cur_eval->flags) < 0) {
                        merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_SEVERITY, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_XCCDF_ID)) {
                    free(cur_eval->xccdf_id);

                    if (!strlen(children[j]->content)) {
                        merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_XCCDF_ID, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->xccdf_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_DS_ID)) {
                    free(cur_eval->ds_id);

                    if (!strlen(children[j]->content)) {
                        merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_DS_ID, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->ds_id = strdup(children[j]->content);
                } else if (!strcmp(children[j]->element, XML_CPE)) {
                    free(cur_eval->cpe);

                    if (!strlen(children[j]->content)) {
                        merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_CPE, WM_OSCAP_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    cur_eval->cpe = strdup(children[j]->content);
                } else {
                    merror("%s: ERROR: No such tag '%s' at module '%s'.", __local_name, children[j]->element, WM_OSCAP_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            oscap->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (oscap->interval == 0 || oscap->interval == UINT_MAX) {
                merror("%s: ERROR: Invalid interval at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
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
                merror("%s: ERROR: Invalid interval at module '%s'", __local_name, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_SKIP_RESULT)) {
            if (wm_oscap_parse_skip_result(nodes[i]->content, &oscap->flags) < 0) {
                merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_RESULT, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_SKIP_SEVERITY)) {
            if (wm_oscap_parse_skip_severity(nodes[i]->content, &oscap->flags) < 0) {
                merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SKIP_SEVERITY, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                oscap->flags.scan_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                oscap->flags.scan_on_start = 0;
            else {
                merror("%s: ERROR: Invalid content for tag '%s' at module '%s'.", __local_name, XML_SCAN_ON_START, WM_OSCAP_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            merror("%s: ERROR: No such tag '%s' at module '%s'.", __local_name, nodes[i]->element, WM_OSCAP_CONTEXT.name);
            return OS_INVALID;
        }
    }

    if (!oscap->interval)
        oscap->interval = WM_DEF_INTERVAL;

    return 0;
}

int wm_oscap_parse_skip_result(const char *content, wm_oscap_flags *flags)
{
    char *string = strdup(content);
    char *token = strtok(string, ",");

    // Reset related flags
    flags->skip_result = 0;

    while (token) {
        token = wm_strtrim(token);

        if (!strcmp(token, "pass"))
            flags->skip_result_pass = 1;
        else if (!strcmp(token, "fail"))
            flags->skip_result_fail = 1;
        else if (!strcmp(token, "notchecked"))
            flags->skip_result_notchecked = 1;
        else if (!strcmp(token, "notapplicable"))
            flags->skip_result_notapplicable = 1;
        else if (!strcmp(token, "fixed"))
            flags->skip_result_fixed = 1;
        else if (!strcmp(token, "informational"))
            flags->skip_result_informational = 1;
        else if (!strcmp(token, "error"))
            flags->skip_result_error = 1;
        else if (!strcmp(token, "unknown"))
            flags->skip_result_unknown = 1;
        else if (!strcmp(token, "notselected"))
            flags->skip_result_notselected = 1;
        else {
            free(string);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    free(string);
    return 0;
}

int wm_oscap_parse_skip_severity(const char *content, wm_oscap_flags *flags)
{
    char *string = strdup(content);
    char *token = strtok(string, ",");

    // Reset related flags
    flags->skip_severity = 0;

    while (token) {
        token = wm_strtrim(token);

        if (!strcmp(token, "low"))
            flags->skip_severity_low = 1;
        else if (!strcmp(token, "medium"))
            flags->skip_severity_medium = 1;
        else if (!strcmp(token, "high"))
            flags->skip_severity_high = 1;
        else {
            free(string);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    free(string);
    return 0;
}
