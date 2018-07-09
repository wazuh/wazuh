/*
 * Wazuh Module Configuration
 * Copyright (C) 2017 Wazuh Inc.
 * October 26, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_DISABLED = "disabled";
static const char *XML_BUCKET = "bucket";
static const char *XML_INTERVAL = "interval";
static const char *XML_ACCESS_KEY = "access_key";
static const char *XML_SECRET_KEY = "secret_key";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_REMOVE_FORM_BUCKET = "remove_from_bucket";

// Parse XML

int wm_aws_read(xml_node **nodes, wmodule *module, int agent_cfg)
{
    int i;
    wm_aws_t * config;

    if (!nodes) {
        mwarn("Tag <%s> not found at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
        return OS_INVALID;
    }

    // Create module

    os_calloc(1, sizeof(wm_aws_t), config);
    config->enabled = 1;
    config->run_on_start = 1;
    config->remove_from_bucket = 0;
    config->interval = WM_AWS_DEFAULT_INTERVAL;
    config->agent_cfg = agent_cfg;
    module->context = &WM_AWS_CONTEXT;
    module->data = config;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                config->enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                config->enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            config->interval = strtoul(nodes[i]->content, &endptr, 0);

            if ((config->interval == 0 && endptr == nodes[i]->content) || config->interval == ULONG_MAX) {
                merror("Invalid interval at module '%s'", WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                config->interval *= 86400;
                break;
            case 'h':
                config->interval *= 3600;
                break;
            case 'm':
                config->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'", WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                config->run_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                config->run_on_start = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_REMOVE_FORM_BUCKET)) {
            if (!strcmp(nodes[i]->content, "yes"))
                config->remove_from_bucket = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                config->remove_from_bucket = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_REMOVE_FORM_BUCKET, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_ACCESS_KEY)) {
            if (strlen(nodes[i]->content) != 0) {
                free(config->access_key);
                os_strdup(nodes[i]->content, config->access_key);
            }
        } else if (!strcmp(nodes[i]->element, XML_SECRET_KEY)) {
            if (strlen(nodes[i]->content) != 0) {
                free(config->secret_key);
                os_strdup(nodes[i]->content, config->secret_key);
            }
        } else if (!strcmp(nodes[i]->element, XML_BUCKET)) {
            if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s' at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }

            free(config->bucket);
            os_strdup(nodes[i]->content, config->bucket);
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_AWS_CONTEXT.name);
            return OS_INVALID;
        }
    }

    if (!config->bucket) {
        mwarn("Tag <%s> not found at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}
