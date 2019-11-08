/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include "wazuh_modules/wmodules.h"

static const char *XML_INTERVAL = "interval";
static const char *XML_ATTEMPTS = "attempts";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_DISABLED = "disabled";

// Parse XML

int wm_docker_read(xml_node **nodes, wmodule *module, char **output)
{
    int i = 0;
    wm_docker_t *docker;
    char message[OS_FLSIZE];

    // Create module

    os_calloc(1, sizeof(wm_docker_t), docker);
    docker->flags.enabled = 1;
    docker->flags.run_on_start = 1;
    docker->attempts = 5;
    docker->interval = WM_DOCKER_DEF_INTERVAL;
    module->context = &WM_DOCKER_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = docker;

    if (!nodes) {
        return 0;
    }

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){

        if (!nodes[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            docker->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (docker->interval <= 0 || docker->interval >= UINT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid interval.", WM_DOCKER_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid interval.", WM_DOCKER_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'w':
                docker->interval *= 604800;
                break;
            case 'd':
                docker->interval *= 86400;
                break;
            case 'h':
                docker->interval *= 3600;
                break;
            case 'm':
                docker->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                if (output == NULL) {
                    merror("At module '%s': Invalid interval.", WM_DOCKER_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid interval.", WM_DOCKER_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (docker->interval < 1) {
                if (output == NULL) {
                    merror("At module '%s': Interval must be a positive number.", WM_DOCKER_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Interval must be a positive number.", WM_DOCKER_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_ATTEMPTS)) {
            docker->attempts = atol(nodes[i]->content);

            if (docker->attempts <= 0 || docker->attempts >= INT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_ATTEMPTS);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_ATTEMPTS);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                docker->flags.run_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                docker->flags.run_on_start = 0;
            else {
                if (output == NULL) {
                    merror("At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_RUN_ON_START);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_RUN_ON_START);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                docker->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                docker->flags.enabled = 1;
            else {
                if (output == NULL) {
                    merror("At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_DISABLED);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_DISABLED);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else {
            if (output == NULL) {
                    merror("At module '%s': No such tag '%s'.", WM_DOCKER_CONTEXT.name, nodes[i]->element);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': No such tag '%s'.", WM_DOCKER_CONTEXT.name, nodes[i]->element);
                    wm_strcat(output, message, '\n');
                }
            return OS_INVALID;
        }
    }

    return 0;
}

#endif
