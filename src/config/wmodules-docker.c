/*
 * Wazuh Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * October, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include "wazuh_modules/wmodules.h"

static const char *XML_ATTEMPTS = "attempts";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_DISABLED = "disabled";

// Parse XML

int wm_docker_read(xml_node **nodes, wmodule *module)
{
    int i = 0;
    wm_docker_t *docker;

    // Create module

    os_calloc(1, sizeof(wm_docker_t), docker);
    docker->flags.enabled = 1;
    docker->attempts = 5;
    sched_scan_init(&(docker->scan_config));
    docker->scan_config.interval = WM_DOCKER_DEF_INTERVAL;
    module->context = &WM_DOCKER_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = docker;

    if (!nodes) {
        return 0;
    }

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){

        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_ATTEMPTS)) {
            docker->attempts = atol(nodes[i]->content);

            if (docker->attempts <= 0 || docker->attempts >= INT_MAX) {
                merror("At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_ATTEMPTS);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                docker->flags.run_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                docker->flags.run_on_start = 0;
            else {
                merror("At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_RUN_ON_START);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                docker->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                docker->flags.enabled = 1;
            else {
                merror("At module '%s': Invalid content for tag '%s'.", WM_DOCKER_CONTEXT.name, XML_DISABLED);
                return OS_INVALID;
            }
        } else if (is_sched_tag(nodes[i]->element)) {
            // Do nothing
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_DOCKER_CONTEXT.name);	
            return OS_INVALID;
        }
    }

    const int sched_read = sched_scan_read(&(docker->scan_config), nodes, module->context->name);
    if ( sched_read != 0 ) {
        return OS_INVALID;
    }

    return 0;
}

#endif
