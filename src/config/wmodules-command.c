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
static const char *XML_TAG = "tag";
static const char *XML_COMMAND = "command";
static const char *XML_INTERVAL = "interval";
static const char *XML_IGNORE_OUTPUT = "ignore_output";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_TIMEOUT = "timeout";

// Parse XML

int wm_command_read(xml_node **nodes, wmodule *module, int agent_cfg)
{
    int i;
    wm_command_t * command;

    if (!nodes) {
        mwarn("Tag <%s> not found at module '%s'.", XML_COMMAND, WM_COMMAND_CONTEXT.name);
        return OS_INVALID;
    }

    // Create module

    os_calloc(1, sizeof(wm_command_t), command);
    command->enabled = 1;
    command->run_on_start = 1;
    command->interval = WM_COMMAND_DEFAULT_INTERVAL;
    command->agent_cfg = agent_cfg;
    module->context = &WM_COMMAND_CONTEXT;
    module->data = command;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                command->enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                command->enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_TAG)) {
            if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s' at module '%s'.", XML_TAG, WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }

            free(command->tag);
            os_strdup(nodes[i]->content, command->tag);
        } else if (!strcmp(nodes[i]->element, XML_COMMAND)) {
            if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s' at module '%s'.", XML_COMMAND, WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }

            free(command->command);
            os_strdup(nodes[i]->content, command->command);
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            command->interval = strtoul(nodes[i]->content, &endptr, 0);

            if ((command->interval == 0 && endptr == nodes[i]->content) || command->interval == ULONG_MAX) {
                merror("Invalid interval at module '%s'", WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                command->interval *= 86400;
                break;
            case 'h':
                command->interval *= 3600;
                break;
            case 'm':
                command->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'", WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                command->run_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                command->run_on_start = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_IGNORE_OUTPUT)) {
            if (!strcmp(nodes[i]->content, "yes"))
                command->ignore_output = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                command->ignore_output = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_IGNORE_OUTPUT, WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            char *endptr;
            command->timeout = strtol(nodes[i]->content, &endptr, 0);

            if (*endptr || command->timeout < 0) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_TIMEOUT, WM_COMMAND_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_COMMAND_CONTEXT.name);
            return OS_INVALID;
        }
    }

    if (!command->tag) {
        mwarn("Option <%s> not found at module '%s'.", XML_TAG, WM_COMMAND_CONTEXT.name);
        os_strdup("", command->tag);
    }

    if (!command->command) {
        mwarn("Tag <%s> not found at module '%s'.", XML_COMMAND, WM_COMMAND_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}
