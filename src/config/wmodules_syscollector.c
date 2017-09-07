/*
 * Wazuh Syscollector Module Configuration
 * Copyright (C) 2016 Wazuh Inc.
 * March 9, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_ON_START = "scan_on_start";
static const char *XML_DISABLED = "disabled";
static const char *XML_NETWORK = "network";
static const char *XML_OS_SCAN = "os";
static const char *XML_HARDWARE = "hardware";

// Parse XML configuration
int wm_sys_read(XML_NODE node, wmodule *module) {
    wm_sys_t *syscollector;
    int i;

    os_calloc(1, sizeof(wm_sys_t), syscollector);
    syscollector->flags.enabled = 1;
    syscollector->flags.scan_on_start = 1;
    syscollector->flags.netinfo = 1;
    syscollector->flags.osinfo = 1;
    syscollector->flags.hwinfo = 1;
    module->context = &WM_SYS_CONTEXT;
    module->data = syscollector;

    // Iterate over elements

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, XML_INTERVAL)) {
            char *endptr;
            syscollector->interval = strtoul(node[i]->content, &endptr, 0);

            if (syscollector->interval == 0 || syscollector->interval == UINT_MAX) {
                merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                syscollector->interval *= 86400;
                break;
            case 'h':
                syscollector->interval *= 3600;
                break;
            case 'm':
                syscollector->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_SCAN_ON_START)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.scan_on_start = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.scan_on_start = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SCAN_ON_START, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_DISABLED)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.enabled = 0;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_NETWORK)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.netinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.netinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_NETWORK, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_OS_SCAN)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.osinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.osinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_OS_SCAN, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_HARDWARE)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.hwinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.hwinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_HARDWARE, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            merror("No such tag '%s' at module '%s'.", node[i]->element, WM_SYS_CONTEXT.name);
            return OS_INVALID;
        }
    }

    return 0;
}
