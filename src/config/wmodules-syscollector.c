/*
 * Wazuh Syscollector Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * March 9, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef ENABLE_SYSC
#include "wazuh_modules/wmodules.h"

static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_ON_START = "scan_on_start";
static const char *XML_DISABLED = "disabled";
static const char *XML_NETWORK = "network";
static const char *XML_OS_SCAN = "os";
static const char *XML_HARDWARE = "hardware";
static const char *XML_PACKAGES = "packages";
static const char *XML_PORTS = "ports";
static const char *XML_PROCS = "processes";
static const char *XML_HOTFIXES = "hotfixes";
static const char *XML_SYNC = "synchronization";

static void parse_synchronization_section(wm_sys_t * syscollector, XML_NODE node) {
    const char *XML_DB_SYNC_MAX_EPS = "max_eps";
    const int XML_DB_SYNC_MAX_EPS_SIZE = 7;
    const int MIN_SYNC_MESSAGES_THROUGHPUT = 0; // It means disabled
    const int MAX_SYNC_MESSAGES_THROUGHPUT = 1000000;
    for (int i = 0; node[i]; ++i) {
        if (strncmp(node[i]->element, XML_DB_SYNC_MAX_EPS, XML_DB_SYNC_MAX_EPS_SIZE) == 0) {
            char * end;
            const long value = strtol(node[i]->content, &end, 10);

            if (value < MIN_SYNC_MESSAGES_THROUGHPUT || value > MAX_SYNC_MESSAGES_THROUGHPUT || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscollector->sync.sync_max_eps = value;
            }
        } else {
            mwarn(XML_INVELEM, node[i]->element);
        }
    }
}

// Parse XML configuration
int wm_syscollector_read(const OS_XML *xml, XML_NODE node, wmodule *module) {
    wm_sys_t *syscollector;
    int i;

    if(!module->data) {
        os_calloc(1, sizeof(wm_sys_t), syscollector);
        // System provider config values
        syscollector->flags.enabled = 1;
        syscollector->interval = WM_SYSCOLLECTOR_DEFAULT_INTERVAL;
        syscollector->flags.scan_on_start = 1;
        syscollector->flags.netinfo = 1;
        syscollector->flags.osinfo = 1;
        syscollector->flags.hwinfo = 1;
        syscollector->flags.programinfo = 1;
#ifdef WIN32
        syscollector->flags.hotfixinfo = 1;
#endif
        syscollector->flags.portsinfo = 1;
        syscollector->flags.allports = 0;
        syscollector->flags.procinfo = 1;

        // Database synchronization config values
        syscollector->sync.sync_max_eps = 10;

        module->context = &WM_SYS_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = syscollector;
    }

    syscollector = module->data;

    if (!node)
        return 0;

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
                syscollector->interval *= W_DAY_SECONDS;
                break;
            case 'h':
                syscollector->interval *= W_HOUR_SECONDS;
                break;
            case 'm':
                syscollector->interval *= W_MINUTE_SECONDS;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }

            if (syscollector->interval < W_MINUTE_SECONDS) {
                mwarn("The scan interval value '%d seconds' is too small. Option set to 60 seconds.", syscollector->interval);
                syscollector->interval = W_MINUTE_SECONDS;
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
        } else if (!strcmp(node[i]->element, XML_PACKAGES)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.programinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.programinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_PACKAGES, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_HOTFIXES)) {
#ifdef WIN32
                if (!strcmp(node[i]->content, "yes"))
                    syscollector->flags.hotfixinfo = 1;
                else if (!strcmp(node[i]->content, "no"))
                    syscollector->flags.hotfixinfo = 0;
                else {
                    merror("Invalid content for tag '%s' at module '%s'.", XML_HOTFIXES, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
#else
                mwarn("The '%s' option is only available on Windows systems. Ignoring it.", XML_HOTFIXES);
#endif
        } else if (!strcmp(node[i]->element, XML_PROCS)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.procinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.procinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_PROCS, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_PORTS)) {
            if (node[i]->attributes) {
                if (!strcmp(node[i]->attributes[0], "all")) {
                    if (!strcmp(node[i]->values[0], "no")) {
                        syscollector->flags.allports = 0;
                    } else if (!strcmp(node[i]->values[0], "yes")) {
                        syscollector->flags.allports = 1;
                    } else {
                        merror("Invalid content for attribute '%s' at module '%s'.", node[i]->attributes[0], WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
            }
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.portsinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.portsinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_SYNC)) {
            // Synchronization section - Let's get the children node and iterate
            // the values (at the moment there is only one: max_eps)
            xml_node **children = OS_GetElementsbyNode(xml, node[i]);
            if (children) {
                parse_synchronization_section(syscollector, children);
                OS_ClearNode(children);
            }
        } else {
            merror("No such tag '%s' at module '%s'.", node[i]->element, WM_SYS_CONTEXT.name);
            return OS_INVALID;
        }
    }

    return 0;
}
#endif
