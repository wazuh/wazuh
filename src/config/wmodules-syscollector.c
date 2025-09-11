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
static const char *XML_MAX_EPS = "max_eps";
static const char *XML_NOTIFY_FIRST_SCAN = "notify_first_scan";
static const char *XML_NETWORK = "network";
static const char *XML_OS_SCAN = "os";
static const char *XML_HARDWARE = "hardware";
static const char *XML_PACKAGES = "packages";
static const char *XML_PORTS = "ports";
static const char *XML_PROCS = "processes";
static const char *XML_HOTFIXES = "hotfixes";
static const char *XML_SYNC = "synchronization";
static const char *XML_GROUPS = "groups";
static const char *XML_USERS = "users";
static const char *XML_SERVICES = "services";
static const char *XML_BROWSER_EXTENSIONS = "browser_extensions";

static void parse_synchronization_section(wm_sys_t * syscollector, XML_NODE node) {
    const char *XML_DB_SYNC_ENABLED = "enabled";
    const char *XML_DB_SYNC_INTERVAL = "interval";
    const char *XML_DB_SYNC_RESPONSE_TIMEOUT = "response_timeout";
    const char *XML_DB_SYNC_MAX_EPS = "max_eps";

    for (int i = 0; node[i]; ++i) {
        if (strcmp(node[i]->element, XML_DB_SYNC_ENABLED) == 0) {
            int r = w_parse_bool(node[i]->content);

            if (r < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscollector->sync.enable_synchronization = r;
            }
        } else if (strcmp(node[i]->element, XML_DB_SYNC_INTERVAL) == 0) {
            long t = w_parse_time(node[i]->content);

            if (t <= 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscollector->sync.sync_interval = t;
            }
        } else if (strcmp(node[i]->element, XML_DB_SYNC_RESPONSE_TIMEOUT) == 0) {
            long response_timeout = w_parse_time(node[i]->content);

            if (response_timeout < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscollector->sync.sync_response_timeout = (uint32_t) response_timeout;
            }
        } else if (strcmp(node[i]->element, XML_DB_SYNC_MAX_EPS) == 0) {
            char * end;
            const long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 1000000 || *end) {
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
        syscollector->flags.groups = 1;
        syscollector->flags.users = 1;
        syscollector->flags.services = 1;
        syscollector->flags.browser_extensions = 1;

        // Database synchronization config values
        syscollector->sync.enable_synchronization = 1;
        syscollector->sync.sync_interval = 300;
        syscollector->sync.sync_response_timeout = 30;
        syscollector->sync.sync_max_eps = 10;

        syscollector->max_eps = 50;
        syscollector->flags.notify_first_scan = 0; // Default value, no notification on first scan

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
            if (!node[i]->content || !strlen(node[i]->content)) {
                merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
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

        } else if (!strcmp(node[i]->element, XML_SCAN_ON_START)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SCAN_ON_START, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.scan_on_start = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_DISABLED)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.enabled = !strcmp(node[i]->content, "no");
        } else if (!strcmp(node[i]->element, XML_MAX_EPS)) {
            char * end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 1000000 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                syscollector->max_eps = value;
            }
        } else if(!strcmp(node[i]->element, XML_NOTIFY_FIRST_SCAN)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_NOTIFY_FIRST_SCAN, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.notify_first_scan = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_NETWORK)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_NETWORK, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.netinfo = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_OS_SCAN)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_OS_SCAN, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.osinfo = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_HARDWARE)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_HARDWARE, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.hwinfo = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_PACKAGES)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_PACKAGES, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.programinfo = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_HOTFIXES)) {
#ifdef WIN32
                if (!node[i]->content || !strlen(node[i]->content) ||
                    (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                    merror("Invalid content for tag '%s' at module '%s'.", XML_HOTFIXES, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
                syscollector->flags.hotfixinfo = !strcmp(node[i]->content, "yes");
#else
                mwarn("The '%s' option is only available on Windows systems. Ignoring it.", XML_HOTFIXES);
#endif
        } else if (!strcmp(node[i]->element, XML_PROCS)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_PROCS, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.procinfo = !strcmp(node[i]->content, "yes");
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
        } else if (!strcmp(node[i]->element, XML_GROUPS)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_GROUPS, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.groups = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_USERS)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_USERS, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_SERVICES)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.services = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.services = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SERVICES, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.users = !strcmp(node[i]->content, "yes");
        } else if (!strcmp(node[i]->element, XML_BROWSER_EXTENSIONS)) {
            if (!node[i]->content || !strlen(node[i]->content) ||
                (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no"))) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_BROWSER_EXTENSIONS, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
            syscollector->flags.browser_extensions = !strcmp(node[i]->content, "yes");

        } else if (!strcmp(node[i]->element, XML_SYNC)) {
            // Synchronization section - Let's get the children node and iterate the values
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
