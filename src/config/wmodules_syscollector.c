/*
 * Wazuh Syscollector Module Configuration
 * Copyright (C) 2015-2020, Wazuh Inc.
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
static const char *XML_ENABLED = "enabled";
static const char *XML_NETWORK = "network";
static const char *XML_OS_SCAN = "os";
static const char *XML_HARDWARE = "hardware";
static const char *XML_PACKAGES = "packages";
static const char *XML_PORTS = "ports";
static const char *XML_PROCS = "processes";
static const char *XML_HOTFIXES = "hotfixes";

unsigned int get_interval(char *value);

// Parse XML configuration
int wm_sys_read(XML_NODE node, wmodule *module) {
    wm_sys_t *syscollector;
    int i;

    if(!module->data) {
        os_calloc(1, sizeof(wm_sys_t), syscollector);
        syscollector->flags.enabled = 1;
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
            if (syscollector->default_interval = get_interval(node[i]->content), !syscollector->default_interval) {
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
        } else if (!strcmp(node[i]->element, XML_ENABLED)) {
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.enabled = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.enabled = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_DISABLED)) {
            mwarn("'%s' option at module syscollector is deprecated. Use '%s' instead.", node[i]->element, XML_ENABLED);
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.enabled = 0;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_NETWORK)) {
            if (node[i]->attributes) {
                if (!strcmp(node[i]->attributes[0], "interval")) {
                    if (syscollector->interfaces_interval = get_interval(node[i]->values[0]), !syscollector->interfaces_interval) {
                        merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
            }
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.netinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.netinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_NETWORK, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_OS_SCAN)) {
            if (node[i]->attributes) {
                if (!strcmp(node[i]->attributes[0], "interval")) {
                    if (syscollector->os_interval = get_interval(node[i]->values[0]), !syscollector->os_interval) {
                        merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
            }
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.osinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.osinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_OS_SCAN, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_HARDWARE)) {
            if (node[i]->attributes) {
                if (!strcmp(node[i]->attributes[0], "interval")) {
                    if (syscollector->hw_interval = get_interval(node[i]->values[0]), !syscollector->hw_interval) {
                        merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
            }
            if (!strcmp(node[i]->content, "yes"))
                syscollector->flags.hwinfo = 1;
            else if (!strcmp(node[i]->content, "no"))
                syscollector->flags.hwinfo = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_HARDWARE, WM_SYS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, XML_PACKAGES)) {
            if (node[i]->attributes) {
                if (!strcmp(node[i]->attributes[0], "interval")) {
                    if (syscollector->programs_interval = get_interval(node[i]->values[0]), !syscollector->programs_interval) {
                        merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
            }
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
                if (node[i]->attributes) {
                    if (!strcmp(node[i]->attributes[0], "interval")) {
                        if (syscollector->hotfixes_interval = get_interval(node[i]->values[0]), !syscollector->hotfixes_interval) {
                            merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                            return OS_INVALID;
                        }
                    } else {
                        merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
                }
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
            if (node[i]->attributes) {
                if (!strcmp(node[i]->attributes[0], "interval")) {
                    if (syscollector->processes_interval = get_interval(node[i]->values[0]), !syscollector->processes_interval) {
                        merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
                } else {
                    merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                    return OS_INVALID;
                }
            }
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
                int j;
                for (j=0; node[i]->attributes[j]; ++j) {
                    if (!strcmp(node[i]->attributes[j], "all")) {
                        if (!strcmp(node[i]->values[j], "no")) {
                            syscollector->flags.allports = 0;
                        } else if (!strcmp(node[i]->values[j], "yes")) {
                            syscollector->flags.allports = 1;
                        } else {
                            merror("Invalid content for attribute '%s' at module '%s'.", node[i]->attributes[0], WM_SYS_CONTEXT.name);
                            return OS_INVALID;
                        }
                    }
                    else if (!strcmp(node[i]->attributes[j], "interval")) {
                        if (syscollector->ports_interval = get_interval(node[i]->values[j]), !syscollector->ports_interval) {
                            merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
                            return OS_INVALID;
                        }
                    }
                    else {
                        merror("Invalid attribute for tag '%s' at module '%s'.", XML_PORTS, WM_SYS_CONTEXT.name);
                        return OS_INVALID;
                    }
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
        } else {
            merror("No such tag '%s' at module '%s'.", node[i]->element, WM_SYS_CONTEXT.name);
            return OS_INVALID;
        }
    }

    return 0;
}

unsigned int get_interval(char *value) {
    char *endptr;
    unsigned int interval = strtoul(value, &endptr, 0);

    if (interval == 0 || interval == UINT_MAX) {
        merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
        return 0;
    }

    switch (*endptr) {
    case 'd':
        interval *= 86400;
        break;
    case 'h':
        interval *= 3600;
        break;
    case 'm':
        interval *= 60;
        break;
    case 's':
    case '\0':
        break;
    default:
        merror("Invalid interval at module '%s'", WM_SYS_CONTEXT.name);
        return 0;
    }
    return interval;
}
#endif
