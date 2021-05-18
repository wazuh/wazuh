/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/
#if defined (WIN32) || (__linux__) || defined (__MACH__)

#include "wazuh_modules/wmodules.h"

static const char *XML_ENABLED = "enabled";

// Parse XML
int wm_office365_read(__attribute__((unused)) const OS_XML *xml, xml_node **nodes, wmodule *module) {

    int i = 0;

    wm_office365* wm_office365_config = NULL;

    if (!module->data) {
        // Default initialization
        module->context = &WM_OFFICE365_CONTEXT;
        module->tag = strdup(module->context->name);
        os_calloc(1, sizeof(wm_office365), wm_office365_config);
        wm_office365_config->enabled = WM_OFFICE365_DEFAULT_ENABLED;
        module->data = wm_office365_config;
    } else {
        wm_office365_config = module->data;
    }

    if (!nodes) {
        return OS_INVALID;
    }

    for (i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                wm_office365_config->enabled = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                wm_office365_config->enabled = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_OFFICE365_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_OFFICE365_CONTEXT.name);
            return OS_INVALID;
        }
    }

    return OS_SUCCESS;
}
#endif
