/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_github.h"

static const char *XML_ENABLED = "enabled";

int wm_github_read(const OS_XML *xml, xml_node **nodes, wmodule *module) {
    wm_github* data = NULL;
    if (!module->data) {
        // Default initialization
        module->context = &WM_GITHUB_CONTEXT;
        module->tag = strdup(module->context->name);
        wm_github* data;
        os_calloc(1, sizeof(wm_github), data);
        data->enabled = 0;
        module->data = data;
    }

    data = module->data;

    for(int i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                data->enabled = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                data->enabled = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_GITHUB_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_GITHUB_CONTEXT.name);
        }
    }

    return 0;
}
