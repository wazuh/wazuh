/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#ifndef CLIENT
#ifndef WIN32

#include "wazuh_modules/task_manager/wm_task_manager.h"

static const char *XML_DISABLED = "disabled";

int wm_task_manager_read(xml_node **nodes, wmodule *module) {

    unsigned int i;
    wm_task_manager* data;

    if (!module->data) {
        os_calloc(1, sizeof(wm_task_manager), data);
        data->enabled = 1;
        module->context = &WM_TASK_MANAGER_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = data;
    }

    data = module->data;

    if (!nodes) {
        return 0;
    }

    for(i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                data->enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                data->enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_TASK_MANAGER_CONTEXT.name);
        }
    }

    return 0;
}

#endif 
#endif
