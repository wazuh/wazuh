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

int wm_task_manager_read(xml_node **nodes, wmodule *module) {
    if (!module->data) {
        // Default initialization
        module->context = &WM_TASK_MANAGER_CONTEXT;
        module->tag = strdup(module->context->name);
        wm_task_manager* data;
        os_calloc(1, sizeof(wm_task_manager), data);
        data->enabled = 1;
        module->data = data;
    }

    return 0;
}

#endif 
#endif
