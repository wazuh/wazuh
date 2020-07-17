/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"

int wm_agent_upgrade_read(xml_node **nodes, wmodule *module) {
    if (!module->data) {
        // Default initialization
        module->context = &WM_AGENT_UPGRADE_CONTEXT;
        module->tag = strdup(module->context->name);
        wm_agent_upgrade* data;
        os_calloc(1, sizeof(wm_agent_upgrade), data);
        data->enabled = 1;
        module->data = data;
    }

    return 0;
}
