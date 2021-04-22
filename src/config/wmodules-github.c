/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wm_github.h"

int wm_github_read(xml_node **nodes, wmodule *module) {
    if (!module->data) {
        // Default initialization
        module->context = &WM_GITHUB_CONTEXT;
        module->tag = strdup(module->context->name);
        wm_github* data;
        os_calloc(1, sizeof(wm_github), data);
        data->enabled = 1;
        module->data = data;
    }

    return 0;
}
