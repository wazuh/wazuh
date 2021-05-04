/*
 * Wazuh Monitor Module Configuration
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 26, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT
#include "../headers/shared.h"
#include "../wazuh_modules/wmodules.h"
#include "../monitord/monitord.h"

// Parse XML configuration
int wm_monitor_read(__attribute__((unused)) const OS_XML *xml, __attribute__((unused)) XML_NODE node, wmodule *module) {
    if (module) {
        module->context = &WM_MONITOR_CONTEXT;
        os_strdup(module->context->name, module->tag);
        if (NULL == module->data) {
            os_calloc(1, sizeof(wm_monitor_t), module->data);
        }
    }
    return 0;
}
#endif
