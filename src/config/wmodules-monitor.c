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
#include "wazuh_modules/wmodules.h"

// Parse XML configuration
int wm_sys_read(const OS_XML *xml, XML_NODE node, wmodule *module) {
    if (module) {
        module->context = &WM_SYS_CONTEXT;
        module->tag = strdup(module->context->name);
    }
    return 0;
}
#endif
