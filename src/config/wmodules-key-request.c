/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"
#include <stdio.h>

// Reading function
int wm_key_request_read(xml_node **nodes, wmodule *module) {
    (void)nodes;
    (void)module;

    mwarn("Detected deprecated configuration block for 'agent-key-polling' module. The content will be ");
    return 0;
}
