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
int wm_key_request_read(__attribute__((unused)) xml_node **nodes, __attribute__((unused)) wmodule *module) {
    minfo("Ignoring deprecated configuration block for old 'agent-key-polling' module: " \
         "The key-requesting feature is now part of the 'auth' daemon");
    return 0;
}
