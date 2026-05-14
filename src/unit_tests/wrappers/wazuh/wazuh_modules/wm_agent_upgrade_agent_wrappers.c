/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "../../common.h"
#include "wm_agent_upgrade_agent_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_wm_agent_upgrade_start_agent_module(const wm_agent_configs* agent_config, const int enabled) {
    check_expected(agent_config);
    check_expected(enabled);
}

size_t __wrap_wm_agent_upgrade_process_command(const char *buffer, char **output) {
    check_expected(buffer);
    *output = mock_type(char*);

    return mock();
}
