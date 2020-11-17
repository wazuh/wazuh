/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "agent_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>

int __wrap_auth_connect() {
    return mock();
}

char* __wrap_get_agent_id_from_name(__attribute__((unused)) char *agent_name) {
    return mock_type(char*);
}
