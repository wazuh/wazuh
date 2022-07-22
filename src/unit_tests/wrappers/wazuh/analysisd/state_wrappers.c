/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "state_wrappers.h"

cJSON* __wrap_asys_create_state_json() {
    return mock_type(cJSON *);
}

cJSON* __wrap_asys_create_agents_state_json(int *agents_ids) {
    check_expected(agents_ids);
    return mock_type(cJSON *);
}
