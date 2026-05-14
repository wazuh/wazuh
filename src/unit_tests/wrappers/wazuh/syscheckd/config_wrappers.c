/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "config_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int OSHash_Add_ex_check_data = 1;

void __wrap_free_whodata_event(whodata_evt *w_evt) {
    if (OSHash_Add_ex_check_data) {
        check_expected(w_evt);
    }
}

cJSON * __wrap_getRootcheckConfig() {
    return mock_type(cJSON*);
}

cJSON * __wrap_getSyscheckConfig() {
    return mock_type(cJSON*);
}

cJSON * __wrap_getSyscheckInternalOptions() {
    return mock_type(cJSON*);
}
