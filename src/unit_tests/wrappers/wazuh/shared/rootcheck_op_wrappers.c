/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#include "rootcheck_op_wrappers.h"

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

int __wrap_send_rootcheck_log(const char* agent_id, long int date, const char* log, char* response) {
    check_expected(agent_id);
    check_expected(date);
    check_expected(log);

    sprintf(response, "%s", mock_ptr_type(char*));

    return mock();
}
