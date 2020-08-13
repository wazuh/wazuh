/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "syscom_wrappers.h"
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

size_t __wrap_syscom_dispatch(char * command, char ** output) {
    check_expected(command);

    *output = mock_type(char*);
    return mock();
}
