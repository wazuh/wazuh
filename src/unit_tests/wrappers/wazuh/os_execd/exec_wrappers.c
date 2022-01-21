/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "exec_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"

int __wrap_ReadExecConfig() {
    return mock();
}

char *__wrap_GetCommandbyName(const char *name, int *timeout) {
    check_expected(name);

    *timeout = mock();

    return mock_type(char *);
}
