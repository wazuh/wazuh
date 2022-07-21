/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wait_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>

pid_t __wrap_waitpid(pid_t __pid, int * wstatus, int __options) {

    check_expected(__pid);
    check_expected(__options);
    *wstatus = mock_type(int);
    return mock_type(pid_t);
}
