/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "signal_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>

int __wrap_kill(pid_t pid, int sig){
    check_expected(sig);
    check_expected(pid);
    return mock();
}

pid_t __wrap_waitpid(pid_t pid, int * wstatus, int options) {
    
    return mock_type(pid_t);
}
