/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <shared.h>
#include <os_net/os_net.h>
#include "netcounter_wrappers.h"

void __wrap_rem_setCounter(int fd, size_t counter) {
    check_expected(fd);
    check_expected(counter);
}

size_t __wrap_rem_getCounter(int fd) {
    check_expected(fd);
    return mock();
}
