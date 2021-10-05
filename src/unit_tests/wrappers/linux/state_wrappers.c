/* Copyright (C) 2015-2021, Wazuh Inc.
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

#include "state_wrappers.h"


void __wrap_rem_inc_tcp() {
    function_called();
}

void __wrap_rem_dec_tcp() {
    function_called();
}

