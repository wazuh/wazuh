/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "cluster_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_w_is_worker(void) {
    return mock();
}

int __wrap_w_is_single_node(int* is_worker) {
    if(is_worker) {
        *is_worker = mock();
    }

    return mock();
}
