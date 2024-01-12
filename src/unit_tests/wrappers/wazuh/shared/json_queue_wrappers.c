/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "json_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_jqueue_open(__attribute__((unused)) file_queue *queue, __attribute__((unused)) int tail) {
    return mock_type(int);
}

cJSON * __wrap_jqueue_next(__attribute__((unused)) file_queue * queue) {
    return mock_type(cJSON *);
}
