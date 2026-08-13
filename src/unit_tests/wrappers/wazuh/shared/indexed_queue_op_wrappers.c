/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "indexed_queue_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

void *__wrap_indexed_queue_pop_ex(w_indexed_queue_t *queue) {
    check_expected_ptr(queue);
    return mock_type(void *);
}
