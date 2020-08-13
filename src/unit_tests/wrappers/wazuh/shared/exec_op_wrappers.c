/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "exec_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


extern void write_date_storage();

int __wrap_wpclose() {
    return mock();
}

wfd_t *__wrap_wpopenl() {
    return mock_type(wfd_t *);
}

wfd_t *__wrap_wpopenv() {
    return mock_type(wfd_t *);
}
