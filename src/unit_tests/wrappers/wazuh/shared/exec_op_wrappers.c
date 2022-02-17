/* Copyright (C) 2015, Wazuh Inc.
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

int __wrap_wpclose(__attribute__((unused)) wfd_t * wfd) {
    return mock();
}

wfd_t *__wrap_wpopenl(__attribute__((unused)) const char * path, __attribute__((unused)) int flags, ...) {
    return mock_type(wfd_t *);
}

wfd_t *__wrap_wpopenv(__attribute__((unused)) const char * path,
                      __attribute__((unused)) char * const * argv,
                      __attribute__((unused)) int flags) {
    return mock_type(wfd_t *);
}
