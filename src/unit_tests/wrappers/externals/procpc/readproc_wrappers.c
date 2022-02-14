/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "readproc_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


void __wrap_closeproc(PROCTAB* PT) {
    check_expected(PT);
}

void __wrap_freeproc(proc_t* p) {
    check_expected(p);
}

PROCTAB* __wrap_openproc(int flags, ...) {
    check_expected(flags);
    return mock_type(PROCTAB*);
}

proc_t* __wrap_readproc(PROCTAB *restrict const PT,
                        proc_t *restrict p) {
    check_expected(PT);
    check_expected(p);

    return mock_type(proc_t*);
}
