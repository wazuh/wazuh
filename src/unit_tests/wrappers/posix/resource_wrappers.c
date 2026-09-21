/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "resource_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#ifndef WIN32
int __wrap_getrlimit(int resource, struct rlimit *rlim) {
    check_expected(resource);

    const struct rlimit *mock_limit = mock_type(const struct rlimit *);
    if (mock_limit != NULL) {
        *rlim = *mock_limit;
    }

    return mock_type(int);
}

int __wrap_setrlimit(int resource, const struct rlimit *rlim) {
    const rlim_t rlim_cur = rlim->rlim_cur;
    const rlim_t rlim_max = rlim->rlim_max;

    check_expected(resource);
    check_expected(rlim_cur);
    check_expected(rlim_max);

    return mock_type(int);
}
#endif
