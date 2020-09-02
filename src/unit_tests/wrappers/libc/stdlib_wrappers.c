/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "stdlib_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <limits.h>
#include "../common.h"


extern int __real_atexit(void (*callback)(void));
int __wrap_atexit(void (*callback)(void)) {
    if(test_mode)
        return 0;
    else
        return __real_atexit(callback);
}

char *__wrap_realpath(const char *path, char *resolved_path) {
    check_expected(path);

    snprintf(resolved_path, PATH_MAX, "%s", mock_type(char*));

    return mock_type(char*);
}

int __wrap_system(const char *__command) {
    check_expected(__command);
    return mock();
}
