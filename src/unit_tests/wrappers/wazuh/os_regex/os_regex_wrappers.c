/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_regex_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"

char **d_sub_strings = NULL;

extern int __real_OSRegex_Compile(const char *pattern, OSRegex *reg, int flags);
int __wrap_OSRegex_Compile(const char *pattern, OSRegex *reg, int flags) {
    if (test_mode) {
        if (pattern) {
            check_expected(pattern);
        }

        return mock();
    }

    return __real_OSRegex_Compile(pattern, reg, flags);
}

extern const char *__real_OSRegex_Execute(const char *str, OSRegex *reg);
const char *__wrap_OSRegex_Execute(const char *str, OSRegex *reg) {
    if (test_mode) {
        if (str) {
            check_expected(str);
        }

        reg->d_sub_strings = d_sub_strings;

        return mock_type(const char *);
    }

    return __real_OSRegex_Execute(str, reg);
}

int __wrap_OS_StrIsNum(const char *str) {
    int retval = mock();

    check_expected(str);

    return retval;
}
