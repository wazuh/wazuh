/* Copyright (C) 2015, Wazuh Inc.
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
#include "shared.h"
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

void __wrap_OSRegex_FreePattern(OSRegex *reg) {
    check_expected(reg);
    if (reg->d_sub_strings) {
        w_FreeArray(reg->d_sub_strings);
        os_free(reg->d_sub_strings);
        reg->d_sub_strings = NULL;
    }
    return;
}

extern const char *__real_OSRegex_Execute(const char *str, OSRegex *reg);
const char *__wrap_OSRegex_Execute(const char *str, OSRegex *reg) {
    if (test_mode) {
        if (str) {
            check_expected(str);
        }

        reg->d_sub_strings = NULL;
        os_calloc(16, sizeof(char), reg->d_sub_strings);

        if(!strcmp(str, "test")) {
            reg->d_sub_strings[0] = NULL;
        } else {
            //reg->d_sub_strings[0] = "https://api.com/";
            os_strdup("https://api.com/", *reg->d_sub_strings);
        }

        return mock_type(const char *);
    }

    return __real_OSRegex_Execute(str, reg);
}

int __wrap_OS_StrIsNum(const char *str) {
    int retval = mock();

    check_expected(str);

    return retval;
}

extern int __real_OSMatch_Compile(const char *pattern, OSRegex *reg, int flags);
int __wrap_OSMatch_Compile(const char *pattern, OSRegex *reg, int flags) {
    if (test_mode) {
        if (pattern) {
            check_expected(pattern);
        }

        return mock();
    }

    return __real_OSRegex_Compile(pattern, reg, flags);
}

extern int __real_OSMatch_Execute(const char *str, size_t str_len, OSMatch *reg);
int __wrap_OSMatch_Execute(const char *str, size_t str_len, OSMatch *reg) {
    if (test_mode) {
        if (str) {
            check_expected(str);
        }

        return mock();
    }

    return  __real_OSMatch_Execute(str, str_len, reg);
}

extern const char *__real_OSRegex_Execute_ex(const char *str, OSRegex *reg, regex_matching *regex_match);
const char *__wrap_OSRegex_Execute_ex(const char *str, OSRegex *reg, regex_matching *regex_match) {
    if (test_mode) {
        if (str) {
            check_expected(str);
        }

        return mock_type(const char *);
    }

    return __real_OSRegex_Execute_ex(str, reg, regex_match);
}
