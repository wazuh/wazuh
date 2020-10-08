/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "headers/defs.h"
#include "../../common.h"

int wrap_fprintf (FILE *__stream, const char *__format, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;
    int ret;
    va_start(args, __format);

    if (test_mode) {
        vsnprintf(formatted_msg, OS_MAXSTR, __format, args);
        check_expected(__stream);
        check_expected(formatted_msg);
        ret = mock();
    }
    else {
        ret = vfprintf(__stream, __format, args);
    }

    va_end(args);
    return ret;
}

int wrap_snprintf (char * s, size_t n, const char *__format, ...) {
    va_list args;
    int ret;
    va_start(args, __format);

    if (test_mode) {
        vsnprintf(s, n, __format, args);
        check_expected(s);
        ret = mock();
    }
    else {
        ret = snprintf(s, n, __format, args);
    }

    va_end(args);
    return ret;
}