/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "headers/defs.h"
#include "../../common.h"


char * wrap_fgets(char * __s, int __n, FILE * __stream) {
    if (test_mode) {
        char *buffer = mock_type(char*);
        check_expected(__stream);

        if (buffer) {
            strncpy(__s, buffer, __n);
            return __s;
        }

        return 0;
    }
    else {
        return fgets(__s, __n, __stream);
    }
}


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
