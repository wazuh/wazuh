/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "./fim_db.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "headers/defs.h"

#ifdef WIN32
int test_mode;
#endif

int wrap_fprintf(FILE * __restrict__ _File,const char * __restrict__ _Format,...) {
    int ret;
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, _Format);
    if (test_mode) {
        vsnprintf(formatted_msg, OS_MAXSTR, _Format, args);
        check_expected(formatted_msg);
    } else {
        ret = fprintf(_File, _Format, args);
    }

    va_end(args);
    if(test_mode) {
        return mock();
    }
    return ret;
}

#ifdef WIN32
VOID wrap_fim_db_Sleep (__UNUSED_PARAM(DWORD dwMilliseconds)) {
    function_called();
}
#endif
