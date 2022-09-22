/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "shared.h"
#include "enrollment_op.h"

#include <stdio.h> 
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

int flag_fopen = 0;

int wrap_enrollment_op_gethostname(char *name, int len) {
    snprintf(name, len, "%s",mock_ptr_type(char*));
    return mock_type(int);
}

int wrap_enrollment_op_fprintf ( FILE * stream, const char * format, ... ) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, format);
    vsnprintf(formatted_msg, OS_MAXSTR, format, args);
    va_end(args);

    if(!flag_fopen)
        return fprintf(stream, formatted_msg);

    check_expected(stream);
    check_expected(formatted_msg);

    
    return 0;
}