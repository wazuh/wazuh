/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "string_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#ifdef WIN32
char *__wrap_convert_windows_string(LPCWSTR string) {
    check_expected(string);
    return mock_type(char*);
}
#endif

char *__wrap_wstr_replace(const char * string, const char * search, const char * replace) {
    check_expected(string);
    check_expected(search);
    check_expected(replace);

    return mock_type(char*);
}

void __real_wstr_split(char *str, char *delim, char *replace_delim, int occurrences, char ***splitted_str);
void __wrap_wstr_split(char *str, char *delim, char *replace_delim, int occurrences, char ***splitted_str) {
    if(mock()) {
        __real_wstr_split(str, delim, replace_delim, occurrences, splitted_str);
    }
    else {
        *splitted_str = NULL;
    }
}
