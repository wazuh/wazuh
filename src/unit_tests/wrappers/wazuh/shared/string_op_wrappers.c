/* Copyright (C) 2015-2020, Wazuh Inc.
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

int __wrap_wstr_end(char *str, const char *str_end) {
    if (str) {
        check_expected(str);
    }

    if (str_end) {
        check_expected(str_end);
    }

    return mock();
}

char *__wrap_wstr_escape_json(__attribute__ ((__unused__)) const char * string) {
    return mock_type(char *);
}

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
