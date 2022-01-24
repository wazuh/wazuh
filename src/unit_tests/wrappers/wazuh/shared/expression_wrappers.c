/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "expression_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

bool __wrap_w_expression_match(__attribute__((unused))w_expression_t * expression, __attribute__((unused))const char * str_test,
                               __attribute__((unused))const char ** end_match, regex_matching * regex_match) {
    int ret = mock();

    if(ret < 0) {
        if (ret == -3) {
            regex_match->d_size.prts_str_alloc_size = 0;
            ret = 1;
        } else {
            ret *= (-1);

            regex_match->d_size.prts_str_alloc_size = ret *sizeof(char *);
            os_calloc(1, sizeof(char *) * (ret + 1), regex_match->sub_strings);

            regex_match->sub_strings[0] = w_strndup((char*)mock(), 128);

            if (ret > 1) {
                regex_match->sub_strings[1] = w_strndup((char*)mock(), 128);
                regex_match->sub_strings[2] = NULL;
            } else {
                regex_match->sub_strings[1] = NULL;
            }
        }
    }
    return ret;
}

void __wrap_w_calloc_expression_t(__attribute__((unused))w_expression_t ** var, w_exp_type_t type) {
    check_expected(type);
    return;
}

void __wrap_w_free_expression_t(__attribute__((unused))w_expression_t ** var) {
    return;
}

bool __wrap_w_expression_compile(__attribute__((unused))w_expression_t * expression, __attribute__((unused))char * pattern,
                          __attribute__((unused))int flags) {
    return mock_type(bool);
}