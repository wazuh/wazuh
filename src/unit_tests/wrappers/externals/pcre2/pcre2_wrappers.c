/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "pcre2_wrappers.h"

pcre2_match_data_8 * wrap_pcre2_match_data_create_from_pattern(__attribute__((unused))pcre2_code_8 * code,
                                                               __attribute__((unused))void* aux) {
    return mock_type(pcre2_match_data_8 *);
}

int pcre2_match(__attribute__((unused))pcre2_code_8 * code_match_data,
                __attribute__((unused))const PCRE2_UCHAR8 * str_test,
                __attribute__((unused))size_t strlen,
                __attribute__((unused))int a, __attribute__((unused))int b,
                __attribute__((unused))pcre2_match_data_8 * match_data, __attribute__((unused))void * aux) {
    return mock();
}

void wrap_pcre2_match_data_free(__attribute__((unused))pcre2_match_data_8 * match_data) {
    return;
}

size_t* wrap_pcre2_get_ovector_pointer(__attribute__((unused))pcre2_match_data_8 * match_data) {
    return mock_type(size_t*);
}
