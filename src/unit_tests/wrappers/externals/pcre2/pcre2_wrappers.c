/* Copyright (C) 2015, Wazuh Inc.
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

static bool g_enable_pcre2 = false;

void w_test_pcre2_wrappers(bool enable)
{
    g_enable_pcre2 = !enable;
}

pcre2_match_data_8* wrap_pcre2_match_data_create_from_pattern(pcre2_code_8* code, void* aux)
{

    if (g_enable_pcre2)
    {
        // Print macro
        return pcre2_match_data_create_from_pattern(code, aux);
    }
    return mock_type(pcre2_match_data_8*);
}

int wrap_pcre2_match(pcre2_code_8* code_match_data,
                     const PCRE2_UCHAR8* str_test,
                     size_t strlen,
                     int a,
                     int b,
                     pcre2_match_data_8* match_data,
                     void* aux)
{
    if (g_enable_pcre2)
    {
        return pcre2_match(code_match_data, str_test, strlen, a, b, match_data, aux);
    }
    return mock();
}

void wrap_pcre2_match_data_free(pcre2_match_data_8* match_data)
{
    if (g_enable_pcre2)
    {
        pcre2_match_data_free(match_data);
    }
    return;
}

size_t* wrap_pcre2_get_ovector_pointer(pcre2_match_data_8* match_data)
{
    if (g_enable_pcre2)
    {
        return pcre2_get_ovector_pointer(match_data);
    }
    return mock_type(size_t*);
}
