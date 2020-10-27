/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef PCRE2_WRAPPERS_H
#define PCRE2_WRAPPERS_H

#define PCRE2_CODE_UNIT_WIDTH 8

#include "../../../../external/libpcre2/include/pcre2.h"
#include "../../../../analysisd/expression.h"

#undef pcre2_match_data_create_from_pattern
#define pcre2_match_data_create_from_pattern wrap_pcre2_match_data_create_from_pattern

pcre2_match_data_8 * wrap_pcre2_match_data_create_from_pattern(pcre2_code_8 * code, void* aux);

#undef pcre2_match
#define pcre2_match wrap_pcre2_match

int pcre2_match(pcre2_code_8 * code_match_data, const PCRE2_UCHAR8 * str_test, 
                size_t strlen, int a, int b, pcre2_match_data_8 * match_data, void * aux);

#undef pcre2_match_data_free
#define pcre2_match_data_free wrap_pcre2_match_data_free

void wrap_pcre2_match_data_free(pcre2_match_data_8 * match_data);

#undef pcre2_get_ovector_pointer
#define pcre2_get_ovector_pointer wrap_pcre2_get_ovector_pointer

size_t* wrap_pcre2_get_ovector_pointer(pcre2_match_data_8 * match_data);

#endif
