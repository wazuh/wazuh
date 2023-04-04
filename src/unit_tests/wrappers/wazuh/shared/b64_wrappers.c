/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "b64_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <errno.h>

char *__wrap_encode_base64(int size, const char *src) {
    check_expected(size);
    check_expected(src);
    return mock_type(char *);
}

void expect_encode_base64(int size, const char *src, char * ret) {
    expect_value(__wrap_encode_base64, size, size);
    expect_string(__wrap_encode_base64, src, src);
    will_return(__wrap_encode_base64, strdup(ret));
}

char *__wrap_decode_base64(const char *src) {
    check_expected(src);
    return mock_type(char *);
}

void expect_decode_base64(const char *src, char * ret) {
    expect_string(__wrap_decode_base64, src, src);
    will_return(__wrap_decode_base64, strdup(ret));
}
