/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../headers/shared.h"
#include "../../os_crypto/aes/aes_op.h"
#include "../../wrappers/common.h"

// Tests

void test_aes_string
(void **state)
{
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];
    char buffer2[buffersize];

    memset(buffer1, 0, sizeof(buffer1));
    memset(buffer2, 0, sizeof(buffer2));

    assert_int_equal(OS_AES_Str(string, buffer1, key, strlen(string), OS_ENCRYPT), 16);
    assert_int_equal(OS_AES_Str(buffer1, buffer2, key, strlen(buffer1), OS_DECRYPT), 11);

    assert_int_equal(strncmp(buffer2, string, strlen(string)), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_aes_string),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
