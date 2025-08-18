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
#include "../../os_crypto/blowfish/bf_op.h"
#include "../../wrappers/common.h"

// Tests

void test_blowfish(void **state)
{
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];
    char buffer2[buffersize];

    assert_int_equal(OS_BF_Str(string, buffer1, key, buffersize, OS_ENCRYPT), 1);
    assert_int_equal(OS_BF_Str(buffer1, buffer2, key, buffersize, OS_DECRYPT), 1);

    assert_string_equal(buffer2, string);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_blowfish),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
