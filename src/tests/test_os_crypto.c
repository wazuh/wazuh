/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <check.h>
#include <stdlib.h>

#include "../os_crypto/blowfish/bf_op.h"

Suite *test_suite(void);

START_TEST(test_blowfish)
{
    const char *key = "test_key";
    const char *string = "test string";
    const int buffersize = 1024;
    char buffer1[buffersize];
    char buffer2[buffersize];

    OS_BF_Str(string, buffer1, key, buffersize, OS_ENCRYPT);
    OS_BF_Str(buffer1, buffer2, key, buffersize, OS_DECRYPT);

    ck_assert_str_eq(buffer2, string);
}
END_TEST


Suite *test_suite(void)
{
    Suite *s = suite_create("os_crypto");

    TCase *tc_blowfish = tcase_create("blowfish");
    tcase_add_test(tc_blowfish, test_blowfish);

    suite_add_tcase(s, tc_blowfish);

    return (s);
}

int main(void)
{
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return ((number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}
