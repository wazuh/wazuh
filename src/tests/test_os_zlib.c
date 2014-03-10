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
#include "../os_zlib/os_zlib.h"

Suite *test_suite(void);

#define TEST_STRING_1 "Hello World!"
#define TEST_STRING_2 "Test hello \n test \t test \r World\n"
#define BUFFER_LENGTH 200

START_TEST(test_success1)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);

	ck_assert_uint_ne(i1, 0);

	char buffer2[BUFFER_LENGTH];
	unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, i1, BUFFER_LENGTH);

	ck_assert_uint_ne(i2, 0);
	ck_assert_str_eq(buffer2, TEST_STRING_1);
}
END_TEST

START_TEST(test_success2)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(TEST_STRING_2, buffer, strlen(TEST_STRING_2), BUFFER_LENGTH);

	ck_assert_uint_ne(i1, 0);

	char buffer2[BUFFER_LENGTH];
	unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, i1, BUFFER_LENGTH);

	ck_assert_uint_ne(i2, 0);
	ck_assert_str_eq(buffer2, TEST_STRING_2);
}
END_TEST

START_TEST(test_failcompress1)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(NULL, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
	ck_assert_uint_eq(i1, 0);
}
END_TEST

START_TEST(test_failcompress2)
{
	unsigned long int i1 = os_zlib_compress(TEST_STRING_1, NULL, strlen(TEST_STRING_1), BUFFER_LENGTH);
	ck_assert_uint_eq(i1, 0);
}
END_TEST

START_TEST(test_failcompress3)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), 0);
	ck_assert_uint_eq(i1, 0);
}
END_TEST

START_TEST(test_failuncompress1)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
	ck_assert_uint_ne(i1, 0);

	char buffer2[BUFFER_LENGTH];
	unsigned long int i2 = os_zlib_uncompress(NULL, buffer2, i1, BUFFER_LENGTH);
	ck_assert_uint_eq(i2, 0);
}
END_TEST

START_TEST(test_failuncompress2)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
	ck_assert_uint_ne(i1, 0);

	unsigned long int i2 = os_zlib_uncompress(buffer, NULL, i1, BUFFER_LENGTH);
	ck_assert_uint_eq(i2, 0);
}
END_TEST

START_TEST(test_failuncompress3)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
	ck_assert_uint_ne(i1, 0);

	char buffer2[BUFFER_LENGTH];
	unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, 0, BUFFER_LENGTH);
	ck_assert_uint_eq(i2, 0);
}
END_TEST

START_TEST(test_failuncompress4)
{
	char buffer[BUFFER_LENGTH];
	unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
	ck_assert_uint_ne(i1, 0);

	char buffer2[BUFFER_LENGTH];
	unsigned long int i2 = os_zlib_uncompress(buffer, buffer2, i1, 0);
	ck_assert_uint_eq(i2, 0);
}
END_TEST


Suite *test_suite(void)
{
	Suite *s = suite_create("os_zlib");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_success1);
	tcase_add_test(tc_core, test_success2);
	tcase_add_test(tc_core, test_failcompress1);
	tcase_add_test(tc_core, test_failcompress2);
	tcase_add_test(tc_core, test_failcompress3);
	tcase_add_test(tc_core, test_failuncompress1);
	tcase_add_test(tc_core, test_failuncompress2);
	tcase_add_test(tc_core, test_failuncompress3);
	tcase_add_test(tc_core, test_failuncompress4);
	suite_add_tcase(s, tc_core);

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
