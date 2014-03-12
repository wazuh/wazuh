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
#include "../os_regex/os_regex.h"

Suite *test_suite(void);

#define BUFFER_LENGTH 200


START_TEST(test_success_match1)
{

  int i;
  char *tests[][3] = {
    {"abc", "abcd", ""},
    {"abcd", "abcd", ""},
    {"a", "a", ""},
    {"a", "aa", ""},
    {"^a", "ab", ""},
    {"test", "testa", ""},
    {"test", "testest", ""},
    {"lalaila", "lalalalaila", ""},
    {"abc|cde", "cde", ""},
    {"^aa|ee|ii|oo|uu", "dfgdsii", ""},
    {"Abc", "abc", ""},
    {"ZBE", "zbe", ""},
    {"ABC", "ABc", ""},
    {"^A", "a", ""},
    {"a|E", "abcdef", ""},
    {"daniel", "daniel", ""},
    {"DANIeL", "daNIel", ""},
    {"^abc ", "abc ", ""},
    {"ddd|eee|fff|ggg|ggg|hhh|iii", "iii", ""},
    {"kwo|fe|fw|wfW|edW|dwDF|WdW|dw|d|^la", "la", ""},
    {"^a", "a", ""},
    {"^ab$", "ab", ""},
    {"c$", "c", ""},
    {"c$", "lalalalac", ""},
    {"^bin$|^shell$", "bin", ""},
    {"^bin$|^shell$", "shell", ""},
    {"^bin$|^shell$|^ftp$", "shell", ""},
    {"^bin$|^shell$|^ftp$", "ftp", ""},
    {NULL, NULL}
  };

  for(i=0; tests[i][0] != NULL ;i++){
    ck_assert_msg(OS_Match2(tests[i][0],tests[i][1]), "%s should have OS_Match2 true with %s: Ref: %s", tests[i][0], tests[i][1], tests[i][1]); 
  }
}
END_TEST

START_TEST(test_fail_match1)
{

  int i;
  char *tests[][3] = {
    {"abc", "abb", ""},
    {"^ab", " ab", ""},
    {"test", "tes", ""},
    {"abcd", "abc", ""},
    {"abbb", "abb", ""},
    {"abbbbbbbb", "abbbbbbb", ""},
    {"a|b|c| ", "def", ""},
    {"lala$", "lalalalalal", ""},
    {"^ab$", "abc", ""},
    {"zzzz$", "zzzzzzzzzzzz ", ""},
    {"^bin$|^shell$", "bina", ""},
    {"^bin$|^shell$", "shella", ""},
    {"^bin$|^shell$", "ashell", ""},
    {NULL, NULL, NULL}
  };

  for(i=0; tests[i][0] != NULL ;i++){
    ck_assert_msg(!OS_Match2(tests[i][0],tests[i][1]), "%s should have OS_Match2 false with %s: Ref: %s", tests[i][0], tests[i][1], tests[i][2]); 
  }
}
END_TEST


Suite *test_suite(void)
{
	Suite *s = suite_create("os_regex");

	/* Core test case */
	TCase *tc_match = tcase_create("Match");
  TCase *tc_regex = tcase_create("Regex");

	tcase_add_test(tc_match, test_success_match1);
	tcase_add_test(tc_match, test_fail_match1);

	suite_add_tcase(s, tc_match);
	suite_add_tcase(s, tc_regex);

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
