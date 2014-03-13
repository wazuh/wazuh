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
        {NULL, NULL, NULL}
    };

    for(i=0; tests[i][0] != NULL ; i++) {
        ck_assert_msg(OS_Match2(tests[i][0],tests[i][1]), 
                      "%s should have OS_Match2 true with %s: Ref: %s", 
                      tests[i][0], tests[i][1], tests[i][1]);
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

    for(i=0; tests[i][0] != NULL ; i++) {
        ck_assert_msg(!OS_Match2(tests[i][0],tests[i][1]),
                      "%s should have OS_Match2 false with %s: Ref: %s",
                      tests[i][0], tests[i][1], tests[i][2]);
    }
}
END_TEST

START_TEST(test_success_regex1)
{

    int i;
    /* 
     * Please note that all strings are \ escaped 
     */
    char *tests[][3] = {
        {"\\s+123", "  123", ""},
        {"\\s*123", "123", ""},
        {"\\s123", " 123", ""},
        {"\\w+\\s+\\w+", "a 1", ""},
        {"\\w+\\d+\\w+\\s+", "ab12fb12fd12 ", ""},
        {"^\\s*\\w\\s*\\w+", "a   l a  a", ""},
        {"\\w+\\s+\\w+\\d+\\s$", "a aa11 ", ""},
        {"^su\\S*: BAD su", "su: BAD SU dcid to root on /dev/ttyp0", ""},
        {"^su\\s*: BAD su", "su: BAD SU dcid to root on /dev/ttyp0", ""},
        {"^abc\\sabc", "abc abcd", ""},
        {"^abc\\s\\s*abc", "abc abcd", ""},
        {"^\\s+\\sl", "     lala", ""},
        {"^\\s*\\sl", "     lala", ""},
        {"^\\s\\s+l", "     lala", ""},
        {"^\\s+\\s l", "     lala", ""},
        {"^\\s*\\s lal\\w$", "  lala", ""},
        {"test123test\\d+$", "test123test123", ""},
        {"^kernel: \\S+ \\.+ SRC=\\S+ DST=\\S+ \\.+ PROTO=\\w+ SPT=\\d+ DPT=\\d+ ", "kernel: IPTABLE IN=eth0 OUT= MAC=ff:ff:ff:ff:ff:ff:00:03:93:db:2e:b4:08:00 SRC=10.4.11.40 DST=255.255.255.255 LEN=180 TOS=0x00 PREC=0x00 TTL=64 ID=4753 PROTO=UDP SPT=49320 DPT=2222 LEN=160", ""},
        {"test (\\w+)la", "test abclala", ""},
        {"(\\w+) (\\w+)", "wofl wofl", ""},
        {"^\\S+ [(\\d+:\\d+:\\d+)] \\.+ (\\d+.\\d+.\\d+.\\d+)\\p*\\d* -> (\\d+.\\d+.\\d+.\\d+)\\p*", "snort: [1:469:3] ICMP PING NMAP [Classification: Attempted Information Leak] [Priority: 2]: {ICMP} 10.4.12.26 -> 10.4.10.231", ""},
        {"^\\S+ [(\\d+:\\d+:\\d+)] \\.+ (\\d+.\\d+.\\d+.\\d+)\\p*\\d* -> (\\d+.\\d+.\\d+.\\d+)\\p*", "snort: [1:408:5] ICMP Echo Reply [Classification: Misc Activity] [Priority: 3]: {ICMP} 10.4.10.231 -> 10.4.12.26", ""},
        {"^\\S+ [(\\d+:\\d+:\\d+)] \\.+ (\\d+.\\d+.\\d+.\\d+)\\p*\\d* -> (\\d+.\\d+.\\d+.\\d+)\\p*", "snort: [1:1420:11] SNMP trap tcp [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37020 -> 10.4.10.231:162", ""},
        {"^\\S+ [(\\d+:\\d+:\\d+)] \\.+ (\\d+.\\d+.\\d+.\\d+)\\p*\\d* -> (\\d+.\\d+.\\d+.\\d+)\\p*", "snort: [1:1420:11] SNMP trap tcp [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37021 -> 10.4.10.231:162", ""},
        {"^\\S+ [(\\d+:\\d+:\\d+)] \\.+ (\\d+.\\d+.\\d+.\\d+)\\p*\\d* -> (\\d+.\\d+.\\d+.\\d+)\\p*", "snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.11.94:669 -> 10.4.3.20:111", ""},
        {"^\\S+ [(\\d+:\\d+:\\d+)] \\.+ (\\d+.\\d+.\\d+.\\d+)\\p*\\d* -> (\\d+.\\d+.\\d+.\\d+)\\p*", "snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.11.94:670 -> 10.4.3.20:111", ""},
        {"^\\S+ [(\\d+:\\d+:\\d+)] \\.+ (\\d+.\\d+.\\d+.\\d+)\\p*\\d* -> (\\d+.\\d+.\\d+.\\d+)\\p*", "snort: [1:1421:11] SNMP AgentX/tcp request [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37020 -> 10.4.10.231:705", ""},
        {NULL,NULL,NULL}
    };

    for(i=0; tests[i][0] != NULL ; i++) {
        ck_assert_msg(OS_Regex(tests[i][0],tests[i][1]), 
                      "%s should have OS_Regex true with %s: Ref: %s", 
                      tests[i][0], tests[i][1], tests[i][2]);
    }
}
END_TEST

START_TEST(test_fail_regex1)
{

    int i;
    /* 
     * Please note that all strings are \ escaped 
     */
    char *tests[][3] = {
        {"\\w+\\s+\\w+\\d+\\s$", "a aa11  ", ""},
        {"^\\s+\\s     l", "     lala", ""},
        {"test123test\\d+", "test123test", ""},
        {"test123test\\d+$", "test123test", ""},
        {"(lalala", "lalala", ""},
        {"test123(\\d)", "test123a", ""},
        {"\\(test)", "test", ""},
        {"(\\w+)(\\d+)", "1 1", ""},
        {NULL,NULL,NULL}, 
    };

    for(i=0; tests[i][0] != NULL ; i++) {
        ck_assert_msg(!OS_Regex(tests[i][0],tests[i][1]), 
                      "%s should have OS_Regex false with %s: Ref: %s", 
                      tests[i][0], tests[i][1], tests[i][2]);
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

    tcase_add_test(tc_regex, test_success_regex1);
    tcase_add_test(tc_regex, test_fail_regex1);

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
