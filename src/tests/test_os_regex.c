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

START_TEST(test_success_wordmatch)
{
    int i;

    /*
     * Please note that all strings are \ escaped
     */
    char *tests[][2] = {
            { "test", "this is a test" },
            { "test", "thistestiswithoutspaces" },
            { "test|not", "test" },
            { "test|not", "not" },
            { "^test", "test on start" },
            {NULL,NULL},
       };

    for(i=0; tests[i][0] != NULL ; i++) {
        ck_assert_msg(OS_WordMatch(tests[i][0],tests[i][1]),
        "%s should match positive with %s by OS_WordMatch",
        tests[i][0], tests[i][1]);
    }

}
END_TEST

START_TEST(test_fail_wordmatch)
{
    int i;

    /*
     * Please note that all strings are \ escaped
     */
    char *tests[][2] = {
            { "-test", "this is a test" },
            { "", "test" },
            { "test|not", "negative" },
            { "test", "" },
            { "^test", "starttest" },
            {NULL,NULL},
       };

    for(i=0; tests[i][0] != NULL ; i++) {
        ck_assert_msg(!OS_WordMatch(tests[i][0],tests[i][1]),
        "%s should not match positive with %s by OS_WordMatch",
        tests[i][0], tests[i][1]);
    }

}
END_TEST

START_TEST(test_success_strisnum)
{
    int i;

    /*
     * Please note that all strings are \ escaped
     */
    char *tests[] = {
            "1",
            "0123",
            NULL,
       };

    for(i=0; tests[i] != NULL ; i++) {
        ck_assert_msg(OS_StrIsNum(tests[i]),
        "%s should match positive by OS_StrIsNum",
        tests[i]);
    }

}
END_TEST

START_TEST(test_fail_strisnum)
{
    int i;

    /*
     * Please note that all strings are \ escaped
     */
    char *tests[] = {
            "test",
            "1234e",
            NULL,
       };

    for(i=0; tests[i] != NULL ; i++) {
        ck_assert_msg(!OS_StrIsNum(tests[i]),
        "%s should not match positive by OS_StrIsNum",
        tests[i]);
    }

}
END_TEST

START_TEST(test_strhowclosedmatch)
{
    int i;

    /*
     * Please note that all strings are \ escaped
     */
    char *tests[][3] = {
            { "test", "test1234", "4" },
            { "test1234", "test", "4" },
            { "test", "test", "4" },
            { "test", "", "0" },
            { "", "test", "0" },
            {NULL,NULL,NULL},
       };

    for(i=0; tests[i][0] != NULL ; i++) {
        ck_assert_int_eq(OS_StrHowClosedMatch(tests[i][0],tests[i][1])
                , atoi(tests[i][2]));
    }

}
END_TEST

START_TEST(test_strbreak)
{
    int i;

    /*
     * Please note that all strings are \ escaped
     */
    char *tests[][15] = {
            { "X", "testX1234", "4", "test", "1234", NULL},
            { "X", "XtestX1234X", "4", "", "test", "1234", "", NULL},
            { "Y", "testX1234", "4", "testX1234", NULL},
            { "X", "testXX1234", "4", "test", "", "1234", NULL},
            { "X", "testX1234", "1", "testX1234", NULL},
            { "X", "testX1234X5678", "2", "test", "1234X5678", NULL},
            { "X", "testX1234", "0", NULL},
            {NULL},
       };

    for(i=0; tests[i][0] != NULL; i++) {
        char **result = OS_StrBreak(tests[i][0][0], tests[i][1], atoi(tests[i][2]));

        int j = 3;
        if(tests[i][j] == NULL)
        {
            ck_assert_ptr_eq(result, NULL);
            continue;
        }

        int k;
        for(k = 0; tests[i][j] != NULL; j++, k++)
        {
            ck_assert_ptr_ne(result[k], NULL);
            ck_assert_str_eq(result[k], tests[i][j]);
        }
        ck_assert_ptr_eq(result[k], NULL);

        k=0;
        while(result[k])
            free(result[k++]);
        free(result);
    }

}
END_TEST

START_TEST(test_regexextraction)
{

    int i;
    /*
     * Please note that all strings are \ escaped
     */
    char *tests[][15] = {
        { "123(\\w+\\s+)abc", "123sdf    abc", "sdf    ", NULL},
        { "123(\\w+\\s+)abc", "abc123sdf    abc", "sdf    ", NULL},
        { "123 (\\d+.\\d.\\d.\\d\\d*\\d*)", "123 45.6.5.567", "45.6.5.567", NULL},
        { "from (\\S*\\d+.\\d+.\\d+.\\d\\d*\\d*)", "sshd[21576]: Illegal user web14 from ::ffff:212.227.60.55", "::ffff:212.227.60.55", NULL},
        { "^sshd[\\d+]: Accepted \\S+ for (\\S+) from (\\S+) port ", "sshd[21405]: Accepted password for root from 192.1.1.1 port 6023", "root", "192.1.1.1", NULL},
        { ": \\((\\S+)@(\\S+)\\) [", "pure-ftpd: (?@enigma.lab.ossec.net) [INFO] New connection from enigma.lab.ossec.net", "?", "enigma.lab.ossec.net", NULL},
        {NULL,NULL,NULL}
    };

    for(i=0; tests[i][0] != NULL; i++) {
        OSRegex reg;
        ck_assert_int_eq(OSRegex_Compile(tests[i][0], &reg, OS_RETURN_SUBSTRING), 1);
        ck_assert_ptr_ne(OSRegex_Execute(tests[i][1], &reg), NULL);



        char **result = reg.sub_strings;

        int j;
        int k;
        for(j = 2, k = 0; tests[i][j] != NULL; j++, k++)
        {
            ck_assert_ptr_ne(result[k], NULL);
            ck_assert_str_eq(result[k], tests[i][j]);
        }
        ck_assert_ptr_eq(result[k], NULL);

        OSRegex_FreePattern(&reg);
    }
}
END_TEST

START_TEST(test_hostnamemap)
{
    unsigned char test = 0;

    while(1)
    {
        if((test >= 48 && test <= 57) // 0-9
                || (test >= 65 && test <= 90) // A-Z
                || (test >= 97 && test <= 122) // a-z
                || test == '(' || test == ')' || test == '-'
                || test == '.' || test == '@' || test == '/'
                || test == '_')
        {
            ck_assert_msg(isValidChar(test) == 1, "char %d should be a valid hostname char", test);
        }
        else
        {
            ck_assert_msg(isValidChar(test) != 1, "char %d should not be a valid hostname char", test);
        }



        if(test == 255)
        {
            break;
        }
        test++;
    }

}
END_TEST

Suite *test_suite(void)
{
    Suite *s = suite_create("os_regex");

    /* Core test case */
    TCase *tc_match = tcase_create("Match");
    TCase *tc_regex = tcase_create("Regex");
    TCase *tc_wordmatch = tcase_create("WordMatch");
    TCase *tc_strisnum = tcase_create("StrIsNum");
    TCase *tc_strhowclosedmatch = tcase_create("StrHowClosedMatch");
    TCase *tc_strbreak = tcase_create("StrBreak");
    TCase *tc_regexextraction = tcase_create("RegexExtraction");
    TCase *tc_hostnamemap = tcase_create("HostnameMap");

    tcase_add_test(tc_match, test_success_match1);
    tcase_add_test(tc_match, test_fail_match1);

    tcase_add_test(tc_regex, test_success_regex1);
    tcase_add_test(tc_regex, test_fail_regex1);

    tcase_add_test(tc_wordmatch, test_success_wordmatch);
    tcase_add_test(tc_wordmatch, test_fail_wordmatch);

    tcase_add_test(tc_strisnum, test_success_strisnum);
    tcase_add_test(tc_strisnum, test_fail_strisnum);

    tcase_add_test(tc_strhowclosedmatch, test_strhowclosedmatch);

    tcase_add_test(tc_strbreak, test_strbreak);

    //tcase_add_test(tc_regexextraction, test_regexextraction);

    tcase_add_test(tc_hostnamemap, test_hostnamemap);

    suite_add_tcase(s, tc_match);
    suite_add_tcase(s, tc_regex);
    suite_add_tcase(s, tc_wordmatch);
    suite_add_tcase(s, tc_strisnum);
    suite_add_tcase(s, tc_strhowclosedmatch);
    suite_add_tcase(s, tc_strbreak);
    suite_add_tcase(s, tc_regexextraction);
    suite_add_tcase(s, tc_hostnamemap);

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
