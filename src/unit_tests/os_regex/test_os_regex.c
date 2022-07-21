/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "../../os_regex/os_regex.h"
#include "../../os_regex/os_regex_internal.h"
#include "../wrappers/common.h"

// Tests

void test_success_match(void **state)
{
    (void) state;

    const char *tests[][3] = {
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
        {"!test1", "test2", ""},
        {"\0", "", ""},
        {NULL, NULL, NULL}
    };

    for (int i = 0; tests[i][0] != NULL ; i++) {
        assert_int_equal(OS_Match2(tests[i][0], tests[i][1]), 1);
    }
}

void test_fail_match(void **state)
{
    (void) state;

    char large_pattern[OS_PATTERN_MAXSIZE + 2] = {[0 ... OS_PATTERN_MAXSIZE + 1] 'a' };
    large_pattern[OS_PATTERN_MAXSIZE + 1] = '\0';

    const char *tests[][3] = {
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
        {"zzzz$", "zzz", ""},
        {"^bin$|^shell$", "bina", ""},
        {"^bin$|^shell$", "shella", ""},
        {"^bin$|^shell$", "ashell", ""},
        {"!test1", "test1", ""},
        {large_pattern, "", ""},
        {NULL, "", ""},
        {NULL, NULL, NULL}
    };

    for (int i = 0; tests[i][0] != NULL || tests[i][1] != NULL ; i++) {
        assert_int_not_equal(OS_Match2(tests[i][0], tests[i][1]), 1);
    }
}

void test_success_regex(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][3] = {
        {"", "", ""},
        {"", "a", ""},
        {"abc", "abcd", ""},
        {"abcd", "abcd", ""},
        {"a", "a", ""},
        {"a", "aa", ""},
        {"^a", "ab", ""},
        {"^$", "", ""},
        {"^", "", ""},
        {"$", "", ""},
        {"\\.*", "", ""},
        {"(\\.*)", "", ""},
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
        {"^\\t 1234", "\t 1234", ""},
        {"^abc\\$d", "abc$d", ""},
        {"^abc\\|d", "abc|d", ""},
        {"^abc\\<d", "abc<d", ""},
        {"^\\\\ \\w$", "\\ a", ""},
        {"^\\D+123", "test123", ""},
        {"^\\W+abc", " \t abc", ""},
        {NULL, NULL, NULL}
    };

    for (int i = 0; tests[i][0] != NULL ; i++) {
        assert_int_equal(OS_Regex(tests[i][0], tests[i][1]), 1);
    }
}

void test_fail_regex(void **state)
{
    (void) state;

    char large_pattern[OS_PATTERN_MAXSIZE + 2] = {[0 ... OS_PATTERN_MAXSIZE + 1] 'a' };
    large_pattern[OS_PATTERN_MAXSIZE + 1] = '\0';

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][3] = {
        {"abc", "abb", ""},
        {"^ab", " ab", ""},
        {"^$", "a", ""},
        {"$", "a", ""},
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
        {"^abc\\*d", "abc*d", ""},
        {"^\\D+123", "te5st123", ""},
        {"^\\W+abc", " \t 1 abc", ""},
        {"(\\w|(\\w)", "", ""},
        {large_pattern, "", ""},
        {NULL, "", ""},
        {NULL, NULL, NULL},
    };

    for (int i = 0; tests[i][0] != NULL || tests[i][1] != NULL ; i++) {
        assert_int_not_equal(OS_Regex(tests[i][0], tests[i][1]), 1);
    }
}

void test_success_wordmatch(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][2] = {
        { "test", "this is a test" },
        { "test", "thistestiswithoutspaces" },
        { "test|not", "test" },
        { "test|not", "not" },
        { "^test", "test on start" },
        {NULL, NULL},
    };

    for (int i = 0; tests[i][0] != NULL ; i++) {
        assert_int_equal(OS_WordMatch(tests[i][0], tests[i][1]), 1);
    }
}

void test_fail_wordmatch(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][2] = {
        { "-test", "this is a test" },
        { "", "test" },
        { "test|not", "negative" },
        { "test", "" },
        { "^test", "starttest" },
        {NULL, NULL},
    };

    for (int i = 0; tests[i][0] != NULL ; i++) {
        assert_int_not_equal(OS_WordMatch(tests[i][0], tests[i][1]), 1);
    }
}

void test_success_strisnum(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[] = {
        "1",
        "0123",
        NULL,
    };

    for (int i = 0; tests[i] != NULL ; i++) {
        assert_int_equal(OS_StrIsNum(tests[i]), 1);
    }
}

void test_fail_strisnum(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[] = {
        "test",
        "1234e",
        "-1",
        "+1",
        NULL,
    };

    for (int i = 0; tests[i] != NULL ; i++) {
        assert_int_not_equal(OS_StrIsNum(tests[i]), 1);
    }
}

void test_fail_strisnum_null(void **state)
{
    (void) state;

    assert_int_not_equal(OS_StrIsNum(NULL), 1);
}

void test_success_strhowclosedmatch(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][3] = {
        { "test", "test1234", "4" },
        { "test1234", "test", "4" },
        { "test", "test", "4" },
        { "test", "", "0" },
        { "", "test", "0" },
        {NULL, NULL, NULL},
    };

    for (int i = 0; tests[i][0] != NULL ; i++) {
        assert_int_equal(OS_StrHowClosedMatch(tests[i][0], tests[i][1]), (unsigned) atoi(tests[i][2]));
    }
}

void test_fail_strhowclosedmatch_null(void **state)
{
    (void) state;

    assert_int_equal(OS_StrHowClosedMatch(NULL, NULL), 0);
}

void test_success_str_starts_with(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][2] = {
        { "test1234", "test" },
        { "test", "test" },
        { "test", "" },
        { "", "" },
        {NULL, NULL},
    };

    for (int i = 0; tests[i][0] != NULL ; i++) {
        assert_int_equal(OS_StrStartsWith(tests[i][0], tests[i][1]), 1);
    }
}

void test_fail_str_starts_with(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][2] = {
        { "test", "test1234" },
        { "", "test" },
        {NULL, NULL},
    };


    for (int i = 0; tests[i][0] != NULL ; i++) {
        assert_int_not_equal(OS_StrStartsWith(tests[i][0], tests[i][1]), 1);
    }
}

void test_strbreak(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][15] = {
        { "X", "testX1234", "4", "test", "1234", NULL},
        { "X", "XtestX1234X", "4", "", "test", "1234", "", NULL},
        { "Y", "testX1234", "4", "testX1234", NULL},
        { "X", "testXX1234", "4", "test", "", "1234", NULL},
        { "X", "testX1234", "1", "testX1234", NULL},
        { "X", "testX1234X5678", "2", "test", "1234X5678", NULL},
        { "X", "testX1234", "0", NULL},
        {NULL},
    };

    for (int i = 0; tests[i][0] != NULL; i++) {
        char **result = OS_StrBreak(tests[i][0][0], tests[i][1], (unsigned) atoi(tests[i][2]));

        int j = 3;
        if (tests[i][j] == NULL) {
            assert_null(result);
            continue;
        }

        int k;
        for (k = 0; tests[i][j] != NULL; j++, k++) {
            assert_non_null(result[k]);
            assert_string_equal(result[k], tests[i][j]);
        }
        assert_null(result[k]);

        k = 0;
        while (result[k]) {
            free(result[k++]);
        }
        free(result);
    }
}

void test_strbreak_null(void **state)
{
    (void) state;

    char **result = OS_StrBreak('X', NULL, 0);

    assert_null(result);
}

void test_regex_extraction(void **state)
{
    (void) state;

    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][15] = {
        { "123(\\w+\\s+)abc", "123sdf    abc", "sdf    ", NULL},
        { "123(\\w+\\s+)abc", "abc123sdf    abc", "sdf    ", NULL},
        { "123 (\\d+.\\d.\\d.\\d\\d*\\d*)", "123 45.6.5.567", "45.6.5.567", NULL},
        { "from (\\S*\\d+.\\d+.\\d+.\\d\\d*\\d*)", "sshd[21576]: Illegal user web14 from ::ffff:212.227.60.55", "::ffff:212.227.60.55", NULL},
        { "^sshd[\\d+]: Accepted \\S+ for (\\S+) from (\\S+) port ", "sshd[21405]: Accepted password for root from 192.1.1.1 port 6023", "root", "192.1.1.1", NULL},
        { ": \\((\\S+)@(\\S+)\\) [", "pure-ftpd: (?@enigma.lab.ossec.net) [INFO] New connection from enigma.lab.ossec.net", "?", "enigma.lab.ossec.net", NULL},
        {NULL, NULL, NULL}
    };

    for (int i = 0; tests[i][0] != NULL; i++) {
        OSRegex reg;
        assert_int_equal(OSRegex_Compile(tests[i][0], &reg, OS_RETURN_SUBSTRING), 1);
        assert_non_null((void *)OSRegex_Execute(tests[i][1], &reg));

        char **result = reg.d_sub_strings;

        int j;
        int k;
        for (j = 2, k = 0; tests[i][j] != NULL; j++, k++) {
            assert_non_null(result[k]);
            assert_string_equal(result[k], tests[i][j]);
        }
        assert_null(result[k]);

        OSRegex_FreePattern(&reg);
    }
}

void test_hostname_map(void **state)
{
    (void) state;

    unsigned char test = 0;

    while (1) {
        if ((test >= 48 && test <= 57) // 0-9
                || (test >= 65 && test <= 90) // A-Z
                || (test >= 97 && test <= 122) // a-z
                || test == '(' || test == ')' || test == '-'
                || test == '.' || test == '@' || test == '/'
                || test == '_') {
            assert_int_equal(isValidChar(test), 1);
        } else {
            assert_int_not_equal(isValidChar(test), 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_case_insensitive_char_map(void **state)
{
    (void) state;

    unsigned char test = 0;

    while (1) {
        if (test >= 65 && test <= 90) { // A-Z
            assert_int_equal(charmap[test], test+32);
        } else {
            assert_int_equal(charmap[test], test);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_digit(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test >= '0' && test <= '9') {
            assert_int_equal(regexmap[1][test], 1);
        } else {
            assert_int_not_equal(regexmap[1][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_word(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if ((test >= 'a' && test <= 'z')
                || (test >= 'A' && test <= 'Z')
                || (test >= '0' && test <= '9')
                || test == '-' || test == '@'
                || test == '_') {
            assert_int_equal(regexmap[2][test], 1);
        } else {
            assert_int_not_equal(regexmap[2][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_space(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == ' ') {
            assert_int_equal(regexmap[3][test], 1);
        } else {
            assert_int_not_equal(regexmap[3][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_punctuation(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == '<' || test == '>' || test == '!' || test == '?'
                || test == '"' || test == '\'' || test == '#'
                || test == '$' || test == '%' || test == '&'
                || test == '(' || test == ')' || test == '+'
                || test == '*' || test == ',' || test == '-'
                || test == '-' || test == ':' || test == '|'
                || test == '.' || test == ';' || test == '='
                || test == '[' || test == ']' || test == '{'
                || test == '}') {
            assert_int_equal(regexmap[4][test], 1);
        } else {
            assert_int_not_equal(regexmap[4][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_lparenthesis(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == '(') {
            assert_int_equal(regexmap[5][test], 1);
        } else {
            assert_int_not_equal(regexmap[5][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_rparenthesis(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == ')') {
            assert_int_equal(regexmap[6][test], 1);
        } else {
            assert_int_not_equal(regexmap[6][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_backslash(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == '\\') {
            assert_int_equal(regexmap[7][test], 1);
        } else {
            assert_int_not_equal(regexmap[7][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_nondigit(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (!(test >= '0' && test <= '9')) {
            assert_int_equal(regexmap[8][test], 1);
        } else {
            assert_int_not_equal(regexmap[8][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_nonword(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (!((test >= 'a' && test <= 'z')
                || (test >= 'A' && test <= 'Z')
                || (test >= '0' && test <= '9')
                || test == '-' || test == '@'
                || test == '_')) {
            assert_int_equal(regexmap[9][test], 1);
        } else {
            assert_int_not_equal(regexmap[9][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}


void test_regexmap_nonspace(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test != ' ') {
            assert_int_equal(regexmap[10][test], 1);
        } else {
            assert_int_not_equal(regexmap[10][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_all(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        assert_int_equal(regexmap[11][test], 1);

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_tab(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == '\t') {
            assert_int_equal(regexmap[12][test], 1);
        } else {
            assert_int_not_equal(regexmap[12][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_dollar(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == '$') {
            assert_int_equal(regexmap[13][test], 1);
        } else {
            assert_int_not_equal(regexmap[13][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_or(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == '|') {
            assert_int_equal(regexmap[14][test], 1);
        } else {
            assert_int_not_equal(regexmap[14][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

void test_regexmap_lt(void **state)
{
    (void) state;
    unsigned char test = 0;

    while (1) {
        if (test == '<') {
            assert_int_equal(regexmap[15][test], 1);
        } else {
            assert_int_not_equal(regexmap[15][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_success_match),
        cmocka_unit_test(test_fail_match),
        cmocka_unit_test(test_success_regex),
        cmocka_unit_test(test_fail_regex),
        cmocka_unit_test(test_success_wordmatch),
        cmocka_unit_test(test_fail_wordmatch),
        cmocka_unit_test(test_success_strisnum),
        cmocka_unit_test(test_fail_strisnum),
        cmocka_unit_test(test_fail_strisnum_null),
        cmocka_unit_test(test_success_strhowclosedmatch),
        cmocka_unit_test(test_fail_strhowclosedmatch_null),
        cmocka_unit_test(test_success_str_starts_with),
        cmocka_unit_test(test_fail_str_starts_with),
        cmocka_unit_test(test_strbreak),
        cmocka_unit_test(test_strbreak_null),
        cmocka_unit_test(test_regex_extraction),
        cmocka_unit_test(test_hostname_map),
        cmocka_unit_test(test_case_insensitive_char_map),
        cmocka_unit_test(test_regexmap_digit),
        cmocka_unit_test(test_regexmap_word),
        cmocka_unit_test(test_regexmap_space),
        cmocka_unit_test(test_regexmap_punctuation),
        cmocka_unit_test(test_regexmap_lparenthesis),
        cmocka_unit_test(test_regexmap_rparenthesis),
        cmocka_unit_test(test_regexmap_backslash),
        cmocka_unit_test(test_regexmap_nondigit),
        cmocka_unit_test(test_regexmap_nonword),
        cmocka_unit_test(test_regexmap_nonspace),
        cmocka_unit_test(test_regexmap_all),
        cmocka_unit_test(test_regexmap_tab),
        cmocka_unit_test(test_regexmap_dollar),
        cmocka_unit_test(test_regexmap_or),
        cmocka_unit_test(test_regexmap_lt),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
