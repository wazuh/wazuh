#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../os_regex/os_regex.h"
#include "../os_regex/os_regex_internal.h"
#include "../headers/pthreads_op.h"
#include "tap.h"

#define MAX_TEST_THREADS 10
pthread_barrier_t   barrier;

int test_success_match() {

    int i;
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
        {NULL, NULL, NULL}
    };

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_eq(OS_Match2(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

int test_fail_match() {

    int i;
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
        {"^bin$|^shell$", "bina", ""},
        {"^bin$|^shell$", "shella", ""},
        {"^bin$|^shell$", "ashell", ""},
        {NULL, NULL, NULL}
    };

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_ne(OS_Match2(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

int test_success_regex() {

    int i;
    /*
     * Please note that all strings are \ escaped
     */
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
        {NULL, NULL, NULL}
    };

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_eq(OS_Regex(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

int test_fail_regex() {

    int i;
    /*
     * Please note that all strings are \ escaped
     */
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
        {NULL, NULL, NULL},
    };

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_ne(OS_Regex(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

int test_success_wordmatch() {

    int i;
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

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_eq(OS_WordMatch(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

int test_fail_wordmatch() {

    int i;
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

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_ne(OS_WordMatch(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

int test_success_strisnum() {

    int i;
    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[] = {
        "1",
        "0123",
        NULL,
    };

    for (i = 0; tests[i] != NULL ; i++) {
        w_assert_int_eq(OS_StrIsNum(tests[i]), 1);
    }
    return 1;
}

int test_fail_strisnum() {

    int i;
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

    for (i = 0; tests[i] != NULL ; i++) {
        w_assert_int_ne(OS_StrIsNum(tests[i]), 1);
    }
    return 1;
}

int test_success_strhowclosedmatch() {

    int i;
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

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_uint_eq(OS_StrHowClosedMatch(tests[i][0], tests[i][1])
                          , (unsigned) atoi(tests[i][2]));
    }
    return 1;
}

int test_strbreak() {

    int i;

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

    for (i = 0; tests[i][0] != NULL; i++) {
        char **result = OS_StrBreak(tests[i][0][0], tests[i][1], (unsigned) atoi(tests[i][2]));

        int j = 3;
        if (tests[i][j] == NULL) {
            w_assert_ptr_eq(result, NULL);
            continue;
        }

        int k;
        for (k = 0; tests[i][j] != NULL; j++, k++) {
            w_assert_ptr_ne(result[k], NULL);
            w_assert_str_eq(result[k], tests[i][j]);
        }
        w_assert_ptr_eq(result[k], NULL);

        k = 0;
        while (result[k]) {
            free(result[k++]);
        }
        free(result);
    }
    return 1;
}

int test_regex_extraction() {

    int i;
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

    for (i = 0; tests[i][0] != NULL; i++) {
        OSRegex reg;
        w_assert_int_eq(OSRegex_Compile(tests[i][0], &reg, OS_RETURN_SUBSTRING), 1);
        w_assert_ptr_ne((void *)OSRegex_Execute(tests[i][1], &reg), NULL);



        char **result = reg.d_sub_strings;

        int j;
        int k;
        for (j = 2, k = 0; tests[i][j] != NULL; j++, k++) {
            w_assert_ptr_ne(result[k], NULL);
            w_assert_str_eq(result[k], tests[i][j]);
        }
        w_assert_ptr_eq(result[k], NULL);

        OSRegex_FreePattern(&reg);
    }
    return 1;
}

int test_hostname_map() {

    unsigned char test = 0;

    while (1) {
        if ((test >= 48 && test <= 57) // 0-9
                || (test >= 65 && test <= 90) // A-Z
                || (test >= 97 && test <= 122) // a-z
                || test == '(' || test == ')' || test == '-'
                || test == '.' || test == '@' || test == '/'
                || test == '_') {
            w_assert_int_eq(isValidChar(test), 1);
        } else {
            w_assert_int_ne(isValidChar(test), 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_case_insensitive_char_map() {

    unsigned char test = 0;

    while (1) {
        if (test >= 65 && test <= 90) { // A-Z
            w_assert_int_eq(charmap[test], test+32);
        } else {
            w_assert_int_eq(charmap[test], test);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_digit() {

    unsigned char test = 0;

    while (1) {
        if (test >= '0' && test <= '9') {
            w_assert_int_eq(regexmap[1][test], 1);
        } else {
            w_assert_int_ne(regexmap[1][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_word() {

    unsigned char test = 0;

    while (1) {
        if ((test >= 'a' && test <= 'z')
                || (test >= 'A' && test <= 'Z')
                || (test >= '0' && test <= '9')
                || test == '-' || test == '@'
                || test == '_') {
            w_assert_int_eq(regexmap[2][test], 1);
        } else {
            w_assert_int_ne(regexmap[2][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_space() {

    unsigned char test = 0;

    while (1) {
        if (test == ' ') {
            w_assert_int_eq(regexmap[3][test], 1);
        } else {
            w_assert_int_ne(regexmap[3][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_punctuation() {

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
            w_assert_int_eq(regexmap[4][test], 1);
        } else {
            w_assert_int_ne(regexmap[4][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_lparenthesis() {

    unsigned char test = 0;

    while (1) {
        if (test == '(') {
            w_assert_int_eq(regexmap[5][test], 1);
        } else {
            w_assert_int_ne(regexmap[5][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_rparenthesis() {

    unsigned char test = 0;

    while (1) {
        if (test == ')') {
            w_assert_int_eq(regexmap[6][test], 1);
        } else {
            w_assert_int_ne(regexmap[6][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_backslash() {

    unsigned char test = 0;

    while (1) {
        if (test == '\\') {
            w_assert_int_eq(regexmap[7][test], 1);
        } else {
            w_assert_int_ne(regexmap[7][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_nondigit() {

    unsigned char test = 0;

    while (1) {
        if (!(test >= '0' && test <= '9')) {
            w_assert_int_eq(regexmap[8][test], 1);
        } else {
            w_assert_int_ne(regexmap[8][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_nonword() {

    unsigned char test = 0;

    while (1) {
        if (!((test >= 'a' && test <= 'z')
                || (test >= 'A' && test <= 'Z')
                || (test >= '0' && test <= '9')
                || test == '-' || test == '@'
                || test == '_')) {
            w_assert_int_eq(regexmap[9][test], 1);
        } else {
            w_assert_int_ne(regexmap[9][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}


int test_regexmap_nonspace() {

    unsigned char test = 0;

    while (1) {
        if (test != ' ') {
            w_assert_int_eq(regexmap[10][test], 1);
        } else {
            w_assert_int_ne(regexmap[10][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_all() {

    unsigned char test = 0;

    while (1) {
        w_assert_int_eq(regexmap[11][test], 1);

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_tab() {

    unsigned char test = 0;

    while (1) {
        if (test == '\t') {
            w_assert_int_eq(regexmap[12][test], 1);
        } else {
            w_assert_int_ne(regexmap[12][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_dollar() {

    unsigned char test = 0;

    while (1) {
        if (test == '$') {
            w_assert_int_eq(regexmap[13][test], 1);
        } else {
            w_assert_int_ne(regexmap[13][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_or() {

    unsigned char test = 0;

    while (1) {
        if (test == '|') {
            w_assert_int_eq(regexmap[14][test], 1);
        } else {
            w_assert_int_ne(regexmap[14][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_regexmap_lt() {

    unsigned char test = 0;

    while (1) {
        if (test == '<') {
            w_assert_int_eq(regexmap[15][test], 1);
        } else {
            w_assert_int_ne(regexmap[15][test], 1);
        }

        if (test == 255) {
            break;
        }
        test++;
    }
    return 1;
}

int test_success_str_starts_with() {

    int i;
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

    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_eq(OS_StrStartsWith(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

int test_fail_str_starts_with() {

    int i;
    /*
     * Please note that all strings are \ escaped
     */
    const char *tests[][2] = {
        { "test", "test1234" },
        { "", "test" },
        {NULL, NULL},
    };


    for (i = 0; tests[i][0] != NULL ; i++) {
        w_assert_int_ne(OS_StrStartsWith(tests[i][0], tests[i][1]), 1);
    }
    return 1;
}

void *test_no_rc_exec_thread(__attribute__((unused)) void *regex){
    pthread_barrier_wait (&barrier);
    OSRegex_Execute_ex("Pattern", (OSRegex *) regex, NULL);
}

int test_no_rc_execute() {
    int i;
    int error;
    pthread_t threads[MAX_TEST_THREADS];
    OSRegex regex;

    if ((error = !OSRegex_Compile("Pattern to compile.", &regex, 0))) {
        goto end;
    }

    pthread_barrier_init (&barrier, NULL, MAX_TEST_THREADS);

    for (i = 0; i < MAX_TEST_THREADS; i++) {
        if (error = CreateThreadJoinable(&threads[i], test_no_rc_exec_thread, &regex), error) {
            goto end;
        }
    }

    for (i = 0; i < MAX_TEST_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    OSRegex_FreePattern(&regex);
end:
    w_assert_int_eq(error, 0);
    return 1;
}

int main(void) {
    printf("\n\n    STARTING TEST - OS_REGEX   \n\n");

    // Match strings with patterns using OS_Match
    TAP_TEST_MSG(test_success_match(), "Matching strings with patterns using OS_Match2 test.");

    // Don't match strings with patterns using OS_Match
    TAP_TEST_MSG(test_fail_match(), "Not matching strings with patterns using OS_Regex test.");

    // Match strings with patterns using OS_Regex
    TAP_TEST_MSG(test_success_regex(), "Matching strings with patterns using OS_Regex test.");

    // Don't match strings with patterns using OS_Regex
    TAP_TEST_MSG(test_fail_regex(), "Not matching strings with patterns using OS_Regex test.");

    // Match strings with patterns using OS_WordMatch
    TAP_TEST_MSG(test_success_wordmatch(), "Matching strings with patterns using OS_WordMatch test.");

    // Don't match strings with patterns using OS_WordMatch
    TAP_TEST_MSG(test_fail_wordmatch(), "Not matching strings with patterns using OS_WordMatch test.");

    // Match strings with patterns using OS_StrIsNum
    TAP_TEST_MSG(test_success_strisnum(), "Matching strings with patterns using OS_StrIsNum test.");

    // Don't match strings with patterns using OS_StrIsNum
    TAP_TEST_MSG(test_fail_strisnum(), "Not matching strings with patterns using OS_StrIsNum test.");

    // Match strings with patterns using OS_StrHowClosedMatch
    TAP_TEST_MSG(test_success_strhowclosedmatch(), "Matching strings with patterns using OS_StrHowClosedMatch test.");

    // Match strings with patterns using OS_StrBreak
    TAP_TEST_MSG(test_strbreak(), "OS_StrBreak test.");

    // Match strings with patterns using OSRegex_Execute
    TAP_TEST_MSG(test_regex_extraction(), "OSRegex_Execute test.");

    // Validate the characters of a hostname
    TAP_TEST_MSG(test_hostname_map(), "Validate the characters of a hostname.");

    // Validate case insensitive char map test
    TAP_TEST_MSG(test_case_insensitive_char_map(), "Validate case insensitive char map test.");

    // Validate back slash char test
    TAP_TEST_MSG(test_regexmap_backslash(), "Validate back slash char test.");

    // Validate \d charset
    TAP_TEST_MSG(test_regexmap_digit(), "Validate charset from '\\d'.");

    // Validate \w charset
    TAP_TEST_MSG(test_regexmap_word(), "Validate charset from '\\w' test.");

    // Using spaces inside regex test
    TAP_TEST_MSG(test_regexmap_space(), "Validate charset from '\\s' test.");

    // Validate puncuation characters test
    TAP_TEST_MSG(test_regexmap_punctuation(), "Validate charset from '\\p' test.");

    // Validate non-digit charmap test
    TAP_TEST_MSG(test_regexmap_nondigit(), "Validate charset from '\\D' test.");

    // Validate non-word charmap test
    TAP_TEST_MSG(test_regexmap_nonword(), "Validate charset from '\\W' test.");

    // Validate non-space charmap test
    TAP_TEST_MSG(test_regexmap_nonspace(), "Validate charset from '\\S' test.");

    // Validate anything charmap test
    TAP_TEST_MSG(test_regexmap_all(), "Validate charset from '\\.' test.");

    // Validate tab charmap test
    TAP_TEST_MSG(test_regexmap_tab(), "Validate charset from '\\t' test.");

    // Validate left parenthesis char test
    TAP_TEST_MSG(test_regexmap_lparenthesis(), "Validate left parenthesis '(' char test.");

    // Validate right parenthesis char test
    TAP_TEST_MSG(test_regexmap_rparenthesis(), "Validate right parenthesis ')' char test.");

    // Validate dollar char test
    TAP_TEST_MSG(test_regexmap_dollar(), "Validate dollar '$' char test.");

    // Validate OR char test
    TAP_TEST_MSG(test_regexmap_or(), "Validate OR '|' char test.");

    // Validate < char test
    TAP_TEST_MSG(test_regexmap_lt(), "Validate less than '<' char test.");

    // Validate string starts with substring test
    TAP_TEST_MSG(test_success_str_starts_with(), "Validate string starts with substring test.");

    // Not matching substring at the beginning of string
    TAP_TEST_MSG(test_fail_str_starts_with(), "Not matching substring at the beginning of string.");

    // There is no race condition in OSRegex_Execute_ex
    TAP_TEST_MSG(test_no_rc_execute(), "There is no race condition in OSRegex_Execute_ex().");

    TAP_PLAN;
    int r = tap_summary();
    printf("\n    ENDING TEST  - OS_REGEX   \n\n");
    return r;
}
