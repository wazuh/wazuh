/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

#ifdef TEST_AGENT
char *_read_file(const char *high_name, const char *low_name, const char *defines_file) __attribute__((nonnull(3)));
#endif

#ifdef TEST_WINAGENT
char* filter(const char *string);
char *adapt_win_fc_output(char *command_output);
#endif

/* redefinitons/wrapping */

#ifdef TEST_AGENT
int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max) {
    int ret;
    char *value;
    char *pt;

    /* Try to read from the local define file */
    value = _read_file(high_name, low_name, "./internal_options.conf");
    if (!value) {
        merror_exit(DEF_NOT_FOUND, high_name, low_name);
    }

    pt = value;
    while (*pt != '\0') {
        if (!isdigit((int)*pt)) {
            merror_exit(INV_DEF, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if ((ret < min) || (ret > max)) {
        merror_exit(INV_DEF, high_name, low_name, value);
    }

    /* Clear memory */
    free(value);

    return (ret);
}

int __wrap_isChroot() {
    return 1;
}
#endif

#ifdef TEST_WINAGENT
void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}
#endif

/* Setup/teardown */

static int setup_group(void **state) {
    (void) state;
    Read_Syscheck_Config("test_syscheck.conf");
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    Free_Syscheck(&syscheck);
    return 0;
}

static int teardown_string(void **state) {
    char *s = *state;
    free(s);
    return 0;
}

#ifdef TEST_WINAGENT
static int setup_adapt_win_fc_output(void **state) {
    char **strarray = calloc(2, sizeof(char*));

    if(strarray == NULL)
        return -1;

    *state = strarray;

    return 0;
}

static int teardown_adapt_win_fc_output(void **state) {
    char **strarray = *state;

    free(strarray[0]);
    free(strarray[1]);
    free(strarray);

    return 0;
}
#endif

/* tests */

void test_is_nodiff_true(void **state) {
    int ret;

    const char * file_name = "/etc/ssl/private.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_false(void **state) {
    int ret;

    const char * file_name = "/dummy_file.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


void test_is_nodiff_regex_true(void **state) {
    int ret;

    const char * file_name = "file.test";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_regex_false(void **state) {
    int ret;

    const char * file_name = "test.file";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


void test_is_nodiff_no_nodiff(void **state) {
    int ret;
    int i;

    if (syscheck.nodiff) {
        for (i=0; syscheck.nodiff[i] != NULL; i++) {
            free(syscheck.nodiff[i]);
        }
        free(syscheck.nodiff);
    }
    if (syscheck.nodiff_regex) {
        for (i=0; syscheck.nodiff_regex[i] != NULL; i++) {
            OSMatch_FreePattern(syscheck.nodiff_regex[i]);
            free(syscheck.nodiff_regex[i]);
        }
        free(syscheck.nodiff_regex);
    }
    syscheck.nodiff = NULL;
    syscheck.nodiff_regex = NULL;

    const char * file_name = "test.file";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}

#ifdef TEST_WINAGENT
/* Forbidden windows path characters taken from: */
/* https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions */

void test_filter_success(void **state) {
    char *input = "a/unix/style/path/";
    char *output;

    output = filter(input);

    *state = output;

    assert_string_equal(output, "a\\unix\\style\\path\\");
}

void test_filter_unchanged_string(void **state) {
    char *input = "This string wont change";
    char *output;

    output = filter(input);

    *state = output;

    assert_string_equal(output, input);
}

void test_filter_colon_char(void **state) {
    char *input = "This : is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_filter_question_mark_char(void **state) {
    char *input = "This ? is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_filter_less_than_char(void **state) {
    char *input = "This < is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_filter_greater_than_char(void **state) {
    char *input = "This > is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_filter_pipe_char(void **state) {
    char *input = "This | is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_filter_double_quote_char(void **state) {
    char *input = "This \" is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_filter_asterisk_char(void **state) {
    char *input = "This * is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_filter_percentage_char(void **state) {
    char *input = "This % is not valid";
    char *output;

    output = filter(input);

    assert_null(output);
}

void test_adapt_win_fc_output_success(void **state) {
    char **strarray = *state;
    char *output;
    char *input = strdup(
        "***** start.txt\r\n"
        "    1:  First line\r\n"
        "***** END.TXT\r\n"
        "    1:  First Line 123\r\n"
        "    2:  Last line\r\n"
        "*****");

    if(input == NULL) fail();

    strarray[0] = input;

    output = adapt_win_fc_output(input);

    assert_non_null(output);

    strarray[1] = output;

    assert_string_equal(output, "> First line\n< First Line 123\n< Last line\n---\n");
}

void test_adapt_win_fc_output_invalid_input(void **state) {
    char **strarray = *state;
    char *output;
    char *input = strdup("This is invalid");

    if(input == NULL) fail();

    strarray[0] = input;

    expect_string(__wrap__mdebug2, formatted_msg, "(6667): Unable to find second line of alert string.: This is invalid");

    output = adapt_win_fc_output(input);

    assert_non_null(output);

    strarray[1] = output;

    assert_string_equal(output, input);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_nodiff_true),
        cmocka_unit_test(test_is_nodiff_false),
        cmocka_unit_test(test_is_nodiff_regex_true),
        cmocka_unit_test(test_is_nodiff_regex_false),
        cmocka_unit_test(test_is_nodiff_no_nodiff),

        /* Windows specific tests */
        #ifdef TEST_WINAGENT
        /* filter */
        cmocka_unit_test_teardown(test_filter_success, teardown_string),
        cmocka_unit_test_teardown(test_filter_unchanged_string, teardown_string),
        cmocka_unit_test(test_filter_colon_char),
        cmocka_unit_test(test_filter_question_mark_char),
        cmocka_unit_test(test_filter_less_than_char),
        cmocka_unit_test(test_filter_greater_than_char),
        cmocka_unit_test(test_filter_pipe_char),
        cmocka_unit_test(test_filter_double_quote_char),
        cmocka_unit_test(test_filter_asterisk_char),
        cmocka_unit_test(test_filter_percentage_char),

        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_success, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        cmocka_unit_test_setup_teardown(test_adapt_win_fc_output_invalid_input, setup_adapt_win_fc_output, teardown_adapt_win_fc_output),
        #endif
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
