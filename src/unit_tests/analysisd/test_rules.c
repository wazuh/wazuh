/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../../analysisd/rules.h"
#include "../../analysisd/config.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/analysisd.h"

char *loadmemory(char *at, const char *str, OSList* log_msg);
int get_info_attributes(char **attributes, char **values, OSList* log_msg);


/* setup/teardown */

/* wraps */
void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                    const char * file, char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected_ptr(list);
    check_expected(formatted_msg);
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

/* tests */
// loadmemory
void test_loadmemory_null_append_ok(void ** state)
{
    char * at = NULL;
    char * str;

    const size_t len = 1000;
    char * expect_retval;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), expect_retval);
    memset(expect_retval, (int) '-', len - 1);
    expect_retval[len-1] = '\0';

    retval = loadmemory(at,str, NULL);

    assert_string_equal(retval, expect_retval);

    os_free(str);
    os_free(retval);
    os_free(expect_retval);

}

void test_loadmemory_null_append_oversize(void ** state)
{
    char * at = NULL;
    char * str;
    OSList list_msg = {0};

    const size_t len = 2049;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    char expect_msg[OS_SIZE_4096];

    snprintf(expect_msg, OS_SIZE_4096, "(1104): Maximum string size reached for: %s.", str);
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expect_msg);

    retval = loadmemory(at,str, &list_msg);

    assert_null(retval);

    os_free(str);

}

void test_loadmemory_append_oversize(void ** state)
{
    char * at = NULL;
    char * str = NULL;
    OSList list_msg = {0};

    const size_t len = 2050;
    char * retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), at);
    memset(at, (int) '+', len - 1);
    str[len-1] = '\0';

    char expect_msg[OS_SIZE_20480];

    snprintf(expect_msg, OS_SIZE_20480, "(1104): Maximum string size reached for: %s.", str);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expect_msg);

    retval = loadmemory(at,str, &list_msg);

    assert_null(retval);

    os_free(str);
    os_free(at);

}

void test_loadmemory_append_ok(void ** state)
{
    char * at = NULL;
    char * str = NULL;
    OSList list_msg = {0};

    const size_t len = 512;
    char * retval;
    char * expect_retval;

    os_calloc(len, sizeof(char), str);
    memset(str, (int) '-', len - 1);
    str[len-1] = '\0';

    os_calloc(len, sizeof(char), at);
    memset(at, (int) '+', len - 1);
    at[len-1] = '\0';

    os_calloc(len * 2, sizeof(char), expect_retval);
    strncat(expect_retval, at, len * 2);
    strncat(expect_retval, str, len * 2);

    retval = loadmemory(at,str, &list_msg);

    assert_non_null(retval);
    assert_string_equal(retval, expect_retval);

    os_free(str);
    os_free(retval);
    os_free(expect_retval);

}

// get_info_attributes
void test_get_info_attributes_null(void ** state)
{
    OSList log_msg = {0};
    char ** values = NULL;
    char ** attributes = NULL;

    int retval;
    const int expect_retval = 0;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);
}

void test_get_info_attributes_empty(void ** state)
{
    OSList log_msg = {0};
    char ** values = NULL;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = NULL;

    int retval;
    const int expect_retval = 0;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
}

void test_get_info_attributes_without_value(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = NULL;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = -1;

    char excpect_msg[OS_SIZE_2048];
    snprintf(excpect_msg, OS_SIZE_2048, "rules_op: Element info attribute \"%s\" does not have a value", attributes[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, excpect_msg);

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_text(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "text";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 0;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_link(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "link";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 1;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_cve(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "cve";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 2;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_osvdb(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "osvdb";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = 3;

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_invalid_value(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "bad_type";
    char * values_k = "test_value";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = -1;

    char excpect_msg[OS_SIZE_2048];
    snprintf(excpect_msg, OS_SIZE_2048, "rules_op: Element info has invalid attribute \"%s\"", attributes[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, excpect_msg);

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

void test_get_info_attributes_invalid_type(void ** state)
{
    OSList log_msg = {0};
    char * attribute_k = "type";
    char * values_k = "bad_value";

    char ** values;
    os_calloc(1,sizeof(char *), values);
    values[0] = values_k;

    char ** attributes;
    os_calloc(1,sizeof(char *), attributes);
    attributes[0] = attribute_k;

    int retval;
    const int expect_retval = -1;

    char excpect_msg[OS_SIZE_2048];
    snprintf(excpect_msg, OS_SIZE_2048, "rules_op: Element info attribute \"%s\""
                            " has invalid value \"%s\"", attributes[0], values[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &log_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, excpect_msg);

    retval = get_info_attributes(attributes, values, &log_msg);

    assert_int_equal(retval, expect_retval);

    os_free(attributes);
    os_free(values);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests _loadmemory
        cmocka_unit_test(test_loadmemory_null_append_ok),
        cmocka_unit_test(test_loadmemory_null_append_oversize),
        cmocka_unit_test(test_loadmemory_append_oversize),
        cmocka_unit_test(test_loadmemory_append_ok),
        // Tests get_info_attributes
        cmocka_unit_test(test_get_info_attributes_null),
        cmocka_unit_test(test_get_info_attributes_empty),
        cmocka_unit_test(test_get_info_attributes_without_value),
        cmocka_unit_test(test_get_info_attributes_text),
        cmocka_unit_test(test_get_info_attributes_link),
        cmocka_unit_test(test_get_info_attributes_cve),
        cmocka_unit_test(test_get_info_attributes_osvdb),
        cmocka_unit_test(test_get_info_attributes_invalid_value),
        cmocka_unit_test(test_get_info_attributes_invalid_type)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}