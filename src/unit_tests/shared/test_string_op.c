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

#include "../headers/shared.h"

char * w_tolower_str(const char *string);

/* redefinitons/wrapping */

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

/* tests */

/* w_tolower_str */
void test_w_tolower_str_NULL(void **state)
{
    char * string = NULL;

    char* ret = w_tolower_str(string);
    assert_null(ret);

}

void test_w_tolower_str_empty(void **state)
{
    char * string = "";

    char* ret = w_tolower_str(string);
    assert_string_equal(ret, "");

    os_free(ret);

}

void test_w_tolower_str_caps(void **state)
{
    char * string = "TEST";

    char* ret = w_tolower_str(string);
    assert_string_equal(ret, "test");

    os_free(ret);

}

void test_os_snprintf_short(void **state)
{
    int ret;
    size_t size = 10;
    char str[size + 1];

    ret = os_snprintf(str, size, "%s%3d", "agent", 1);
    assert_int_equal(ret, 8);
}

void test_os_snprintf_long(void **state)
{
    int ret;
    size_t size = 5;
    char str[size + 1];

    expect_string(__wrap__mwarn, formatted_msg,"String may be truncated because it is too long.");
    ret = os_snprintf(str, size, "%s%3d", "agent", 1);
    assert_int_equal(ret, 8);
}

void test_os_snprintf_more_parameters(void **state)
{
    int ret;
    size_t size = 100;
    char str[size + 1];

    ret = os_snprintf(str, size, "%s%3d:%s%s", "agent", 1, "sent ", "message");
    assert_int_equal(ret, 21);
}

void test_w_remove_substr(void **state)
{
    int i;
    char * ret;
    char * strings[] = {
        "remove thisThis is the principal string.",
        "This is the principal string.remove this",
        "This isremove this the principal string."
    };
    int size_array = sizeof(strings) / sizeof(strings[0]);
    char * substr = "remove this";
    char * string;
    char * str_cpy;

    for (i = 0; i < size_array; i++) {
        w_strdup(strings[i], string);
        str_cpy = string;
        ret = w_remove_substr(str_cpy, substr);
        assert_string_equal(ret, "This is the principal string.");
        os_free(str_cpy);
    }
}

// Tests W_JSON_AddField

void test_W_JSON_AddField_nest_object(void **state)
{
    cJSON * root = cJSON_CreateObject();
    cJSON_AddObjectToObject(root, "test");
    const char * key = "test.files";
    const char * value = "[\"file1\",\"file2\",\"file3\"]";
    char * output = NULL;

    W_JSON_AddField(root, key, value);
    output = cJSON_PrintUnformatted(root);
    assert_string_equal(output, "{\"test\":{\"files\":[\"file1\",\"file2\",\"file3\"]}}");

    os_free(output);
    cJSON_Delete(root);
}

void test_W_JSON_AddField_nest_no_object(void **state)
{
    cJSON * root = cJSON_CreateObject();
    const char * key = "test.files";
    const char * value = "[\"file1\",\"file2\",\"file3\"]";
    char * output = NULL;

    W_JSON_AddField(root, key, value);
    output = cJSON_PrintUnformatted(root);
    assert_string_equal(output, "{\"test\":{\"files\":[\"file1\",\"file2\",\"file3\"]}}");

    os_free(output);
    cJSON_Delete(root);
}

void test_W_JSON_AddField_JSON_valid(void **state)
{
    cJSON * root = cJSON_CreateObject();
    const char * key = "files";
    const char * value = "[\"file1\",\"file2\",\"file3\"]";
    char * output = NULL;

    W_JSON_AddField(root, key, value);
    output = cJSON_PrintUnformatted(root);
    assert_string_equal(output, "{\"files\":[\"file1\",\"file2\",\"file3\"]}");

    os_free(output);
    cJSON_Delete(root);
}

void test_W_JSON_AddField_JSON_invalid(void **state)
{
    cJSON * root = cJSON_CreateObject();
    const char * key = "files";
    const char * value = "[\"file1\",\"file2\"],\"file3\"]";
    char * output = NULL;

    W_JSON_AddField(root, key, value);
    output = cJSON_PrintUnformatted(root);
    assert_string_equal(output, "{\"files\":\"[\\\"file1\\\",\\\"file2\\\"],\\\"file3\\\"]\"}");
    
    os_free(output);
    cJSON_Delete(root);
}

void test_W_JSON_AddField_string_time(void **state)
{
    cJSON * root = cJSON_CreateObject();
    const char * key = "time";
    const char * value = "[28/Oct/2020:10:22:11 +0000]";
    char * output = NULL;

    W_JSON_AddField(root, key, value);
    output = cJSON_PrintUnformatted(root);
    assert_string_equal(output, "{\"time\":\"[28/Oct/2020:10:22:11 +0000]\"}");

    os_free(output);
    cJSON_Delete(root);
}

/* Tests */

int main(void) {
    const struct CMUnitTest tests[] = {
        //Tests w_tolower_str
        cmocka_unit_test(test_w_tolower_str_NULL),
        cmocka_unit_test(test_w_tolower_str_empty),
        cmocka_unit_test(test_w_tolower_str_caps),
        // Tests os_snprintf
        cmocka_unit_test(test_os_snprintf_short),
        cmocka_unit_test(test_os_snprintf_long),
        cmocka_unit_test(test_os_snprintf_more_parameters),
        // Tests w_remove_substr
        cmocka_unit_test(test_w_remove_substr),
        // Tests W_JSON_AddField
        cmocka_unit_test(test_W_JSON_AddField_nest_object),
        cmocka_unit_test(test_W_JSON_AddField_nest_no_object),
        cmocka_unit_test(test_W_JSON_AddField_JSON_valid),
        cmocka_unit_test(test_W_JSON_AddField_JSON_invalid),
        cmocka_unit_test(test_W_JSON_AddField_string_time),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
