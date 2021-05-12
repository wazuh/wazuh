/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

/* setup/teardown */

int teardown_free_paths(void **state) {
    char **paths = *state;
    free_strarray(paths);

    return 0;
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
/* w_strndup */
void test_w_strndup_null_str(void ** state)
{
    const char * str = NULL;
    assert_null(w_strndup(NULL, 5));
}

void test_w_strndup_str_less_than_n(void ** state)
{
    const char * str = "Test";
    const char * expected_str = "Test";
    char * retval;

    retval = w_strndup(str, strlen(str)+10);
    assert_string_equal(retval, expected_str);
    assert_int_equal(strlen(retval), strlen(expected_str));
    os_free(retval);
}

void test_w_strndup_str_greater_than_n(void ** state) {
    const char * str = "Test Test Test Test";
    const char * expected_str = "Test Test ";
    char * retval;

    retval = w_strndup(str, 10);
    assert_string_equal(retval, expected_str);
    assert_int_equal(strlen(retval), 10);
    os_free(retval);
}

void test_w_strndup_str_equal_to_n(void ** state) {
    const char * str = "Test Test Test Test";
    const char * expected_str = "Test Test Test Test";
    char * retval;

    retval = w_strndup(str, strlen(expected_str));
    assert_string_equal(retval, expected_str);
    assert_int_equal(strlen(retval), strlen(expected_str));
    os_free(retval);
}


void test_w_strndup_str_zero_n(void ** state) {
    const char * str = "Test Test Test Test";
    const char * expected_str = "Test Test Test Test";
    char * retval;

    retval = w_strndup(str, 0);
    assert_string_equal(retval, "");
    assert_int_equal(strlen(retval), 0);
    os_free(retval);
}

void test_w_strcat_null_input(void ** state) {
    const char * B = "Hello World";
    char * a = w_strcat(NULL, B, strlen(B));

    assert_string_equal(a, B);

    free(a);
}

void test_w_strcat_string_input(void ** state) {
    char * a = strdup("Hello");
    const char * B = "World";
    a = w_strcat(a, B, strlen(B));

    assert_string_equal(a, "HelloWorld");

    free(a);
}

void test_w_strarray_append(void ** state) {
    char ** array = NULL;
    char *a, *b;
    int n = 0;

    os_strdup("Hello", a);
    os_strdup("World", b);

    array = w_strarray_append(array, a, n++);
    array = w_strarray_append(array, b, n++);

    assert_ptr_equal(array[0], a);
    assert_ptr_equal(array[1], b);
    assert_null(array[2]);

    free_strarray(array);
}

void test_w_strtok_empty(void ** state) {
    char ** array = w_strtok("");
    assert_null(array[0]);
    free_strarray(array);
}

void test_w_strtok_nospaces(void ** state) {
    char ** array = w_strtok("Hello");
    assert_string_equal(array[0], "Hello");
    assert_null(array[1]);
    free_strarray(array);
}

void test_w_strtok_string(void ** state) {
    char ** array = w_strtok("BB\"B BBB BBE\" \"\" F \"\\\"G\\\"\" \"BB\"B BB\\\\E\\ GGF D B");
    assert_string_equal(array[0], "BBB BBB BBE");
    assert_string_equal(array[1], "");
    assert_string_equal(array[2], "F");
    assert_string_equal(array[3], "\"G\"");
    assert_string_equal(array[4], "BBB");
    assert_string_equal(array[5], "BB\\E GGF");
    assert_string_equal(array[6], "D");
    assert_string_equal(array[7], "B");
    assert_null(array[8]);
    free_strarray(array);
}

void test_w_string_split_str_null(void ** state) {
    const char *str = NULL;
    char **paths = NULL;
    const char *delim = ",";

    paths = w_string_split(str, delim, 0);
    *state = paths;
    assert_null(paths[0]);
}

void test_w_string_split_delim_null(void ** state) {
    const char *str = "test1,test2,test3";
    char **paths = NULL;
    const char *delim = NULL;

    paths = w_string_split(str, delim, 0);
    *state = paths;
    assert_null(paths[0]);
}

void test_w_string_split_normal(void ** state) {
    const char *str = "test1,test2,test3";
    char *expected_str[] = {"test1","test2","test3"};
    char **paths = NULL;
    const char *delim = ",";

    paths = w_string_split(str, delim, 0);
    *state = paths;

    assert_non_null(paths[0]);
    for (int i = 0; paths[i]; i++){
        assert_string_equal(paths[i], expected_str[i]);
    }
}

void test_w_string_split_max_array_size(void ** state) {
    const char *str = "test1,test2,test3,outofarray";
    char *expected_str[] = {"test1","test2","test3"};
    char **paths = NULL;
    const char *delim = ",";

    paths = w_string_split(str, delim, 3);
    *state = paths;

    assert_non_null(paths[0]);
    for (int i = 0; paths[i]; i++){
        assert_string_equal(paths[i], expected_str[i]);
    }
}


void test_strnspn_escaped(void ** state)
{
    assert_int_equal(strcspn_escaped("ABC\\D ", ' '), 5);
    assert_int_equal(strcspn_escaped("ABC\\ D", ' '), 6);
    assert_int_equal(strcspn_escaped("ABCD\\", ' '), 5);
    assert_int_equal(strcspn_escaped("ABCDE \\ ", ' '), 5);
    assert_int_equal(strcspn_escaped("ABCDE\\\\ F", ' '), 7);
    assert_int_equal(strcspn_escaped("ABCDE\\\\", ' '), 7);
    assert_int_equal(strcspn_escaped("ABC\\ D E", ' '), 6);
    assert_int_equal(strcspn_escaped("ABCDE", ' '), 5);
}

void test_json_escape(void ** state)
{
    const char * INPUTS[] = { "\b\tHello \n\f\r \"World\".\\", "Hello\b\t \n\f\r \"World\"\\.", NULL };
    const char * EXPECTED_OUTPUTS[] = { "\\b\\tHello \\n\\f\\r \\\"World\\\".\\\\", "Hello\\b\\t \\n\\f\\r \\\"World\\\"\\\\.", NULL };
    int i;

    for (i = 0; INPUTS[i] != NULL; i++) {
        char * output = wstr_escape_json(INPUTS[i]);
        assert_string_equal(output, EXPECTED_OUTPUTS[i]);
        free(output);
    }
}

void test_json_unescape(void ** state)
{
    const char * INPUTS[] = { "\\b\\tHello \\n\\f\\r \\\"World\\\".\\\\", "Hello\\b\\t \\n\\f\\r \\\"World\\\"\\\\.", "Hello \\World", "Hello World\\", NULL };
    const char * EXPECTED_OUTPUTS[] = { "\b\tHello \n\f\r \"World\".\\", "Hello\b\t \n\f\r \"World\"\\.", "Hello \\World", "Hello World\\", NULL };
    int i;

    for (i = 0; INPUTS[i] != NULL; i++) {
        char * output = wstr_unescape_json(INPUTS[i]);
        assert_string_equal(output, EXPECTED_OUTPUTS[i]);
        free(output);
    }
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
        // Tests w_strndup
        cmocka_unit_test(test_w_strndup_null_str),
        cmocka_unit_test(test_w_strndup_str_less_than_n),
        cmocka_unit_test(test_w_strndup_str_greater_than_n),
        cmocka_unit_test(test_w_strndup_str_equal_to_n),
        cmocka_unit_test(test_w_strndup_str_zero_n),
        // Tests w_strcat
        cmocka_unit_test(test_w_strcat_null_input),
        cmocka_unit_test(test_w_strcat_string_input),
        // Tests w_strarray_append
        cmocka_unit_test(test_w_strarray_append),
        // Tests w_strtok
        cmocka_unit_test(test_w_strtok_empty),
        cmocka_unit_test(test_w_strtok_nospaces),
        cmocka_unit_test(test_w_strtok_string),
        // Tests w_string_split
        cmocka_unit_test_teardown(test_w_string_split_str_null, teardown_free_paths),
        cmocka_unit_test_teardown(test_w_string_split_delim_null, teardown_free_paths),
        cmocka_unit_test_teardown(test_w_string_split_normal, teardown_free_paths),
        cmocka_unit_test_teardown(test_w_string_split_max_array_size, teardown_free_paths),
        // Tests escape/unescape
        cmocka_unit_test(test_strnspn_escaped),
        cmocka_unit_test(test_json_escape),
        cmocka_unit_test(test_json_unescape),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
