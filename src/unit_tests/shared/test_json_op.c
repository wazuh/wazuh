/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>


#include "../../headers/json_op.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/common.h"
#include "../../headers/shared.h"

#define PATH_EXAMPLE "/home/test"
#define BUFFER_EXAMPLE "//This is a comment"

static int teardown(void **state) {
    if (state[0]) {
        int *ids = (int*)state[0];
        os_free(ids);
    }
    return 0;
}

static void test_json_fread_buffer_null(void **state) {
    (void) state;
    const char * DEBUG_MESSAGE_FREAD_BUFFER_NULL = "Cannot get the content of the file: /home/test";
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    expect_w_get_file_content(NULL);
    expect_string(__wrap__mdebug1, formatted_msg, DEBUG_MESSAGE_FREAD_BUFFER_NULL);

    assert_ptr_equal(json_fread(path, 1), NULL);

    os_free(path);
}

static void test_json_fread_no_retry(void **state) {
    (void) state;
    char * buffer;
    os_strdup(BUFFER_EXAMPLE, buffer);
    expect_w_get_file_content(buffer);
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON*)1);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON*)1);

    assert_ptr_equal(json_fread(path, 0), 0X1);

    os_free(path);
}

static void test_json_fread_with_retry(void **state) {
    (void) state;
    const char * DEBUG_MESSAGE_FREAD_TRYING_CLEAR_COMMENTS = "Couldn't parse JSON file '/home/test'. Trying to clear comments.";
    const char * DEBUG_MESSAGE_FREAD_COULD_NOT_PARSE_JSON = "Couldn't parse JSON file '/home/test'.";
    char * buffer;
    os_strdup(BUFFER_EXAMPLE, buffer);
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    expect_w_get_file_content(buffer);
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, DEBUG_MESSAGE_FREAD_TRYING_CLEAR_COMMENTS);
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    will_return(__wrap_cJSON_ParseWithOpts, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, DEBUG_MESSAGE_FREAD_COULD_NOT_PARSE_JSON);

    assert_ptr_equal(json_fread(path, 1), NULL);

    os_free(path);
}

static void test_json_fread_successfully(void **state) {
    (void) state;
    char * buffer;
    os_strdup(BUFFER_EXAMPLE, buffer);
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    expect_w_get_file_content(buffer);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON*)8);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON*)8);

    assert_ptr_equal(json_fread(path, 0), 0X8);

    os_free(path);
}

static void test_json_fwrite_buffer_null(void **state) {
    (void) state;
    test_mode = 1;
    const char * DEBUG_MESSAGE_FWRITE_DUMPING_JSON = "Internal error dumping JSON into file '/home/test'";
    cJSON * item = NULL;
    FILE *fp = NULL;
    char *buffer = NULL;
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    will_return(__wrap_cJSON_PrintUnformatted, buffer);
    expect_string(__wrap__mdebug1, formatted_msg, DEBUG_MESSAGE_FWRITE_DUMPING_JSON);

    assert_int_equal(json_fwrite(path, item), -1);

    test_mode = 0;
    os_free(path);
}

static void test_json_fwrite_fail_open(void **state) {
    (void) state;
    test_mode = 1;
    const char * JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR = "//This is a comment \n{\"fruit\":[{\"lemon\":200},{\"banana\":100}]}";
    const char * DEBUG_MESSAGE_FWRITE_COULD_NOT_OPEN_FILE = "(1103): Could not open file '/home/test' due to";
    cJSON * item = NULL;
    FILE *fp = NULL;
    char * buffer;
    os_strdup(JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR, buffer);
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    will_return(__wrap_cJSON_PrintUnformatted, buffer);
    expect_wfopen(path, "w", fp);
    expect_memory(__wrap__mdebug1, formatted_msg, DEBUG_MESSAGE_FWRITE_COULD_NOT_OPEN_FILE, strlen(DEBUG_MESSAGE_FWRITE_COULD_NOT_OPEN_FILE));

    assert_int_equal(json_fwrite(path, item), -1);

    test_mode = 0;
    os_free(path);
}

static void test_json_fwrite_fail_write(void **state) {
    (void) state;
    test_mode = 1;
    const char * DEBUG_MESSAGE_FWRITE_COULD_NOT_WRITE = "Couldn't write JSON into '/home/test'";
    cJSON * item = NULL;
    FILE *fp = (FILE*)1;
    char * buffer;
    os_strdup(BUFFER_EXAMPLE, buffer);
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    will_return(__wrap_cJSON_PrintUnformatted, buffer);
    test_mode = 0;
    expect_wfopen(path, "w", fp);
    test_mode = 1;
    will_return(__wrap_fwrite, strlen(buffer)-1);
    expect_memory(__wrap__mdebug1, formatted_msg, DEBUG_MESSAGE_FWRITE_COULD_NOT_WRITE, strlen(DEBUG_MESSAGE_FWRITE_COULD_NOT_WRITE));
    expect_fclose(fp, 1);

    assert_int_equal(json_fwrite(path, item), -1);

    test_mode = 0;
    os_free(path);
}

static void test_json_fwrite_successfully(void **state) {
    (void) state;
    const char * JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR = "//This is a comment \n{\"fruit\":[{\"lemon\":200},{\"banana\":100}]}";
    cJSON * item = (cJSON*)2;
    FILE *fp = (FILE*)2;
    char * buffer;
    os_strdup(JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR, buffer);
    char * path;
    os_strdup(PATH_EXAMPLE, path);

    will_return(__wrap_cJSON_PrintUnformatted, buffer);
    test_mode = 0;
    expect_wfopen(path, "w", fp);
    will_return(__wrap_fwrite, strlen(buffer));
    test_mode = 1;
    expect_fclose(fp, 1);
    assert_int_equal(json_fwrite(path, item), 0);

    test_mode = 0;
    os_free(path);
}

static void test_json_strip_delete_comment_single_bar(void **state) {
    (void) state;
    const char * JSON_EXAMPLE_WITH_COMMENT_SINGLE_BAR = "/*This is a comment*/{\"fruit\":[{\"lemon\":200},{\"banana\":100}]}";
    const char * EXPECTED_JSON_EXAMPLE_WITH_COMMENT_SINGLE_BAR = "{\"fruit\":[{\"lemon\":200},{\"banana\":100}]}";
    char * buffer;
    os_strdup(JSON_EXAMPLE_WITH_COMMENT_SINGLE_BAR, buffer);

    json_strip(buffer);

    assert_string_equal(buffer, EXPECTED_JSON_EXAMPLE_WITH_COMMENT_SINGLE_BAR);

    os_free(buffer);
}

static void test_json_strip_delete_comment_double_bar(void **state) {
    (void) state;
    const char * EXPECTED_JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR = "\n{\"fruit\":[{\"lemon\":200},{\"banana\":100}]}";
    const char * JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR = "//This is a comment \n{\"fruit\":[{\"lemon\":200},{\"banana\":100}]}";
    char * buffer;
    os_strdup(JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR, buffer);

    json_strip(buffer);

    assert_string_equal(buffer, EXPECTED_JSON_EXAMPLE_WITH_COMMENT_DOBLE_BAR);

    os_free(buffer);
}

static void test_json_strip_file_without_json_content(void **state) {
    (void) state;
    const char * FILE_WITHOUT_JSON_CONTENT = "/*this is a comment*/ \0";
    const char * STRING_EMPTY = " ";
    char * buffer;
    os_strdup(FILE_WITHOUT_JSON_CONTENT, buffer);

    json_strip(buffer);

    assert_string_equal(buffer, STRING_EMPTY);

    os_free(buffer);
}

void test_json_parse_agents_success(void **state)
{
    cJSON *agents = cJSON_CreateArray();
    cJSON *agent1 = cJSON_CreateNumber(15);
    cJSON *agent2 = cJSON_CreateNumber(23);
    cJSON *agent3 = cJSON_CreateNumber(8);
    cJSON_AddItemToArray(agents, agent1);
    cJSON_AddItemToArray(agents, agent2);
    cJSON_AddItemToArray(agents, agent3);

    int* agent_ids = json_parse_agents(agents);

    cJSON_Delete(agents);

    state[0] = (void*)agent_ids;
    state[1] = NULL;

    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], 15);
    assert_int_equal(agent_ids[1], 23);
    assert_int_equal(agent_ids[2], 8);
    assert_int_equal(agent_ids[3], -1);
}

void test_json_parse_agents_type_error(void **state)
{
    cJSON *agents = cJSON_CreateArray();
    cJSON *agent1 = cJSON_CreateNumber(15);
    cJSON *agent2 = cJSON_CreateString("23");
    cJSON *agent3 = cJSON_CreateNumber(8);
    cJSON_AddItemToArray(agents, agent1);
    cJSON_AddItemToArray(agents, agent2);
    cJSON_AddItemToArray(agents, agent3);

    int* agent_ids = json_parse_agents(agents);

    cJSON_Delete(agents);

    state[1] = NULL;

    assert_null(agent_ids);
}

void test_json_parse_agents_empty(void **state)
{
    cJSON *agents = cJSON_CreateArray();

    int* agent_ids = json_parse_agents(agents);

    cJSON_Delete(agents);

    state[0] = (void*)agent_ids;
    state[1] = NULL;

    assert_non_null(agent_ids);
    assert_int_equal(agent_ids[0], -1);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_json_fread_buffer_null),
        cmocka_unit_test(test_json_fread_no_retry),
        cmocka_unit_test(test_json_fread_with_retry),
        cmocka_unit_test(test_json_fread_successfully),
        cmocka_unit_test(test_json_fwrite_buffer_null),
        cmocka_unit_test(test_json_fwrite_fail_open),
        cmocka_unit_test(test_json_fwrite_fail_write),
        cmocka_unit_test(test_json_fwrite_successfully),
        cmocka_unit_test(test_json_strip_delete_comment_double_bar),
        cmocka_unit_test(test_json_strip_delete_comment_single_bar),
        cmocka_unit_test(test_json_strip_file_without_json_content),
        // json_parse_agents
        cmocka_unit_test_teardown(test_json_parse_agents_success, teardown),
        cmocka_unit_test_teardown(test_json_parse_agents_type_error, teardown),
        cmocka_unit_test_teardown(test_json_parse_agents_empty, teardown)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
