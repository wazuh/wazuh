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
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

// setup / teardown

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

int setup_queue(void **state) {
    file_queue * queue;

    os_calloc(1, sizeof(file_queue), queue);
    queue->read_attempts = 0;
    queue->flags = 0;
    queue->fp = (FILE *)1;
    *state = queue;
    return 0;
}

int teardown_queue(void **state) {
    file_queue * queue = *state;
    os_free(queue);

    return 0;
}

// jqueue_parse_json

void test_jqueue_parse_json_valid(void ** state) {
    file_queue * queue = *state;
    char buffer[OS_MAXSTR + 1];
    int64_t current_pos = 0;
    cJSON * object = NULL;
    char * output = NULL;

    snprintf(buffer, OS_MAXSTR, "%s\n", "{\"test\":\"valid_json\"}");

    will_return(__wrap_w_ftell, 1);

    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer);

    object = jqueue_parse_json(queue);

    output = cJSON_PrintUnformatted(object);
    assert_string_equal(output, "{\"test\":\"valid_json\"}");
    assert_int_equal(queue->read_attempts, 0);
    assert_int_equal(queue->flags, 0);

    os_free(output);
    cJSON_Delete(object);
}

void test_jqueue_parse_json_invalid(void ** state) {
    file_queue * queue = *state;
    char buffer[OS_MAXSTR + 1];
    int64_t current_pos = 0;
    cJSON * object = NULL;

    snprintf(queue->file_name, MAX_FQUEUE, "%s", "/home/test");
    snprintf(buffer, OS_MAXSTR, "%s\n", "{\"test\":\"invalid_value");

    will_return(__wrap_w_ftell, 1);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer);

    expect_string(__wrap__mdebug2, formatted_msg, "Invalid JSON alert read from '/home/test'. Remaining attempts: 2");
    will_return(__wrap_fseek, 0);

    object = jqueue_parse_json(queue);

    assert_null(object);
    assert_int_equal(queue->read_attempts, 1);
    assert_int_equal(queue->flags, 0);
}

void test_jqueue_parse_json_max_attempts(void ** state) {
    file_queue * queue = *state;
    char buffer[OS_MAXSTR + 1];
    int64_t current_pos = 0;
    cJSON * object = NULL;

    queue->read_attempts = 2;

    snprintf(queue->file_name, MAX_FQUEUE, "%s", "/home/test");
    snprintf(buffer, OS_MAXSTR, "%s\n", "{\"test\":\"invalid_value");

    will_return(__wrap_w_ftell, 1);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer);

    expect_string(__wrap__mdebug2, formatted_msg, "Invalid JSON alert read from '/home/test'. Remaining attempts: 0");
    expect_string(__wrap__merror, formatted_msg, "Invalid JSON alert read from '/home/test'. Skipping it.");

    object = jqueue_parse_json(queue);

    assert_null(object);
    assert_int_equal(queue->read_attempts, 0);
    assert_int_equal(queue->flags, 0);
}

void test_jqueue_parse_json_fgets_fail(void ** state) {
    file_queue * queue = *state;
    int64_t current_pos = 0;
    cJSON * object = NULL;

    will_return(__wrap_w_ftell, 1);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, NULL);

    object = jqueue_parse_json(queue);

    assert_null(object);
    assert_int_equal(queue->read_attempts, 0);
    assert_int_equal(queue->flags, CRALERT_READ_FAILED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_valid, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_invalid, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_max_attempts, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_fgets_fail, setup_queue, teardown_queue)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
