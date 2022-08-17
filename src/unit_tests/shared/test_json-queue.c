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

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 23);

    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer);

    object = jqueue_parse_json(queue);

    output = cJSON_PrintUnformatted(object);
    assert_string_equal(output, "{\"test\":\"valid_json\"}");
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

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 24);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer);

    expect_string(__wrap__mwarn, formatted_msg, "Invalid JSON alert read from '/home/test': '{\"test\":\"invalid_value'");

    object = jqueue_parse_json(queue);

    assert_null(object);
    assert_int_equal(queue->flags, 0);
}

void test_jqueue_parse_json_overlong_alert(void ** state) {
    file_queue * queue = *state;
    char buffer1[OS_MAXSTR + 1];
    char buffer2[OS_MAXSTR + 1];
    int64_t current_pos = 0;
    cJSON * object = NULL;

    snprintf(queue->file_name, MAX_FQUEUE, "%s", "/home/test");

    for (int i = 0; i < OS_MAXSTR; i++) {
        buffer1[i] = 'a';
    }
    buffer1[OS_MAXSTR]='\0';

    snprintf(buffer2, OS_MAXSTR, "%s\n","aaaa");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 1);

    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 65537);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 131073);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 131078);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer2);

    expect_string(__wrap__mwarn, formatted_msg, "Overlong JSON alert read from '/home/test'");

    object = jqueue_parse_json(queue);

    assert_null(object);
    assert_int_equal(queue->flags, 0);
}

void test_jqueue_parse_json_fgets_fail(void ** state) {
    file_queue * queue = *state;
    int64_t current_pos = 0;
    cJSON * object = NULL;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 1);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, NULL);

    object = jqueue_parse_json(queue);

    assert_null(object);
    assert_int_equal(queue->flags, CRALERT_READ_FAILED);
}

void test_jqueue_parse_json_fgets_fail_and_retry(void ** state) {
    file_queue * queue = *state;
    char buffer[OS_MAXSTR + 1];
    int64_t current_pos = 0;
    cJSON * object = NULL;

    snprintf(queue->file_name, MAX_FQUEUE, "%s", "/home/test");

    for (int i = 0; i < OS_MAXSTR; i++) {
        buffer[i] = 'a';
    }
    buffer[OS_MAXSTR]='\0';

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 1);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, buffer);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 65537);
    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "Can't read from '/home/test'. Trying again");

    will_return(__wrap_fseek, 1);

    object = jqueue_parse_json(queue);

    assert_null(object);
    assert_int_equal(queue->flags, CRALERT_READ_FAILED);
}

void test_jqueue_parse_json_stat_fail_and_retry(void ** state) {
    file_queue * queue = *state;
    int64_t current_pos = 0;
    cJSON * object = NULL;
    struct stat st = { .st_dev = 0 };

    snprintf(queue->file_name, MAX_FQUEUE, "%s", "/home/test");

    expect_function_call(__wrap_clearerr);
    expect_value(__wrap_clearerr, __stream, 1);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);

    expect_value(__wrap_fgets, __stream, queue->fp);
    will_return(__wrap_fgets, NULL);

    errno = ENOENT;

    expect_string(__wrap_stat, __file, "/home/test");
    will_return(__wrap_stat, &st);
    will_return(__wrap_stat, -1);

    expect_value(__wrap_sleep, seconds, 1);

    expect_string(__wrap_stat, __file, "/home/test");
    will_return(__wrap_stat, &st);
    will_return(__wrap_stat, -1);

    expect_string(__wrap__mwarn, formatted_msg, "(1118): Could not retrieve information of file '/home/test' due to [(2)-(No such file or directory)].");

    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, 0);

    object = jqueue_next(queue);

    assert_null(object);
    assert_null(queue->fp);
    assert_int_equal(queue->flags, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_valid, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_invalid, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_overlong_alert, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_fgets_fail, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_fgets_fail_and_retry, setup_queue, teardown_queue),
            cmocka_unit_test_setup_teardown(test_jqueue_parse_json_stat_fail_and_retry, setup_queue, teardown_queue),

    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
