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
#include <string.h>

#include "shared.h"

/* setup/teardown */

static int setup_labels(void **state) {
    wlabel_t *labels;
    os_calloc(3, sizeof(wlabel_t), labels);

    labels[0].key = strdup("key1");
    labels[0].value = strdup("value1");
    labels[0].flags.hidden = 0;
    labels[0].flags.system = 0;

    labels[1].key = strdup("key2");
    labels[1].value = strdup("value2");
    labels[1].flags.hidden = 0;
    labels[1].flags.system = 0;

    labels[2].key = NULL;
    labels[2].value = NULL;

    *state = labels;
    return 0;
}

static int teardown_labels(void **state) {
    wlabel_t *labels = *state;
    labels_free(labels);
    return 0;
}

/* tests for labels_add */

void test_labels_add_new_label(void **state) {
    wlabel_t *labels = NULL;
    size_t size = 0;
    label_flags_t flags = {.hidden = 0, .system = 0};

    labels = labels_add(labels, &size, "test_key", "test_value", flags, 0);

    assert_non_null(labels);
    assert_int_equal(size, 1);
    assert_string_equal(labels[0].key, "test_key");
    assert_string_equal(labels[0].value, "test_value");
    assert_int_equal(labels[0].flags.hidden, 0);
    assert_int_equal(labels[0].flags.system, 0);
    assert_null(labels[1].key);

    labels_free(labels);
}

void test_labels_add_multiple_labels(void **state) {
    wlabel_t *labels = NULL;
    size_t size = 0;
    label_flags_t flags = {.hidden = 0, .system = 0};

    labels = labels_add(labels, &size, "key1", "value1", flags, 0);
    labels = labels_add(labels, &size, "key2", "value2", flags, 0);
    labels = labels_add(labels, &size, "key3", "value3", flags, 0);

    assert_non_null(labels);
    assert_int_equal(size, 3);
    assert_string_equal(labels[0].key, "key1");
    assert_string_equal(labels[1].key, "key2");
    assert_string_equal(labels[2].key, "key3");
    assert_null(labels[3].key);

    labels_free(labels);
}

void test_labels_add_with_flags(void **state) {
    wlabel_t *labels = NULL;
    size_t size = 0;
    label_flags_t flags_hidden = {.hidden = 1, .system = 0};
    label_flags_t flags_system = {.hidden = 0, .system = 1};

    labels = labels_add(labels, &size, "hidden_key", "hidden_value", flags_hidden, 0);
    labels = labels_add(labels, &size, "system_key", "system_value", flags_system, 0);

    assert_int_equal(labels[0].flags.hidden, 1);
    assert_int_equal(labels[0].flags.system, 0);
    assert_int_equal(labels[1].flags.hidden, 0);
    assert_int_equal(labels[1].flags.system, 1);

    labels_free(labels);
}

void test_labels_add_overwrite_existing(void **state) {
    wlabel_t *labels = NULL;
    size_t size = 0;
    label_flags_t flags = {.hidden = 0, .system = 0};

    labels = labels_add(labels, &size, "key1", "value1", flags, 0);
    labels = labels_add(labels, &size, "key1", "new_value", flags, 1);

    assert_int_equal(size, 1);
    assert_string_equal(labels[0].key, "key1");
    assert_string_equal(labels[0].value, "new_value");

    labels_free(labels);
}

void test_labels_add_no_overwrite(void **state) {
    wlabel_t *labels = NULL;
    size_t size = 0;
    label_flags_t flags = {.hidden = 0, .system = 0};

    labels = labels_add(labels, &size, "key1", "value1", flags, 0);
    labels = labels_add(labels, &size, "key1", "value2", flags, 0);

    assert_int_equal(size, 2);
    assert_string_equal(labels[0].key, "key1");
    assert_string_equal(labels[0].value, "value1");
    assert_string_equal(labels[1].key, "key1");
    assert_string_equal(labels[1].value, "value2");

    labels_free(labels);
}

/* tests for labels_get */

void test_labels_get_existing_key(void **state) {
    wlabel_t *labels = *state;
    char *value = labels_get(labels, "key1");

    assert_non_null(value);
    assert_string_equal(value, "value1");
}

void test_labels_get_non_existing_key(void **state) {
    wlabel_t *labels = *state;
    char *value = labels_get(labels, "non_existing");

    assert_null(value);
}

void test_labels_get_null_labels(void **state) {
    char *value = labels_get(NULL, "key1");

    assert_null(value);
}

/* tests for labels_free */

void test_labels_free_valid(void **state) {
    wlabel_t *labels;
    os_calloc(2, sizeof(wlabel_t), labels);

    labels[0].key = strdup("key1");
    labels[0].value = strdup("value1");
    labels[1].key = NULL;
    labels[1].value = NULL;

    labels_free(labels);
    /* If no crash, test passes */
}

void test_labels_free_null(void **state) {
    labels_free(NULL);
    /* If no crash, test passes */
}

/* tests for labels_format */

void test_labels_format_simple(void **state) {
    wlabel_t *labels = *state;
    char buffer[256];

    int ret = labels_format(labels, buffer, sizeof(buffer));

    assert_int_equal(ret, 0);
    assert_string_equal(buffer, "\"key1\":value1\n\"key2\":value2\n");
}

void test_labels_format_with_hidden_flag(void **state) {
    wlabel_t *labels;
    os_calloc(2, sizeof(wlabel_t), labels);

    labels[0].key = strdup("hidden_key");
    labels[0].value = strdup("hidden_value");
    labels[0].flags.hidden = 1;
    labels[0].flags.system = 0;
    labels[1].key = NULL;

    char buffer[256];
    int ret = labels_format(labels, buffer, sizeof(buffer));

    assert_int_equal(ret, 0);
    assert_string_equal(buffer, "!\"hidden_key\":hidden_value\n");

    labels_free(labels);
}

void test_labels_format_with_system_flag(void **state) {
    wlabel_t *labels;
    os_calloc(2, sizeof(wlabel_t), labels);

    labels[0].key = strdup("system_key");
    labels[0].value = strdup("system_value");
    labels[0].flags.hidden = 0;
    labels[0].flags.system = 1;
    labels[1].key = NULL;

    char buffer[256];
    int ret = labels_format(labels, buffer, sizeof(buffer));

    assert_int_equal(ret, 0);
    assert_string_equal(buffer, "#\"system_key\":system_value\n");

    labels_free(labels);
}

void test_labels_format_buffer_overflow(void **state) {
    wlabel_t *labels;
    os_calloc(2, sizeof(wlabel_t), labels);

    labels[0].key = strdup("key_with_long_value");
    labels[0].value = strdup("this_is_a_very_long_value_that_will_cause_overflow");
    labels[0].flags.hidden = 0;
    labels[0].flags.system = 0;
    labels[1].key = NULL;

    char buffer[20];
    int ret = labels_format(labels, buffer, sizeof(buffer));

    assert_int_equal(ret, -1);
    assert_true(strstr(buffer, "Not all labels") != NULL);

    labels_free(labels);
}

void test_labels_format_exact_buffer_size(void **state) {
    wlabel_t *labels;
    os_calloc(2, sizeof(wlabel_t), labels);

    labels[0].key = strdup("k");
    labels[0].value = strdup("v");
    labels[0].flags.hidden = 0;
    labels[0].flags.system = 0;
    labels[1].key = NULL;

    char buffer[8]; // "k":v\n\0 = 7 chars + null terminator
    int ret = labels_format(labels, buffer, sizeof(buffer));

    assert_int_equal(ret, 0);
    assert_string_equal(buffer, "\"k\":v\n");

    labels_free(labels);
}

void test_labels_format_buffer_overflow_edge_case(void **state) {
    wlabel_t *labels;
    os_calloc(3, sizeof(wlabel_t), labels);

    labels[0].key = strdup("key1");
    labels[0].value = strdup("val1");
    labels[0].flags.hidden = 0;
    labels[0].flags.system = 0;

    labels[1].key = strdup("key2");
    labels[1].value = strdup("val2");
    labels[1].flags.hidden = 0;
    labels[1].flags.system = 0;

    labels[2].key = NULL;

    char buffer[20]; // Too small for both labels
    int ret = labels_format(labels, buffer, sizeof(buffer));

    assert_int_equal(ret, -1);

    labels_free(labels);
}

void test_labels_format_empty_labels(void **state) {
    wlabel_t *labels;
    os_calloc(1, sizeof(wlabel_t), labels);
    labels[0].key = NULL;

    char buffer[256] = {0};
    int ret = labels_format(labels, buffer, sizeof(buffer));

    assert_int_equal(ret, 0);
    assert_string_equal(buffer, "");

    labels_free(labels);
}

/* tests for labels_parse */

void test_labels_parse_simple(void **state) {
    cJSON *json = cJSON_Parse("[{\"key\":\"\\\"test_key\\\"\",\"value\":\"test_value\"}]");

    wlabel_t *labels = labels_parse(json);

    assert_non_null(labels);
    assert_string_equal(labels[0].key, "test_key");
    assert_string_equal(labels[0].value, "test_value");
    assert_null(labels[1].key);

    labels_free(labels);
    cJSON_Delete(json);
}

void test_labels_parse_with_hidden_flag(void **state) {
    cJSON *json = cJSON_Parse("[{\"key\":\"!\\\"hidden_key\\\"\",\"value\":\"hidden_value\"}]");

    wlabel_t *labels = labels_parse(json);

    assert_non_null(labels);
    assert_string_equal(labels[0].key, "hidden_key");
    assert_string_equal(labels[0].value, "hidden_value");
    assert_int_equal(labels[0].flags.hidden, 1);
    assert_int_equal(labels[0].flags.system, 0);

    labels_free(labels);
    cJSON_Delete(json);
}

void test_labels_parse_with_system_flag(void **state) {
    cJSON *json = cJSON_Parse("[{\"key\":\"#\\\"system_key\\\"\",\"value\":\"system_value\"}]");

    wlabel_t *labels = labels_parse(json);

    assert_non_null(labels);
    assert_string_equal(labels[0].key, "system_key");
    assert_string_equal(labels[0].value, "system_value");
    assert_int_equal(labels[0].flags.hidden, 0);
    assert_int_equal(labels[0].flags.system, 1);

    labels_free(labels);
    cJSON_Delete(json);
}

void test_labels_parse_multiple_labels(void **state) {
    cJSON *json = cJSON_Parse("[{\"key\":\"\\\"key1\\\"\",\"value\":\"value1\"},"
                               "{\"key\":\"!\\\"key2\\\"\",\"value\":\"value2\"},"
                               "{\"key\":\"#\\\"key3\\\"\",\"value\":\"value3\"}]");

    wlabel_t *labels = labels_parse(json);

    assert_non_null(labels);
    assert_string_equal(labels[0].key, "key1");
    assert_string_equal(labels[1].key, "key2");
    assert_string_equal(labels[2].key, "key3");
    assert_int_equal(labels[1].flags.hidden, 1);
    assert_int_equal(labels[2].flags.system, 1);
    assert_null(labels[3].key);

    labels_free(labels);
    cJSON_Delete(json);
}

void test_labels_parse_invalid_key_format(void **state) {
    cJSON *json = cJSON_Parse("[{\"key\":\"invalid_key\",\"value\":\"value\"}]");

    wlabel_t *labels = labels_parse(json);

    assert_non_null(labels);
    assert_null(labels[0].key);

    labels_free(labels);
    cJSON_Delete(json);
}

void test_labels_parse_missing_closing_quote(void **state) {
    cJSON *json = cJSON_Parse("[{\"key\":\"\\\"key_without_closing\",\"value\":\"value\"}]");

    wlabel_t *labels = labels_parse(json);

    assert_non_null(labels);
    assert_null(labels[0].key);

    labels_free(labels);
    cJSON_Delete(json);
}

void test_labels_parse_null_json(void **state) {
    wlabel_t *labels = labels_parse(NULL);

    assert_null(labels);
}

void test_labels_parse_empty_json(void **state) {
    cJSON *json = cJSON_Parse("[]");

    wlabel_t *labels = labels_parse(json);

    assert_null(labels);

    cJSON_Delete(json);
}

void test_labels_parse_invalid_special_char(void **state) {
    cJSON *json = cJSON_Parse("[{\"key\":\"!invalid\",\"value\":\"value\"}]");

    wlabel_t *labels = labels_parse(json);

    assert_non_null(labels);
    assert_null(labels[0].key);

    labels_free(labels);
    cJSON_Delete(json);
}

/* tests for labels_dup */

void test_labels_dup_simple(void **state) {
    wlabel_t *labels = *state;

    wlabel_t *copy = labels_dup(labels);

    assert_non_null(copy);
    assert_string_equal(copy[0].key, "key1");
    assert_string_equal(copy[0].value, "value1");
    assert_string_equal(copy[1].key, "key2");
    assert_string_equal(copy[1].value, "value2");
    assert_null(copy[2].key);

    /* Verify deep copy */
    assert_ptr_not_equal(copy[0].key, labels[0].key);
    assert_ptr_not_equal(copy[0].value, labels[0].value);

    labels_free(copy);
}

void test_labels_dup_with_flags(void **state) {
    wlabel_t *labels;
    os_calloc(2, sizeof(wlabel_t), labels);

    labels[0].key = strdup("test");
    labels[0].value = strdup("value");
    labels[0].flags.hidden = 1;
    labels[0].flags.system = 1;
    labels[1].key = NULL;

    wlabel_t *copy = labels_dup(labels);

    assert_non_null(copy);
    assert_int_equal(copy[0].flags.hidden, 1);
    assert_int_equal(copy[0].flags.system, 1);

    labels_free(labels);
    labels_free(copy);
}

void test_labels_dup_null(void **state) {
    wlabel_t *copy = labels_dup(NULL);

    assert_null(copy);
}

void test_labels_dup_empty(void **state) {
    wlabel_t *labels;
    os_calloc(1, sizeof(wlabel_t), labels);
    labels[0].key = NULL;

    wlabel_t *copy = labels_dup(labels);

    assert_non_null(copy);
    assert_null(copy[0].key);

    labels_free(labels);
    labels_free(copy);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests labels_add
        cmocka_unit_test(test_labels_add_new_label),
        cmocka_unit_test(test_labels_add_multiple_labels),
        cmocka_unit_test(test_labels_add_with_flags),
        cmocka_unit_test(test_labels_add_overwrite_existing),
        cmocka_unit_test(test_labels_add_no_overwrite),
        // Tests labels_get
        cmocka_unit_test_setup_teardown(test_labels_get_existing_key, setup_labels, teardown_labels),
        cmocka_unit_test_setup_teardown(test_labels_get_non_existing_key, setup_labels, teardown_labels),
        cmocka_unit_test(test_labels_get_null_labels),
        // Tests labels_free
        cmocka_unit_test(test_labels_free_valid),
        cmocka_unit_test(test_labels_free_null),
        // Tests labels_format
        cmocka_unit_test_setup_teardown(test_labels_format_simple, setup_labels, teardown_labels),
        cmocka_unit_test(test_labels_format_with_hidden_flag),
        cmocka_unit_test(test_labels_format_with_system_flag),
        cmocka_unit_test(test_labels_format_buffer_overflow),
        cmocka_unit_test(test_labels_format_exact_buffer_size),
        cmocka_unit_test(test_labels_format_buffer_overflow_edge_case),
        cmocka_unit_test(test_labels_format_empty_labels),
        // Tests labels_parse
        cmocka_unit_test(test_labels_parse_simple),
        cmocka_unit_test(test_labels_parse_with_hidden_flag),
        cmocka_unit_test(test_labels_parse_with_system_flag),
        cmocka_unit_test(test_labels_parse_multiple_labels),
        cmocka_unit_test(test_labels_parse_invalid_key_format),
        cmocka_unit_test(test_labels_parse_missing_closing_quote),
        cmocka_unit_test(test_labels_parse_null_json),
        cmocka_unit_test(test_labels_parse_empty_json),
        cmocka_unit_test(test_labels_parse_invalid_special_char),
        // Tests labels_dup
        cmocka_unit_test_setup_teardown(test_labels_dup_simple, setup_labels, teardown_labels),
        cmocka_unit_test(test_labels_dup_with_flags),
        cmocka_unit_test(test_labels_dup_null),
        cmocka_unit_test(test_labels_dup_empty),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
