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

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests labels_add
        cmocka_unit_test(test_labels_add_new_label),
        cmocka_unit_test(test_labels_add_multiple_labels),
        cmocka_unit_test(test_labels_add_with_flags),
        cmocka_unit_test(test_labels_add_overwrite_existing),
        cmocka_unit_test(test_labels_add_no_overwrite),
        // Tests labels_free
        cmocka_unit_test(test_labels_free_valid),
        cmocka_unit_test(test_labels_free_null),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
