/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* The manager targets a legacy 4.x <client> block names, and which one the agent uses. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "shared.h"
#include "legacy-server-targets.h"

static void test_targets_add_copies_the_value(void **state) {
    w_legacy_targets_t targets = {0};
    char value[] = "10.0.0.1";

    w_legacy_targets_add(&targets, value, false);
    value[0] = 'X';

    assert_int_equal(targets.count, 1);
    assert_string_equal(targets.items[0].value, "10.0.0.1");
    assert_false(targets.items[0].is_endpoint);

    w_legacy_targets_free(&targets);
}

static void test_targets_chosen_is_false_when_empty(void **state) {
    w_legacy_targets_t targets = {0};
    size_t chosen = 7;

    assert_false(w_legacy_targets_chosen(&targets, &chosen));
    assert_int_equal(chosen, 7);
}

static void test_targets_chosen_is_the_last_address(void **state) {
    w_legacy_targets_t targets = {0};
    size_t chosen = 0;

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_add(&targets, "10.0.0.2", false);
    w_legacy_targets_end_block(&targets);

    assert_true(w_legacy_targets_chosen(&targets, &chosen));
    assert_int_equal(chosen, 1);

    w_legacy_targets_free(&targets);
}

/* The first <client> block that names a manager decides it, as in 5.0.0. */
static void test_targets_chosen_ignores_later_blocks(void **state) {
    w_legacy_targets_t targets = {0};
    size_t chosen = 7;

    w_legacy_targets_end_block(&targets);
    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_end_block(&targets);
    w_legacy_targets_add(&targets, "10.0.0.5:8443", true);
    w_legacy_targets_end_block(&targets);

    assert_true(w_legacy_targets_chosen(&targets, &chosen));
    assert_int_equal(chosen, 0);

    w_legacy_targets_free(&targets);
}

/* An <endpoint> carries the whole target, so it wins over an <address> written after it. */
static void test_targets_chosen_prefers_the_last_endpoint_wherever_it_is(void **state) {
    w_legacy_targets_t targets = {0};
    size_t chosen = 0;

    w_legacy_targets_add(&targets, "10.0.0.5", true);
    w_legacy_targets_add(&targets, "10.0.0.6:8443", true);
    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_end_block(&targets);

    assert_true(w_legacy_targets_chosen(&targets, &chosen));
    assert_int_equal(chosen, 1);

    w_legacy_targets_free(&targets);
}

static void add_values(w_legacy_targets_t *targets, const char **values) {
    for (int i = 0; values[i]; i++) {
        w_legacy_targets_add(targets, values[i], false);
    }
}

static void assert_quoted(const char **values, const char *except, const char *expected) {
    w_legacy_targets_t targets = {0};
    char *list = NULL;

    add_values(&targets, values);
    list = w_legacy_targets_quote(&targets, except);

    if (expected) {
        assert_string_equal(list, expected);
    } else {
        assert_null(list);
    }

    os_free(list);
    w_legacy_targets_free(&targets);
}

static void test_quote_is_null_without_targets(void **state) {
    const char *values[] = { NULL };

    assert_quoted(values, NULL, NULL);
}

static void test_quote_names_every_value_as_written(void **state) {
    const char *values[] = { "192.0.2.10", "wazuh-server", NULL };

    assert_quoted(values, NULL, "'192.0.2.10', 'wazuh-server'");
}

static void test_quote_leaves_out_the_value_in_use(void **state) {
    const char *values[] = { "192.0.2.10", "wazuh-server", NULL };

    assert_quoted(values, "wazuh-server", "'192.0.2.10'");
}

static void test_quote_names_a_repeated_value_once(void **state) {
    const char *values[] = { "10.0.0.1", "10.0.0.2", "10.0.0.1", NULL };

    assert_quoted(values, NULL, "'10.0.0.1', '10.0.0.2'");
}

static void test_quote_is_null_when_only_the_value_in_use_is_left(void **state) {
    const char *values[] = { "10.0.0.1", "10.0.0.1", NULL };

    assert_quoted(values, "10.0.0.1", NULL);
}

static void test_quote_names_an_empty_value(void **state) {
    const char *values[] = { "", "10.0.0.1", NULL };

    assert_quoted(values, "10.0.0.1", "''");
}

static void test_targets_free_resets_the_list(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_end_block(&targets);
    w_legacy_targets_free(&targets);

    assert_null(targets.items);
    assert_int_equal(targets.count, 0);
    assert_int_equal(targets.first_block, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_targets_add_copies_the_value),
        cmocka_unit_test(test_targets_chosen_is_false_when_empty),
        cmocka_unit_test(test_targets_chosen_is_the_last_address),
        cmocka_unit_test(test_targets_chosen_ignores_later_blocks),
        cmocka_unit_test(test_targets_chosen_prefers_the_last_endpoint_wherever_it_is),
        cmocka_unit_test(test_quote_is_null_without_targets),
        cmocka_unit_test(test_quote_names_every_value_as_written),
        cmocka_unit_test(test_quote_leaves_out_the_value_in_use),
        cmocka_unit_test(test_quote_names_a_repeated_value_once),
        cmocka_unit_test(test_quote_is_null_when_only_the_value_in_use_is_left),
        cmocka_unit_test(test_quote_names_an_empty_value),
        cmocka_unit_test(test_targets_free_resets_the_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
