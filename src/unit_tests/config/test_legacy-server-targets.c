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

    assert_true(w_legacy_targets_chosen(&targets, &chosen));
    assert_int_equal(chosen, 1);

    w_legacy_targets_free(&targets);
}

/* An <endpoint> carries the whole target, so it wins over an <address> written after it. */
static void test_targets_chosen_prefers_the_last_endpoint_wherever_it_is(void **state) {
    w_legacy_targets_t targets = {0};
    size_t chosen = 0;

    w_legacy_targets_add(&targets, "10.0.0.5", true);
    w_legacy_targets_add(&targets, "10.0.0.6:8443", true);
    w_legacy_targets_add(&targets, "10.0.0.1", false);

    assert_true(w_legacy_targets_chosen(&targets, &chosen));
    assert_int_equal(chosen, 1);

    w_legacy_targets_free(&targets);
}

static void test_targets_free_resets_the_list(void **state) {
    w_legacy_targets_t targets = {0};

    w_legacy_targets_add(&targets, "10.0.0.1", false);
    w_legacy_targets_free(&targets);

    assert_null(targets.items);
    assert_int_equal(targets.count, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_targets_add_copies_the_value),
        cmocka_unit_test(test_targets_chosen_is_false_when_empty),
        cmocka_unit_test(test_targets_chosen_is_the_last_address),
        cmocka_unit_test(test_targets_chosen_prefers_the_last_endpoint_wherever_it_is),
        cmocka_unit_test(test_targets_free_resets_the_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
