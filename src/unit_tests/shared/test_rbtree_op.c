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
#include <stdlib.h>

#include "../headers/rbtree_op.h"

/* setup/teardowns */

static int create_rbtree(void **state)
{
    rb_tree *tree = rbtree_init();
    *state = tree;
    return 0;
}

static int create_rbtree_with_dispose(void **state)
{
    rb_tree *tree = rbtree_init();

    rbtree_set_dispose(tree, free);

    *state = tree;
    return 0;
}

static int delete_rbtree(void **state)
{
    rb_tree *tree = *state;
    rbtree_destroy(tree);
    return 0;
}

/* tests */

void test_rbtree_insert_success(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("testing");
    rb_node *ret;

    ret = rbtree_insert(tree, "test", value);

    assert_non_null(tree->root);
    assert_non_null(ret);
    assert_ptr_equal(ret->value, value);
    assert_string_equal(tree->root->key, "test");
    assert_ptr_equal(tree->root->value, value);
}

void test_rbtree_insert_failure(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("testing");
    rb_node *ret;

    rbtree_insert(tree, "test", value);
    ret = rbtree_insert(tree, "test", value);

    assert_null(ret);
}

void test_rbtree_insert_null_tree(void **state)
{
    (void) state;
    char *value = strdup("testing");

    expect_assert_failure(rbtree_insert(NULL, "test", value));

    free(value);
}

void test_rbtree_insert_null_key(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("testing");

    expect_assert_failure(rbtree_insert(tree, NULL, value));

    free(value);
}

void test_rbtree_insert_null_value(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = NULL;
    rb_node *ret;

    ret = rbtree_insert(tree, "test", NULL);

    assert_non_null(ret);
    assert_non_null(tree->root);
    assert_string_equal(tree->root->key, "test");
    assert_ptr_equal(tree->root->value, value);
}

void test_rbtree_replace_success(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_testing = strdup("testing");
    char *value_replaced = strdup("replaced");
    char *ret;

    rbtree_insert(tree, "test", value_testing);
    ret = rbtree_replace(tree, "test", value_replaced);

    assert_ptr_equal(ret, value_replaced);
    assert_string_equal(tree->root->key, "test");
    assert_ptr_equal(tree->root->value, value_replaced);
}


void test_rbtree_replace_failure(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_testing = strdup("testing");
    char *ret;

    rbtree_insert(tree, "test", value_testing);
    ret = rbtree_replace(tree, "invalid", value_testing);

    assert_null(ret);
    assert_string_equal(tree->root->key, "test");
    assert_ptr_equal(tree->root->value, value_testing);
}

void test_rbtree_replace_null_tree(void **state)
{
    (void) state;
    char *value_testing = strdup("testing");

    expect_assert_failure(rbtree_replace(NULL, "invalid", value_testing));

    free(value_testing);
}

void test_rbtree_replace_null_key(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_testing = strdup("testing");

    expect_assert_failure(rbtree_replace(tree, NULL, value_testing));

    free(value_testing);
}

void test_rbtree_replace_null_value(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_testing = strdup("testing");
    char *ret;

    rbtree_insert(tree, "test", value_testing);
    ret = rbtree_replace(tree, "test", NULL);

    assert_null(ret);
    assert_string_equal(tree->root->key, "test");
    assert_null(tree->root->value);
}

void test_rbtree_get_success(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_testing = strdup("testing");
    rb_node *ret;

    rbtree_insert(tree, "test", value_testing);

    ret = rbtree_get(tree, "test");

    assert_ptr_equal(ret, value_testing);
}

void test_rbtree_get_failure(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_testing = strdup("testing");
    rb_node *ret;

    rbtree_insert(tree, "test", value_testing);
    ret = rbtree_get(tree, "invalid");

    assert_null(ret);
}

void test_rbtree_get_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_get(NULL, "invalid"));
}

void test_rbtree_get_null_key(void **state)
{
    (void) state;
    rb_tree *tree = *state;

    expect_assert_failure(rbtree_get(tree, NULL));
}


void test_rbtree_delete_success(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_1 = strdup("value_1");
    char *value_2 = strdup("value_2");
    char *value_3 = strdup("value_3");

    rbtree_insert(tree, "test_1", value_1);
    rbtree_insert(tree, "test_2", value_2);
    rbtree_insert(tree, "test_3", value_3);

    assert_int_equal(rbtree_delete(tree, "test_1"), 1);
    assert_null(rbtree_get(tree, "test_1"));
    assert_int_equal(rbtree_delete(tree, "test_2"), 1);
    assert_null(rbtree_get(tree, "test_2"));
    assert_int_equal(rbtree_delete(tree, "test_3"), 1);
    assert_null(rbtree_get(tree, "test_3"));
}

void test_rbtree_delete_failure(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");

    rbtree_insert(tree, "test", value);

    assert_int_equal(rbtree_delete(tree, "invalid"), 0);
}

void test_rbtree_delete_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_delete(NULL, "invalid"));
}

void test_rbtree_delete_null_key(void **state)
{
    (void) state;
    rb_tree *tree = *state;

    expect_assert_failure(rbtree_delete(tree, NULL));
}

void test_rbtree_minimum(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    const char *ret;

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "-key", value);
    rbtree_insert(tree, "9key", value);
    rbtree_insert(tree, "Z_key", value);

    ret = rbtree_minimum(tree);
    free(value);
    assert_string_equal(ret, "-key");
}

void test_rbtree_minimum_empty_tree(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    const char *ret;

    ret = rbtree_minimum(tree);
    assert_null(ret);
}

void test_rbtree_minimum_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_minimum(NULL));
}

void test_rbtree_maximum(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    const char *ret;

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "-key", value);
    rbtree_insert(tree, "9key", value);
    rbtree_insert(tree, "Z_key", value);

    ret = rbtree_maximum(tree);
    free(value);
    assert_string_equal(ret, "a_key");
}

void test_rbtree_maximum_empty_tree(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    const char *ret;

    ret = rbtree_maximum(tree);
    assert_null(ret);
}

void test_rbtree_maximum_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_maximum(NULL));
}

void test_rbtree_keys(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    char ** ret = NULL;
    char expected_ret[32];
    int i;

    rbtree_insert(tree, "key1", value);
    rbtree_insert(tree, "key2", value);
    rbtree_insert(tree, "key3", value);
    rbtree_insert(tree, "key4", value);

    ret = rbtree_keys(tree);
    free(value);

    for(i = 0; ret[i]; i++) {
        assert_non_null(ret[i]);

        snprintf(expected_ret, 32, "key%d", (i + 1));
        assert_string_equal(ret[i], expected_ret);

        free(ret[i]);
    }

    free(ret[i]);
    free(ret);

    assert_int_equal(i, 4);
}

void test_rbtree_keys_empty_tree(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char ** ret = NULL;

    ret = rbtree_keys(tree);

    assert_null(*ret);
    assert_non_null(ret);

    free(ret);
}

void test_rbtree_keys_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_keys(NULL));
}

void test_rbtree_range(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    char expected_ret[32];
    char ** ret = NULL;
    int i;

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "b_key", value);
    rbtree_insert(tree, "c_key", value);
    rbtree_insert(tree, "d_key", value);
    rbtree_insert(tree, "e_key", value);

    ret = rbtree_range(tree, "b_key", "d_key");
    free(value);

    for(i = 0; ret[i]; i++) {
        assert_non_null(ret[i]);

        snprintf(expected_ret, 32, "%c_key", (i + 'b'));
        assert_string_equal(ret[i], expected_ret);

        free(ret[i]);
    }

    assert_int_equal(i, 3);

    free(ret[i]);
    free(ret);
}

void test_rbtree_range_empty_tree(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char ** ret = NULL;

    ret = rbtree_range(tree, "b_key", "d_key");

    assert_non_null(ret);
    assert_null(*ret);
    free(ret);
}

void test_rbtree_range_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_range(NULL, "b_key", "d_key"));
}

void test_rbtree_range_min_not_in_tree(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    char expected_ret[32];
    char ** ret = NULL;
    int i;

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "b_key", value);
    rbtree_insert(tree, "c_key", value);
    rbtree_insert(tree, "d_key", value);
    rbtree_insert(tree, "e_key", value);

    ret = rbtree_range(tree, "__key", "d_key");
    free(value);

    for(i = 0; ret[i]; i++) {
        assert_non_null(ret[i]);

        snprintf(expected_ret, 32, "%c_key", (i + 'a'));
        assert_string_equal(ret[i], expected_ret);

        free(ret[i]);
    }

    assert_int_equal(i, 4);

    free(ret[i]);
    free(ret);
}

void test_rbtree_range_null_min(void **state)
{
    (void) state;
    rb_tree *tree = *state;

    expect_assert_failure(rbtree_range(tree, NULL, "d_key"));
}

void test_rbtree_range_max_not_in_tree(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    char expected_ret[32];
    char ** ret = NULL;
    int i;

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "b_key", value);
    rbtree_insert(tree, "c_key", value);
    rbtree_insert(tree, "d_key", value);
    rbtree_insert(tree, "e_key", value);

    ret = rbtree_range(tree, "b_key", "z_key");
    free(value);

    for(i = 0; ret[i]; i++) {
        assert_non_null(ret[i]);

        snprintf(expected_ret, 32, "%c_key", (i + 'b'));
        assert_string_equal(ret[i], expected_ret);

        free(ret[i]);
    }

    assert_int_equal(i, 4);

    free(ret[i]);
    free(ret);
}

void test_rbtree_range_null_max(void **state)
{
    (void) state;
    rb_tree *tree = *state;

    expect_assert_failure(rbtree_range(tree, "b_key", NULL));
}

void test_rbtree_black_depth_success(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    int ret;

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "b_key", value);

    ret = rbtree_black_depth(tree);
    free(value);

    assert_int_equal(ret, 1);
}

void test_rbtree_black_depth_failure(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    int ret;

    ret = rbtree_black_depth(tree);
    assert_int_equal(ret, 0);

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "b_key", value);
    tree->root->color = RB_RED;

    ret = rbtree_black_depth(tree);
    free(value);

    assert_int_equal(ret, -1);
}

void test_rbtree_black_depth_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_black_depth(NULL));
}

void test_rbtree_size(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    int ret;

    ret = rbtree_size(tree);
    assert_int_equal(ret, 0);

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "b_key", value);
    rbtree_insert(tree, "c_key", value);
    rbtree_insert(tree, "d_key", value);
    rbtree_insert(tree, "e_key", value);

    ret = rbtree_size(tree);
    free(value);

    assert_int_equal(ret, 5);
}

void test_rbtree_size_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_size(NULL));
}

void test_rbtree_empty(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("value");
    int ret;

    ret = rbtree_empty(tree);
    assert_int_equal(ret, 1);

    rbtree_insert(tree, "a_key", value);
    rbtree_insert(tree, "b_key", value);

    ret = rbtree_empty(tree);
    free(value);

    assert_int_equal(ret, 0);
}

void test_rbtree_empty_null_tree(void **state)
{
    (void) state;

    expect_assert_failure(rbtree_empty(NULL));
}


int main(void) {
    const struct CMUnitTest tests[] = {
        /* rbtree_insert tests */
        cmocka_unit_test_setup_teardown(test_rbtree_insert_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_insert_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_insert_null_tree, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_insert_null_key, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_insert_null_value, create_rbtree_with_dispose, delete_rbtree),

        /* rbtree_replace tests */
        cmocka_unit_test_setup_teardown(test_rbtree_replace_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_replace_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_replace_null_tree, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_replace_null_key, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_replace_null_value, create_rbtree_with_dispose, delete_rbtree),

        /* rbtree_get tests */
        cmocka_unit_test_setup_teardown(test_rbtree_get_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_get_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_get_null_tree, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_get_null_key, create_rbtree_with_dispose, delete_rbtree),

        /* rbtree_delete tests */
        cmocka_unit_test_setup_teardown(test_rbtree_delete_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_delete_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_delete_null_tree, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_delete_null_key, create_rbtree_with_dispose, delete_rbtree),

        /* rbtree_minimum tests */
        cmocka_unit_test_setup_teardown(test_rbtree_minimum, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_minimum_empty_tree, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_minimum_null_tree, create_rbtree, delete_rbtree),

        /* rbtree_minimum tests */
        cmocka_unit_test_setup_teardown(test_rbtree_maximum, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_maximum_empty_tree, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_maximum_null_tree, create_rbtree, delete_rbtree),

        /* rbtree_keys tests */
        cmocka_unit_test_setup_teardown(test_rbtree_keys, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_keys_empty_tree, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_keys_null_tree, create_rbtree, delete_rbtree),

        /* rbtree_range tests */
        cmocka_unit_test_setup_teardown(test_rbtree_range, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_range_null_tree, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_range_min_not_in_tree, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_range_null_min, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_range_max_not_in_tree, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_range_null_max, create_rbtree, delete_rbtree),

        /* rbtree_depth tests */
        cmocka_unit_test_setup_teardown(test_rbtree_black_depth_success, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_black_depth_failure, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_black_depth_null_tree, create_rbtree, delete_rbtree),

        /* rbtree_size tests */
        cmocka_unit_test_setup_teardown(test_rbtree_size, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_size_null_tree, create_rbtree, delete_rbtree),

        /* rbtree_empty tests */
        cmocka_unit_test_setup_teardown(test_rbtree_empty, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_empty_null_tree, create_rbtree, delete_rbtree),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
