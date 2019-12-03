/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
    char *ret;

    ret = rbtree_insert(tree, "test", value);

    assert_non_null(tree->root);
    assert_ptr_equal(ret, value);
    assert_string_equal(tree->root->key, "test");
    assert_ptr_equal(tree->root->value, value);
}

void test_rbtree_insert_failure(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value = strdup("testing");
    char *ret;

    rbtree_insert(tree, "test", value);
    ret = rbtree_insert(tree, "test", value);

    assert_null(ret);
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

void test_rbtree_get_success(void **state)
{
    (void) state;
    rb_tree *tree = *state;
    char *value_testing = strdup("testing");
    rb_node *ret;

    rbtree_insert(tree, "test", value_testing);

    assert_ptr_equal(rbtree_get(tree, "test"), value_testing);
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

void test_black_depth_success(void **state)
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

void test_black_depth_failure(void **state)
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rbtree_insert_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_insert_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_replace_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_replace_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_get_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_get_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_delete_success, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_delete_failure, create_rbtree_with_dispose, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_minimum, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_maximum, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_keys, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_range, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_black_depth_success, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_black_depth_failure, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_size, create_rbtree, delete_rbtree),
        cmocka_unit_test_setup_teardown(test_rbtree_empty, create_rbtree, delete_rbtree),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
