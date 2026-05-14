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

#include "../wazuh_db/wdb_pool.h"
#include "../wazuh_db/wdb.h"
#include "../headers/shared.h"
#include "../wrappers/common.h"

extern wdb_pool_t wdb_pool;

/* setup/teardowns */
static int setup_test(void **state) {
    wdb_pool_init();

    for(int i = 1; i<4; i++) {
        char node_name[10];
        snprintf(node_name, 10, "node%d", i);
        wdb_t * node = wdb_init(node_name);
        rbtree_insert(wdb_pool.nodes, node_name, node);
        wdb_pool.size++;
    }

    test_mode = 1;

    return 0;
}

static int setup_test_clean_1(void **state) {
    wdb_pool_init();

    for(int i = 1; i<4; i++) {
        char node_name[10];
        snprintf(node_name, 10, "node%d", i);
        wdb_t * node = wdb_init(node_name);
        if(i != 1) {
            node->refcount++;
            node->db = (sqlite3 *)1;
        }
        rbtree_insert(wdb_pool.nodes, node_name, node);
        wdb_pool.size++;
    }

    test_mode = 1;

    return 0;
}

static int setup_test_clean_2(void **state) {
    wdb_pool_init();

    for(int i = 1; i<4; i++) {
        char node_name[10];
        snprintf(node_name, 10, "node%d", i);
        wdb_t * node = wdb_init(node_name);
        if(i != 2) {
            node->refcount++;
            node->db = (sqlite3 *)1;
        }
        rbtree_insert(wdb_pool.nodes, node_name, node);
        wdb_pool.size++;
    }

    test_mode = 1;

    return 0;
}

static int setup_test_clean_3(void **state) {
    wdb_pool_init();

    for(int i = 1; i<4; i++) {
        char node_name[10];
        snprintf(node_name, 10, "node%d", i);
        wdb_t * node = wdb_init(node_name);
        if(i != 3) {
            node->refcount++;
            node->db = (sqlite3 *)1;
        }
        rbtree_insert(wdb_pool.nodes, node_name, node);
        wdb_pool.size++;
    }

    test_mode = 1;

    return 0;
}

static int teardown_test(void **state) {
    char ** keys = rbtree_keys(wdb_pool.nodes);

    for (int i = 0; keys[i]; i++) {
        wdb_t * node = rbtree_get(wdb_pool.nodes, keys[i]);
        wdb_destroy(node);
        rbtree_delete(wdb_pool.nodes, keys[i]);
        wdb_pool.size--;
    }

    free_strarray(keys);

    rbtree_destroy(wdb_pool.nodes);

    test_mode = 0;
    return 0;
}

static void test_wdb_pool_get_or_create_get(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    // lock node mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    wdb_t * node = wdb_pool_get_or_create("node3");

    assert_string_equal(node->id, "node3");
    char ** keys = rbtree_keys(wdb_pool.nodes);
    assert_string_equal(keys[2], "node3");
    assert_null(keys[3]);
    free_strarray(keys);
}

static void test_wdb_pool_get_or_create_create(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    // lock node mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    wdb_t * node = wdb_pool_get_or_create("node4");

    assert_string_equal(node->id, "node4");
    char ** keys = rbtree_keys(wdb_pool.nodes);
    assert_string_equal(keys[3], "node4");
    free_strarray(keys);
}

static void test_wdb_pool_get_unknown(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    wdb_t * node = wdb_pool_get("node4");

    assert_null(node);
}

static void test_wdb_pool_get_known(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    // lock node mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    wdb_t * node = wdb_pool_get("node3");

    assert_string_equal(node->id, "node3");
}

static void test_wdb_pool_leave_node_null(void **state) {
    wdb_pool_leave(NULL);
}

static void test_wdb_pool_leave_node_no_null(void **state) {
    wdb_t *node = wdb_init("node");
    node->refcount = 1;

    // unlock node mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    wdb_pool_leave(node);

    assert_int_equal(node->refcount, 0);
    wdb_destroy(node);
}

static void test_wdb_pool_keys(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    char **keys = wdb_pool_keys();

    assert_string_equal(keys[0], "node1");
    assert_string_equal(keys[1], "node2");
    assert_string_equal(keys[2], "node3");
    free_strarray(keys);
}

static void test_wdb_pool_clean_all(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    wdb_pool_clean();

    char ** keys = rbtree_keys(wdb_pool.nodes);
    assert_null(keys[0]);
    free_strarray(keys);
}

static void test_wdb_pool_clean_1(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    wdb_pool_clean();

    char ** keys = rbtree_keys(wdb_pool.nodes);
    assert_string_equal(keys[0], "node2");
    assert_string_equal(keys[1], "node3");
    free_strarray(keys);
}

static void test_wdb_pool_clean_2(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    wdb_pool_clean();

    char ** keys = rbtree_keys(wdb_pool.nodes);
    assert_string_equal(keys[0], "node1");
    assert_string_equal(keys[1], "node3");
    free_strarray(keys);
}

static void test_wdb_pool_clean_3(void **state) {
    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    wdb_pool_clean();

    char ** keys = rbtree_keys(wdb_pool.nodes);
    assert_string_equal(keys[0], "node1");
    assert_string_equal(keys[1], "node2");
    free_strarray(keys);
}

static void test_wdb_pool_size(void **state) {
    assert_int_equal(wdb_pool_size(), 3);

    // lock pool mutex
    expect_function_call(__wrap_pthread_mutex_lock);

    // unlock pool mutex
    expect_function_call(__wrap_pthread_mutex_unlock);

    wdb_pool_clean();

    assert_int_equal(wdb_pool_size(), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test wdb_pool_get_or_create
        cmocka_unit_test_setup_teardown(test_wdb_pool_get_or_create_get, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wdb_pool_get_or_create_create, setup_test, teardown_test),
        // Test wdb_pool_get
        cmocka_unit_test_setup_teardown(test_wdb_pool_get_unknown, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wdb_pool_get_known, setup_test, teardown_test),
        // Test wdb_pool_leave
        cmocka_unit_test_setup_teardown(test_wdb_pool_leave_node_null, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wdb_pool_leave_node_no_null, setup_test, teardown_test),
        // Test wdb_pool_keys
        cmocka_unit_test_setup_teardown(test_wdb_pool_keys, setup_test, teardown_test),
        // Test wdb_pool_clean
        cmocka_unit_test_setup_teardown(test_wdb_pool_clean_all, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_wdb_pool_clean_1, setup_test_clean_1, teardown_test),
        cmocka_unit_test_setup_teardown(test_wdb_pool_clean_2, setup_test_clean_2, teardown_test),
        cmocka_unit_test_setup_teardown(test_wdb_pool_clean_3, setup_test_clean_3, teardown_test),
        // Test wdb_pool_size
        cmocka_unit_test_setup_teardown(test_wdb_pool_size, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
