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

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../headers/shared.h"

void test_OSList_GetNext_null_return(void **state) {

    OSList list;
    OSListNode *node = NULL;
    OSListNode *node_returned;

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    node_returned = OSList_GetNext(&list, node);

    assert_null(node_returned);

}

void test_OSList_GetNext_node_return(void **state) {

    OSList list;
    OSListNode node;
    OSListNode *node_returned = NULL;

    node.next = (OSListNode*) malloc(sizeof(OSListNode));

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    node_returned = OSList_GetNext(&list, &node);

    assert_non_null(node_returned);

}

void test_OSList_GetDataFromIndex_null_return(void **state) {

    OSList list;
    int data_index = 0;
    void* data_return;

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    data_return = OSList_GetDataFromIndex(&list, data_index);

    assert_null(data_return);

}

void test_OSList_GetDataFromIndex_data_return(void **state) {

    OSList list;
    int data_index = 0;
    void* data_return;
    char data[5] = "data\0";

    list.first_node = (OSListNode*) malloc(sizeof(OSListNode));
    list.first_node->data = &data;

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    data_return = OSList_GetDataFromIndex(&list, data_index);

    assert_ptr_equal(data_return, list.first_node->data);

}

void test_OSList_InsertData_insert_at_first_position(void **state) {

    OSList list;
    list.first_node = NULL;
    list.last_node = NULL;
    OSListNode *node = NULL;
    void *data = NULL;
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = list.currently_size + 1;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(&list, node, data);

    assert_int_equal(return_code, success_code);
    assert_non_null(list.first_node);
    assert_non_null(list.last_node);
    assert_int_equal(list.currently_size,list_size_after_insertion);

}

void test_OSList_InsertData_insert_at_last_position(void **state) {

    OSList list;
    OSListNode *node = NULL;
    char data[5] = "data\0";
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = 1;

    list.first_node = (OSListNode*) malloc(sizeof(OSListNode));
    list.last_node = list.first_node;
    list.last_node->data = &data;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(&list, node, &data);

    assert_int_equal(return_code, success_code);
    assert_ptr_equal(list.last_node->data, &data);
    assert_int_equal(list.currently_size,list_size_after_insertion);

}

void test_OSList_InsertData_insert_at_first_position_before_node(void **state) {

    OSList list;
    OSListNode *node;
    char data[5] = "data\0";
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = 1;

    node = (OSListNode*) malloc(sizeof(OSListNode));
    list.first_node = node;
    list.last_node = list.first_node;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(&list, node, &data);

    assert_int_equal(return_code, success_code);
    assert_ptr_equal(list.first_node->next, node);
    assert_int_equal(list.currently_size,list_size_after_insertion);

}

void test_OSList_InsertData_insert_at_n_position_before_node(void **state) {

    OSList list;
    OSListNode *node;
    char data[5] = "data\0";
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = 1;

    node = (OSListNode*) malloc(sizeof(OSListNode));
    node->prev = (OSListNode*) malloc(sizeof(OSListNode));
    list.first_node = node->prev;
    list.last_node = node;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(&list, node, &data);

    assert_int_equal(return_code, success_code);
    assert_ptr_equal(list.first_node->next, node->prev);
    assert_int_equal(list.currently_size,list_size_after_insertion);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_OSList_GetNext_null_return),
        cmocka_unit_test(test_OSList_GetNext_node_return),
        cmocka_unit_test(test_OSList_GetDataFromIndex_null_return),
        cmocka_unit_test(test_OSList_GetDataFromIndex_data_return),
        cmocka_unit_test(test_OSList_InsertData_insert_at_first_position),
        cmocka_unit_test(test_OSList_InsertData_insert_at_last_position),
        cmocka_unit_test(test_OSList_InsertData_insert_at_first_position_before_node),
        cmocka_unit_test(test_OSList_InsertData_insert_at_n_position_before_node)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
