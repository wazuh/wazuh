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

#include "../syscheckd/include/syscheck.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../headers/shared.h"

syscheck_config config;

static int setup_syscheck_dir_links(void **state) {

    config.directories = OSList_Create();
    if (config.directories == NULL) {
        return (1);
    }

    return 0;
}

static int teardown_syscheck_dir_links(void **state) {

    OSListNode *node_it;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if (config.directories) {
        OSList_foreach(node_it, config.directories) {
            free_directory(node_it->data);
            node_it->data = NULL;
        }
        OSList_Destroy(config.directories);
        config.directories = NULL;
    }

    return 0;
}

void free_data_function(void* data){
    free(data);
}

void test_OSList_GetNext_null_return(void **state) {

    OSList *list;
    OSListNode *node = NULL;
    OSListNode *node_returned;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    node_returned = OSList_GetNext(list, node);

    assert_null(node_returned);

}

void test_OSList_GetNext_node_return(void **state) {

    OSList *list = config.directories;
    OSListNode *node;
    OSListNode *node_returned;

    list->first_node = (OSListNode*) malloc(sizeof(OSListNode));
    list->first_node->next = (OSListNode*) malloc(sizeof(OSListNode));
    list->first_node->next->next = NULL;
    node = list->first_node;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_wrlock);

    node_returned = OSList_GetNext(list, node);

    assert_non_null(node_returned);

    OSList_CleanNodes(list);

}

void test_OSList_GetDataFromIndex_null_return(void **state) {

    OSList *list = config.directories;
    int data_index = 0;
    void* data_return;

    list->first_node = NULL;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_rwlock_unlock);

    data_return = OSList_GetDataFromIndex(list, data_index);

    assert_null(data_return);

}

void test_OSList_GetDataFromIndex_data_return(void **state) {

    OSList *list = config.directories;
    int data_index = 0;
    void* data_return;
    char* data = malloc(sizeof(char)*5);

    strncpy (data, "data", 5);
    list->first_node = (OSListNode*) malloc(sizeof(OSListNode));
    list->first_node->next = NULL;
    list->first_node->data = data;
    list->free_data_function = free_data_function;

    expect_function_call(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    expect_function_call(__wrap_pthread_rwlock_wrlock);

    data_return = OSList_GetDataFromIndex(list, data_index);

    assert_ptr_equal(data_return, list->first_node->data);

    OSList_CleanNodes(list);
    list->free_data_function = NULL;
}

void test_OSList_InsertData_insert_at_first_position(void **state) {

    OSList *list = config.directories;
    OSListNode *node = NULL;
    void *data = NULL;
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = 1;

    list->first_node = NULL;
    list->last_node = NULL;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(list, node, data);

    assert_int_equal(return_code, success_code);
    assert_non_null(list->first_node);
    assert_non_null(list->last_node);
    assert_int_equal(list->currently_size,list_size_after_insertion);

    OSList_CleanNodes(list);

}

void test_OSList_InsertData_insert_at_last_position(void **state) {

    OSList *list = config.directories;
    OSListNode *node = NULL;
    char *data = malloc(sizeof(char)*5);
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = 1;

    strncpy (data, "data", 5);
    list->first_node = (OSListNode*) malloc(sizeof(OSListNode));
    list->first_node->next = (OSListNode*) malloc(sizeof(OSListNode));
    list->last_node = list->first_node->next;
    list->last_node->prev = list->first_node;
    list->last_node->next = NULL;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(list, node, data);

    assert_int_equal(return_code, success_code);
    assert_ptr_equal(list->last_node->data, data);
    assert_int_equal(list->currently_size,list_size_after_insertion);

    OSList_CleanNodes(list);
    free(data);
}

void test_OSList_InsertData_insert_at_first_position_before_node(void **state) {

    OSList *list = config.directories;
    OSListNode *node;
    char *data = malloc(sizeof(char)*5);
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = 1;

    strncpy (data, "data", 5);
    list->first_node = (OSListNode*) malloc(sizeof(OSListNode));
    list->last_node = list->first_node;
    list->first_node->prev = NULL;
    list->first_node->next = NULL;
    list->last_node->next = NULL;
    node = list->first_node;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(list, node, &data);

    assert_int_equal(return_code, success_code);
    assert_ptr_equal(list->first_node->next, node);
    assert_int_equal(list->currently_size,list_size_after_insertion);

    OSList_CleanNodes(list);
    free(data);
}

void test_OSList_InsertData_insert_at_n_position_before_node(void **state) {

    OSList *list = config.directories;
    OSListNode *node;
    char *data = malloc(sizeof(char)*5);
    int return_code;
    int success_code = 0;
    int list_size_after_insertion = 1;

    strncpy (data, "data", 5);
    list->first_node = (OSListNode*) malloc(sizeof(OSListNode));
    list->first_node->next = (OSListNode*) malloc(sizeof(OSListNode));
    list->last_node = list->first_node->next;
    list->last_node->next = NULL;
    list->last_node->prev = list->first_node;
    node = list->last_node;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    return_code = OSList_InsertData(list, node, &data);

    assert_int_equal(return_code, success_code);
    assert_ptr_equal(list->first_node->next, node->prev);
    assert_int_equal(list->currently_size,list_size_after_insertion);

    OSList_CleanNodes(list);
    free(data);

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

    return cmocka_run_group_tests(tests, setup_syscheck_dir_links, teardown_syscheck_dir_links);
}
