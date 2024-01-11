/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "fim_db_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_fim_db_get_count_file_entry(){
    return mock();
}

int __wrap_fim_db_get_count_registry_data(){
    return mock();
}

int __wrap_fim_db_get_count_registry_key(){
    return mock();
}

FIMDBErrorCode __wrap_fim_db_get_path(const char* file_path,
                                     __attribute__((unused))callback_context_t callback) {
    check_expected(file_path);

    return mock();
}

void expect_fim_db_get_path(const char* path, int ret_val) {
    expect_value(__wrap_fim_db_get_path, file_path, path);
    will_return(__wrap_fim_db_get_path, ret_val);
}

FIMDBErrorCode __wrap_fim_db_init(int storage,
                                  int sync_interval,
                                  uint32_t sync_max_interval,
                                  uint32_t sync_response_timeout,
                                  __attribute__((unused)) fim_sync_callback_t sync_callback,
                                  __attribute__((unused)) logging_callback_t log_callback,
                                  int file_limit,
                                  int value_limit,
                                  int sync_registry_enable,
                                  int sync_thread_pool,
                                  int sync_queue_size) {
    check_expected(storage);
    check_expected(sync_interval);
    check_expected(sync_max_interval);
    check_expected(sync_response_timeout);
    check_expected(file_limit);
    check_expected(value_limit);
    check_expected(sync_registry_enable);
    check_expected(sync_thread_pool);
    check_expected(sync_queue_size);

    return mock_type(int);
}

void expect_wrapper_fim_db_init(int storage,
                                int sync_interval,
                                uint32_t sync_max_interval,
                                uint32_t sync_response_timeout,
                                int file_limit,
                                int value_limit,
                                int sync_registry_enable,
                                int sync_thread_pool,
                                int sync_queue_size) {
    expect_value(__wrap_fim_db_init, storage, storage);
    expect_value(__wrap_fim_db_init, sync_interval, sync_interval);
    expect_value(__wrap_fim_db_init, file_limit, file_limit);
    expect_value(__wrap_fim_db_init, sync_response_timeout, sync_response_timeout);
    expect_value(__wrap_fim_db_init, sync_max_interval, sync_max_interval);
    expect_value(__wrap_fim_db_init, value_limit, value_limit);
    expect_value(__wrap_fim_db_init, sync_registry_enable, sync_registry_enable);
    expect_value(__wrap_fim_db_init, sync_thread_pool, sync_thread_pool);
    expect_value(__wrap_fim_db_init, sync_queue_size, sync_queue_size);

    will_return(__wrap_fim_db_init, FIMDB_OK);
}

FIMDBErrorCode __wrap_fim_db_remove_path(const char *path) {
    check_expected(path);

    return mock_type(int);
}

int __wrap_fim_db_read_line_from_file(fim_tmp_file *file, int storage, int it, char **buffer) {
    check_expected_ptr(file);
    check_expected(storage);
    check_expected(it);

    *buffer = mock_type(char *);

    return mock();
}

void __wrap_fim_db_clean_file(fim_tmp_file **file, int storage) {
    check_expected_ptr(file);
    check_expected(storage);
}

void expect_wrapper_fim_db_get_count_file_entry(int ret) {
    will_return(__wrap_fim_db_get_count_file_entry, ret);
}

void expect_fim_db_remove_path(const char *path, int ret_val) {
    expect_string(__wrap_fim_db_remove_path, path, path);
    will_return(__wrap_fim_db_remove_path, ret_val);
}

FIMDBErrorCode __wrap_fim_db_file_update(__attribute__((unused)) fim_entry* new,
                              __attribute__((unused)) callback_context_t callback)
{
    return mock_type(int);
}

FIMDBErrorCode __wrap_fim_db_file_pattern_search(const char* pattern,
                                      __attribute__((unused)) callback_context_t callback) {
    check_expected(pattern);

    return mock();
}

void expect_fim_db_file_pattern_search(const char* pattern, int ret_val) {
    expect_string(__wrap_fim_db_file_pattern_search, pattern, pattern);
    will_return(__wrap_fim_db_file_pattern_search, ret_val);
}

FIMDBErrorCode __wrap_fim_db_file_inode_search(const unsigned long inode,
                                    const unsigned long dev,
                                    __attribute__((unused)) callback_context_t callback) {
    check_expected(inode);
    check_expected(dev);
    return mock_type(int);
}

void expect_fim_db_file_inode_search(const unsigned long inode,
                                     const unsigned long dev,
                                     int retval) {
    expect_value(__wrap_fim_db_file_inode_search, inode, inode);
    expect_value(__wrap_fim_db_file_inode_search, dev, dev);
    will_return(__wrap_fim_db_file_inode_search, retval);
}

int __wrap_fim_db_get_count_file_inode() {
    return mock();
}

void __wrap_fim_run_integrity() {
    function_called();
}

void __wrap_is_fim_shutdown() {
    function_called();
}

void __wrap_fim_db_teardown() {
    function_called();
}

void __wrap__imp__dbsync_initialize() {
    function_called();
}

void __wrap__imp__rsync_initialize() {
    function_called();
}
