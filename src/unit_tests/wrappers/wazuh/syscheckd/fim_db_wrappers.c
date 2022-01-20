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

int __wrap_fim_db_get_count_file_entry(__attribute__((unused)) fdb_t * fim_sql){
    return mock();
}

fim_entry *__wrap_fim_db_get_path(fdb_t *fim_sql,
                                  const char *file_path) {
    check_expected_ptr(fim_sql);
    check_expected(file_path);

    return mock_type(fim_entry*);
}

void __wrap_fim_db_init(int storage,
                        int sync_interval,
                        __attribute__((unused)) fim_sync_callback_t sync_callback,
                        __attribute__((unused)) logging_callback_t log_callback,
                        int file_limit,
                        int value_limit,
                        bool is_windows
                        ) {
    check_expected(storage);
    check_expected(sync_interval);
    check_expected(file_limit);
    check_expected(value_limit);
    check_expected(is_windows);
}

void expect_wrapper_fim_db_init(int storage,
                                int sync_interval,
                                int file_limit,
                                int value_limit,
                                bool is_windows) {
    expect_value(__wrap_fim_db_init, storage, storage);
    expect_value(__wrap_fim_db_init, sync_interval, sync_interval);
    expect_value(__wrap_fim_db_init, file_limit, file_limit);
    expect_value(__wrap_fim_db_init, value_limit, value_limit);
    expect_value(__wrap_fim_db_init, is_windows, is_windows);
}

int __wrap_fim_db_process_missing_entry(fdb_t *fim_sql,
                                        fim_tmp_file *file,
                                        __attribute__((unused)) pthread_mutex_t *mutex,
                                        int storage,
                                        __attribute__((unused)) event_data_t *evt_data) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(file);
    check_expected_ptr(storage);

    return mock();
}

int __wrap_fim_db_remove_path(char *path) {
    check_expected(path);
    return mock_type(int);
}

int __wrap_fim_db_sync_path_range(fdb_t *fim_sql,
                                  __attribute__((unused)) pthread_mutex_t *mutex,
                                  __attribute__((unused)) fim_tmp_file *file,
                                  __attribute__((unused)) int storage) {
    check_expected_ptr(fim_sql);

    return mock();
}

int __wrap_fim_db_get_count_entries(fdb_t *fim_sql) {
    check_expected_ptr(fim_sql);
    return mock();
}

#ifndef WIN32
fim_entry *__wrap_fim_db_get_entry_from_sync_msg(fdb_t *fim_sql,
                                                 __attribute__((unused)) fim_type type,
                                                 const char *path) {
    check_expected_ptr(fim_sql);
    check_expected(path);

    return mock_type(fim_entry *);
}

#else
fim_entry *__wrap_fim_db_get_entry_from_sync_msg(fdb_t *fim_sql, fim_type type, const char *path) {
    check_expected_ptr(fim_sql);
    check_expected(type);
    check_expected(path);

    return mock_type(fim_entry *);
}
#endif

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

void expect_wrapper_fim_db_get_count_entries(const fdb_t *db, int ret) {
    expect_value(__wrap_fim_db_get_count_entries, fim_sql, db);
    will_return(__wrap_fim_db_get_count_entries, ret);
}

void expect_fim_db_remove_path(char *path, int ret_val) {
    expect_string(__wrap_fim_db_remove_path, path, path);
    will_return(__wrap_fim_db_remove_path, ret_val);
}

int __wrap_fim_db_file_update(fdb_t *fim_sql,
                              const char *path,
                              const __attribute__((unused)) fim_file_data *data,
                              fim_entry **saved) {
    check_expected_ptr(fim_sql);
    check_expected(path);

    if (saved != NULL) {
        *saved = mock_type(fim_entry *);
    }

    return mock();
}

int __wrap_fim_db_file_pattern_search(const char* pattern,
                                      __attribute__((unused)) callback_context_t callback) {
    check_expected(pattern);

    return mock();
}

void expect_fim_db_file_pattern_search(const char* pattern, int ret_val) {
    expect_string(__wrap_fim_db_file_pattern_search, pattern, pattern);
    will_return(__wrap_fim_db_file_pattern_search, ret_val);
}

int __wrap_fim_db_file_inode_search(const unsigned long inode,
                                    const unsigned long dev,
                                    __attribute__((unused)) callback_context_t callback) {
    check_expected(inode);
    check_expected(dev);
}

void expect_fim_db_file_inode_search(const unsigned long inode,
                                     const unsigned long dev) {
    expect_value(__wrap_fim_db_file_inode_search, inode, inode);
    expect_value(__wrap_fim_db_file_inode_search, dev, dev);
}

int __wrap_fim_db_get_count_file_inode() {
    return mock();
}

void __wrap_fim_run_integrity() {
    function_called();
}
