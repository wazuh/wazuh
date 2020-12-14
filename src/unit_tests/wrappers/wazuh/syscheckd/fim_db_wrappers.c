/* Copyright (C) 2015-2020, Wazuh Inc.
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

int __wrap_fim_db_get_checksum_range(fdb_t *fim_sql,
                                     __attribute__ ((__unused__)) fim_type type,
                                     const char *start,
                                     const char *top,
                                     int n,
                                     __attribute__ ((__unused__)) EVP_MD_CTX *ctx_left,
                                     __attribute__ ((__unused__)) EVP_MD_CTX *ctx_right,
                                     char **str_pathlh,
                                     char **str_pathuh){
    check_expected_ptr(fim_sql);
    check_expected(start);
    check_expected(top);
    check_expected(n);
    *str_pathlh = mock_type(char *);
    *str_pathuh = mock_type(char *);
    return mock();
}

int __wrap_fim_db_delete_not_scanned(fdb_t * fim_sql,
                                     __attribute__ ((__unused__)) fim_tmp_file *file,
                                     __attribute__ ((__unused__)) pthread_mutex_t *mutex,
                                     __attribute__ ((__unused__)) int storage) {
    check_expected_ptr(fim_sql);

    return mock();
}

int __wrap_fim_db_delete_range(fdb_t * fim_sql,
                               fim_tmp_file *file,
                               __attribute__((unused)) pthread_mutex_t *mutex,
                               int storage) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(storage);
    check_expected_ptr(file);

    return mock();
}

int __wrap_fim_db_get_count_file_entry(__attribute__((unused)) fdb_t * fim_sql){
    return mock();
}

int __wrap_fim_db_get_count_range(fdb_t *fim_sql,
                                  fim_type type,
                                  char *start,
                                  char *top,
                                  int *count) {
    check_expected_ptr(fim_sql);
    check_expected(type);
    check_expected(start);
    check_expected(top);

    *count = mock();
    return mock();
}

int __wrap_fim_db_get_data_checksum(fdb_t *fim_sql,
                                    __attribute__((unused)) void * arg) {
    check_expected_ptr(fim_sql);

    return mock();
}

int __wrap_fim_db_get_not_scanned(fdb_t * fim_sql,
                                  fim_tmp_file **file,
                                  int storage) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(storage);

    *file = mock_type(fim_tmp_file *);

    return mock();
}

fim_entry *__wrap_fim_db_get_path(fdb_t *fim_sql,
                                  const char *file_path) {
    check_expected_ptr(fim_sql);
    check_expected(file_path);

    return mock_type(fim_entry*);
}
int __wrap_fim_db_get_last_path(fdb_t * fim_sql, int type, char **path) {
    check_expected_ptr(fim_sql);
    check_expected(type);

    *path = mock_type(char *);

    return mock_type(int);
}

int __wrap_fim_db_get_first_path(fdb_t * fim_sql, int type, char **path) {
    check_expected_ptr(fim_sql);
    check_expected(type);

    *path = mock_type(char *);

    return mock_type(int);
}

int __wrap_fim_db_get_path_range(fdb_t *fim_sql,
                                 fim_type type,
                                 char *start,
                                 char *top,
                                 fim_tmp_file **file,
                                 int storage) {
    check_expected_ptr(fim_sql);
    check_expected(type);
    check_expected(start);
    check_expected(top);
    check_expected(storage);

    *file = mock_type(fim_tmp_file *);

    return mock();
}

char **__wrap_fim_db_get_paths_from_inode(fdb_t *fim_sql,
                                          const unsigned long int inode,
                                          const unsigned long int dev) {
    check_expected_ptr(fim_sql);
    check_expected(inode);
    check_expected(dev);

    return mock_type(char **);
}

int __wrap_fim_db_get_row_path(fdb_t * fim_sql,
                               int mode,
                               char **path) {
    check_expected_ptr(fim_sql);
    check_expected(mode);

    *path = mock_type(char*);

    return mock();
}

fdb_t *__wrap_fim_db_init(int memory) {
    check_expected(memory);
    return mock_type(fdb_t*);
}

int __wrap_fim_db_insert(fdb_t *fim_sql,
                         const char *file_path,
                         __attribute__((unused)) fim_file_data *entry,
                         __attribute__((unused)) int alert_type) {
    check_expected_ptr(fim_sql);
    check_expected(file_path);

    if (activate_full_db) {
        syscheck.database->full = true;
    }

    return mock();
}

int __wrap_fim_db_process_missing_entry(fdb_t *fim_sql,
                                        fim_tmp_file *file,
                                        __attribute__((unused)) pthread_mutex_t *mutex,
                                        int storage,
                                        fim_event_mode mode,
                                        __attribute__((unused)) whodata_evt * w_evt) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(file);
    check_expected_ptr(storage);
    check_expected_ptr(mode);

    return mock();
}

void __wrap_fim_db_remove_path(fdb_t *fim_sql,
                               fim_entry *entry,
                               __attribute__((unused)) void *arg) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(entry);
}

int __wrap_fim_db_set_all_unscanned(fdb_t *fim_sql) {
    check_expected_ptr(fim_sql);

    return mock();
}

int __wrap_fim_db_set_scanned(fdb_t *fim_sql,
                              char *path) {
    check_expected_ptr(fim_sql);
    check_expected(path);

    return mock();
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

void expect_wrapper_fim_db_get_path_range_call(const fdb_t *db,
                                       const char *start_str,
                                       const char *top_str,
                                       int storage,
                                       fim_tmp_file *tmp_file,
                                       int ret) {

    expect_value(__wrap_fim_db_get_path_range, fim_sql, db);
    expect_value(__wrap_fim_db_get_path_range, type, FIM_TYPE_FILE);
    expect_string(__wrap_fim_db_get_path_range, start, start_str);
    expect_string(__wrap_fim_db_get_path_range, top, top_str);
    expect_value(__wrap_fim_db_get_path_range, storage, storage);
    will_return(__wrap_fim_db_get_path_range, tmp_file);
    will_return(__wrap_fim_db_get_path_range, ret);
}

void expect_wrapper_fim_db_delete_range_call(const fdb_t *db, int storage, const fim_tmp_file *file, int ret){
    expect_value(__wrap_fim_db_delete_range, fim_sql, db);
    expect_value(__wrap_fim_db_delete_range, storage, storage);
    expect_memory(__wrap_fim_db_delete_range, file, file, sizeof(file));
    will_return(__wrap_fim_db_delete_range, ret);
}

void expect_wrapper_fim_db_get_count_entries(const fdb_t *db, int ret) {
    expect_value(__wrap_fim_db_get_count_entries, fim_sql, db);
    will_return(__wrap_fim_db_get_count_entries, ret);
}

void expect_wrapper_fim_db_get_paths_from_inode(fdb_t *db, int inode, int dev, char **ret) {
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, db);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, inode);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, dev);
    will_return(__wrap_fim_db_get_paths_from_inode, ret);
}

int __wrap_fim_db_process_read_file(__attribute__((unused)) fdb_t *fim_sql,
                                    __attribute__((unused)) fim_tmp_file *file,
                                    __attribute__((unused)) int type,
                                    __attribute__((unused)) pthread_mutex_t *mutex,
                                    __attribute__((unused)) void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                    __attribute__((unused)) int storage,
                                    __attribute__((unused)) void *alert,
                                    __attribute__((unused)) void *mode,
                                    __attribute__((unused)) void *w_evt) {
    return mock();
}
