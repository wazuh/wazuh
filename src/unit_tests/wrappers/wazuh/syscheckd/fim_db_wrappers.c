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

int __wrap_fim_db_data_checksum_range(fdb_t *fim_sql,
                                      const char *start,
                                      const char *top,
                                      const long id,
                                      const int n,
                                      __attribute__ ((__unused__)) pthread_mutex_t *mutex) {
    check_expected_ptr(fim_sql);
    check_expected(start);
    check_expected(top);
    check_expected(id);
    check_expected(n);

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

int __wrap_fim_db_get_count_entry_path(__attribute__((unused)) fdb_t * fim_sql){
    return mock();
}

int __wrap_fim_db_get_count_range(fdb_t *fim_sql,
                                  char *start,
                                  char *top,
                                  int *count) {
    check_expected_ptr(fim_sql);
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

int __wrap_fim_db_get_path_range(fdb_t *fim_sql,
                                 char *start,
                                 char *top,
                                 fim_tmp_file **file,
                                 int storage) {
    check_expected_ptr(fim_sql);
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
                         __attribute__((unused)) fim_entry_data *entry,
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
