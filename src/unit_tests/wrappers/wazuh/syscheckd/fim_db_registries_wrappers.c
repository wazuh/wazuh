/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software {} you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifdef WIN32
#include "fim_db_registries_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_fim_db_remove_registry_value_data(fdb_t *fim_sql,
                                             fim_registry_value_data *entry) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(entry);
    return mock();
}

int __wrap_fim_db_get_values_from_registry_key(fdb_t *fim_sql,
                                               fim_tmp_file **file,
                                               int storage,
                                               __attribute__((unused)) unsigned long int key_id) {
    check_expected_ptr(fim_sql);
    *file = mock_type(fim_tmp_file *);
    check_expected(storage);

    return mock();
}

int __wrap_fim_db_process_read_registry_data_file(__attribute__((unused)) fdb_t *fim_sql,
                                                  __attribute__((unused)) fim_tmp_file *file,
                                                  __attribute__((unused)) pthread_mutex_t *mutex,
                                                  __attribute__((unused)) void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                                  __attribute__((unused)) int storage,
                                                  __attribute__((unused)) void *alert,
                                                  __attribute__((unused)) void *mode,
                                                  __attribute__((unused)) void *w_evt) {
    return mock();
}

int __wrap_fim_db_remove_registry_key(fdb_t *fim_sql,
                                      fim_entry *entry) {
    check_expected_ptr(fim_sql);
    check_expected_ptr(entry);
    return mock();
}

int __wrap_fim_db_get_registry_keys_not_scanned(__attribute__((unused)) fdb_t *fim_sql,
                                                fim_tmp_file **file,
                                                __attribute__((unused)) int storage) {
    *file = mock_type(fim_tmp_file *);
    return mock();
}

int __wrap_fim_db_get_registry_data_not_scanned(__attribute__((unused)) fdb_t *fim_sql,
                                                fim_tmp_file **file,
                                                __attribute__((unused)) int storage) {
    *file = mock_type(fim_tmp_file *);
    return mock();
}


fim_registry_value_data *__wrap_fim_db_get_registry_data(__attribute__((unused)) fdb_t *fim_sql,
                                                         __attribute__((unused)) unsigned int key_id,
                                                         __attribute__((unused)) const char *name) {
    return mock_type(fim_registry_value_data *);
}

int __wrap_fim_db_insert_registry_data(__attribute__((unused)) fdb_t *fim_sql,
                                       __attribute__((unused)) fim_registry_value_data *data,
                                       __attribute__((unused)) unsigned int key_id,
                                       __attribute__((unused)) unsigned int replace_entry) {
    return mock();
}

int __wrap_fim_db_set_registry_data_scanned(__attribute__((unused)) fdb_t *fim_sql,
                                            __attribute__((unused)) const char *name,
                                            __attribute__((unused)) unsigned int key_id) {
    return FIMDB_OK;
}

int __wrap_fim_db_get_registry_key_rowid(__attribute__((unused)) fdb_t *fim_sql,
                                         __attribute__((unused)) const char *path,
                                         __attribute__((unused)) unsigned int arch,
                                         __attribute__((unused)) unsigned int *rowid) {
    return mock();
}

fim_registry_key *__wrap_fim_db_get_registry_key(__attribute__((unused)) fdb_t *fim_sql,
                                                 __attribute__((unused)) const char *path,
                                                 __attribute__((unused)) unsigned int arch) {
    return mock_type(fim_registry_key *);
}

int __wrap_fim_db_insert_registry_key(__attribute__((unused)) fdb_t *fim_sql,
                                      __attribute__((unused)) fim_registry_key *entry,
                                      __attribute__((unused)) unsigned int rowid) {
    return mock();
}

int __wrap_fim_db_set_registry_key_scanned(__attribute__((unused)) fdb_t *fim_sql,
                                           __attribute__((unused)) const char *path,
                                           __attribute__((unused)) unsigned int arch) {
    return FIMDB_OK;
}

int __wrap_fim_db_set_all_registry_data_unscanned(__attribute__((unused)) fdb_t *fim_sql) {
    return FIMDB_OK;
}

int __wrap_fim_db_set_all_registry_key_unscanned(__attribute__((unused)) fdb_t *fim_sql) {
    return FIMDB_OK;
}

void expect_fim_db_get_values_from_registry_key_call(fdb_t *fim_sql,
                                                     fim_tmp_file *file,
                                                     int storage,
                                                     int ret) {

    expect_value(__wrap_fim_db_get_values_from_registry_key, fim_sql, fim_sql);
    will_return(__wrap_fim_db_get_values_from_registry_key, file);
    expect_value(__wrap_fim_db_get_values_from_registry_key, storage, storage);
    will_return(__wrap_fim_db_get_values_from_registry_key, ret);
}

void expect_fim_db_remove_registry_key_call(fdb_t *fim_sql, fim_entry *entry, int ret) {
    expect_value(__wrap_fim_db_remove_registry_key, fim_sql, fim_sql);
    expect_value(__wrap_fim_db_remove_registry_key, entry, entry);
    will_return(__wrap_fim_db_remove_registry_key, ret);
}

void expect_fim_db_remove_registry_value_data_call(fdb_t *fim_sql, fim_registry_value_data *entry, int ret) {
    expect_value(__wrap_fim_db_remove_registry_value_data, fim_sql, fim_sql);
    expect_value(__wrap_fim_db_remove_registry_value_data, entry, entry);
    will_return(__wrap_fim_db_remove_registry_value_data, ret);
}

#endif // WIN32
