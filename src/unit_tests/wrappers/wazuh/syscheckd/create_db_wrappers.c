/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "create_db_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_fim_checker(const char *path, event_data_t *evt_data, const directory_t *configuration) {
    check_expected(path);
    check_expected(evt_data);
    check_expected(configuration);
}

directory_t *__wrap_fim_configuration_directory(const char *path) {
    check_expected(path);
    return mock_type(directory_t *);
}

cJSON *__wrap_fim_json_event() {
    return mock_type(cJSON *);
}

void __wrap_fim_realtime_event(char *file) {
    check_expected(file);
}

int __wrap_fim_registry_event(__attribute__((unused)) char *key,
                              __attribute__((unused)) fim_file_data *data,
                              __attribute__((unused)) int pos) {
    return mock();
}

int __wrap_fim_whodata_event(whodata_evt * w_evt)
{
    if (w_evt->process_id) check_expected(w_evt->process_id);
    if (w_evt->user_id) check_expected(w_evt->user_id);
    if (w_evt->process_name) check_expected(w_evt->process_name);
    if (w_evt->path) check_expected(w_evt->path);
#ifndef WIN32
    if (w_evt->group_id) check_expected(w_evt->group_id);
    if (w_evt->audit_uid) check_expected(w_evt->audit_uid);
    if (w_evt->effective_uid) check_expected(w_evt->effective_uid);
    if (w_evt->inode) check_expected(w_evt->inode);
    if (w_evt->ppid) check_expected(w_evt->ppid);
#endif
    return 1;
}

void expect_fim_checker_call(const char *path, const directory_t *configuration) {
    expect_string(__wrap_fim_checker, path, path);
    expect_any(__wrap_fim_checker, evt_data);
    expect_value(__wrap_fim_checker, configuration, configuration);
}

void expect_fim_configuration_directory_call(const char *path, directory_t *ret) {
    expect_string(__wrap_fim_configuration_directory, path, path);
    will_return(__wrap_fim_configuration_directory, ret);
}

void __wrap_free_entry(__attribute__((unused)) fim_entry *entry) {
    return;
}

void __wrap_fim_db_transaction_deleted_rows(__attribute__((unused))TXN_HANDLE txn_handler,
                                            __attribute__((unused))result_callback_t callback,
                                            __attribute__((unused))void* txn_ctx) {
    function_called();
}

int __wrap_fim_db_transaction_sync_row(__attribute__((unused))TXN_HANDLE txn_handler, __attribute__((unused))const fim_entry* entry){
    return mock_type(int);
}

TXN_HANDLE __wrap_fim_db_transaction_start(__attribute__((unused))const char* table,
                                           __attribute__((unused))result_callback_t row_callback,
                                           __attribute__((unused))void *user_data){
    return mock_type(TXN_HANDLE);
}

int __wrap_Start_win32_Syscheck() {
    function_called();
    return mock();
}

void __wrap_fim_generate_delete_event(){
    function_called();
}
