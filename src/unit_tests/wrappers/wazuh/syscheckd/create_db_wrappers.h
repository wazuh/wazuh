/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef CREATE_DB_WRAPPERS_H
#define CREATE_DB_WRAPPERS_H

#include "../../../../syscheckd/include/syscheck.h"

void __wrap_fim_checker(const char *path, event_data_t *evt_data, const directory_t *configuration);

directory_t *__wrap_fim_configuration_directory(const char *path);

cJSON *__wrap_fim_json_event();

void __wrap_fim_realtime_event(char *file);

int __wrap_fim_registry_event(char *key, fim_file_data *data, int pos);

int __wrap_fim_whodata_event(whodata_evt * w_evt);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_configuration_directory
 */
void expect_fim_configuration_directory_call(const char *path, directory_t *ret);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_checker
 */
void expect_fim_checker_call(const char *path, const directory_t *configuration);

void __wrap_free_entry(fim_entry *entry);


TXN_HANDLE __wrap_fim_db_transaction_start(const char*, result_callback_t, void*);

int __wrap_fim_db_transaction_sync_row(TXN_HANDLE, const fim_entry*);

void __wrap_fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler,
                                            result_callback_t callback,
                                            void* txn_ctx);
int __wrap_Start_win32_Syscheck();

void __wrap_fim_generate_delete_event();
#endif
