/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef FIM_DB_WRAPPERS_H
#define FIM_DB_WRAPPERS_H

#include "../../../../syscheckd/include/syscheck.h"
#include "../../../../syscheckd/src/db/include/fimCommonDefs.h"

int __wrap_fim_db_get_checksum_range(fdb_t *fim_sql,
                                     fim_type type,
                                     const char *start,
                                     const char *top,
                                     int n,
                                     EVP_MD_CTX *ctx_left,
                                     EVP_MD_CTX *ctx_right,
                                     char **str_pathlh,
                                     char **str_pathuh);

int __wrap_fim_db_get_count_file_entry();

int __wrap_fim_db_get_count_registry_data();

int __wrap_fim_db_get_count_registry_key();

int __wrap_fim_db_get_count_range(fdb_t *fim_sql,
                                  fim_type type,
                                  char *start,
                                  char *top,
                                  int *count);

FIMDBErrorCode __wrap_fim_db_get_path(const char *file_path, callback_context_t callback);
void expect_fim_db_get_path(const char* path, int ret_val);

FIMDBErrorCode __wrap_fim_db_init(int storage,
                                  int sync_interval,
                                  uint32_t sync_max_interval,
                                  uint32_t sync_response_timeout,
                                  fim_sync_callback_t sync_callback,
                                  logging_callback_t log_callback,
                                  int file_limit,
                                  int value_limit,
                                  int sync_registry_enable,
                                  int sync_thread_pool,
                                  int sync_queue_size);

void expect_wrapper_fim_db_init(int storage,
                                int sync_interval,
                                uint32_t sync_max_interval,
                                uint32_t sync_response_timeout,
                                int file_limit,
                                int value_limit,
                                int sync_registry_enable,
                                int sync_thread_pool,
                                int sync_queue_size);

FIMDBErrorCode __wrap_fim_db_remove_path(const char *path);

int __wrap_fim_db_read_line_from_file(fim_tmp_file *file, int storage, int it, char **buffer);

void __wrap_fim_db_clean_file(fim_tmp_file **file, int storage);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_get_count_file_entry
 */
void expect_wrapper_fim_db_get_count_file_entry(int ret);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_remove_path
 */
void expect_fim_db_remove_path(const char *path, int ret_val);

FIMDBErrorCode __wrap_fim_db_file_update(fim_entry* new, callback_context_t callback);

FIMDBErrorCode __wrap_fim_db_file_pattern_search(const char* pattern,
                                      __attribute__((unused)) callback_context_t callback);

void expect_fim_db_file_pattern_search(const char* pattern, int ret_val);

FIMDBErrorCode __wrap_fim_db_file_inode_search(const unsigned long inode,
                                    const unsigned long dev,
                                    __attribute__((unused)) callback_context_t callback);
void expect_fim_db_file_inode_search(const unsigned long inode,
                                     const unsigned long dev,
                                     int ret_val);

int __wrap_fim_db_get_count_file_inode();

void __wrap_fim_run_integrity();

void __wrap_is_fim_shutdown();

void __wrap_fim_db_teardown();

void __wrap__imp__dbsync_initialize();

void __wrap__imp__rsync_initialize();

#endif
