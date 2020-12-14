/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef FIM_DB_WRAPPERS_H
#define FIM_DB_WRAPPERS_H

#include "syscheckd/syscheck.h"

int __wrap_fim_db_get_checksum_range(fdb_t *fim_sql,
                                     fim_type type,
                                     const char *start,
                                     const char *top,
                                     int n,
                                     EVP_MD_CTX *ctx_left,
                                     EVP_MD_CTX *ctx_right,
                                     char **str_pathlh,
                                     char **str_pathuh);

int __wrap_fim_db_delete_not_scanned(fdb_t * fim_sql,
                                     fim_tmp_file *file,
                                     pthread_mutex_t *mutex,
                                     int storage);

int __wrap_fim_db_delete_range(fdb_t * fim_sql,
                               fim_tmp_file *file,
                               pthread_mutex_t *mutex,
                               int storage);

int __wrap_fim_db_get_count_file_entry(fdb_t * fim_sql);

int __wrap_fim_db_get_count_range(fdb_t *fim_sql,
                                  fim_type type,
                                  char *start,
                                  char *top,
                                  int *count);

int __wrap_fim_db_get_data_checksum(fdb_t *fim_sql,
                                    void * arg);

int __wrap_fim_db_get_not_scanned(fdb_t * fim_sql,
                                  fim_tmp_file **file,
                                  int storage);

fim_entry *__wrap_fim_db_get_path(fdb_t *fim_sql,
                                  const char *file_path);

int __wrap_fim_db_get_path_range(fdb_t *fim_sql,
                                 fim_type type,
                                 char *start,
                                 char *top,
                                 fim_tmp_file **file,
                                 int storage);

char **__wrap_fim_db_get_paths_from_inode(fdb_t *fim_sql,
                                          const unsigned long int inode,
                                          const unsigned long int dev);

int __wrap_fim_db_get_row_path(fdb_t * fim_sql,
                               int mode,
                               char **path);

fdb_t *__wrap_fim_db_init(int memory);

int __wrap_fim_db_insert(fdb_t *fim_sql,
                         const char *file_path,
                         fim_file_data *entry,
                         int alert_type);

int __wrap_fim_db_process_missing_entry(fdb_t *fim_sql,
                                        fim_tmp_file *file,
                                        pthread_mutex_t *mutex,
                                        int storage,
                                        fim_event_mode mode,
                                        whodata_evt * w_evt);

void __wrap_fim_db_remove_path(fdb_t *fim_sql,
                               fim_entry *entry,
                               void *arg);

int __wrap_fim_db_set_all_unscanned(fdb_t *fim_sql);

int __wrap_fim_db_set_scanned(fdb_t *fim_sql,
                              char *path);

int __wrap_fim_db_sync_path_range(fdb_t *fim_sql,
                                  pthread_mutex_t *mutex,
                                  fim_tmp_file *file,
                                  int storage);

int __wrap_fim_db_get_count_entries(fdb_t *fim_sql);


#ifndef WIN32
fim_entry *__wrap_fim_db_get_entry_from_sync_msg(fdb_t *fim_sql,
                                                 __attribute__((unused)) fim_type type,
                                                 const char *path);

#else
fim_entry *__wrap_fim_db_get_entry_from_sync_msg(fdb_t *fim_sql, fim_type type, const char *path);
#endif

int __wrap_fim_db_read_line_from_file(fim_tmp_file *file, int storage, int it, char **buffer);

void __wrap_fim_db_clean_file(fim_tmp_file **file, int storage);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_get_path_range
 */
void expect_wrapper_fim_db_get_path_range_call(const fdb_t *db,
                                       const char *start_str,
                                       const char *top_str,
                                       int storage,
                                       fim_tmp_file *tmp_file,
                                       int ret);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_delete_range
 */
void expect_wrapper_fim_db_delete_range_call(const fdb_t *db, int storage, const fim_tmp_file *file, int ret);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_get_count_entries
 */
void expect_wrapper_fim_db_get_count_entries(const fdb_t *fim_sql, int ret);

/**
 * @brief This function loads the expect and will_return calls for the wrapper of fim_db_get_paths_from_inode
 */
void expect_wrapper_fim_db_get_paths_from_inode(fdb_t *db, int inode, int dev, char **ret);

/**
 * @brief This function mocks a call to fim_db_process_read_file
 */
int __wrap_fim_db_process_read_file(fdb_t *fim_sql,
                                    fim_tmp_file *file,
                                    int type,
                                    pthread_mutex_t *mutex,
                                    void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                    int storage,
                                    void *alert,
                                    void *mode,
                                    void *w_evt);
#endif
