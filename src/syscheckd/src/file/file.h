/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FILE_H
#define FILE_H

#include "../../include/syscheck.h"

#ifdef WIN32
#define check_removed_file(x) ({ strstr(x, ":\\$recycle.bin") ? 1 : 0; })
#endif

// Global variables
extern int _base_line;

typedef struct callback_ctx
{
    event_data_t* event;
    const directory_t* config;
    fim_entry* entry;
} callback_ctx;

/**
 * @brief Search the position of the path in directories array
 *
 * @param key Path to seek in the directories array
 * @return Returns a pointer to the configuration associated with the provided path, NULL if the path is not found
 */
directory_t* fim_configuration_directory(const char* key);

/**
 * @brief Evaluates the depth of the directory or file to check if it exceeds the configured max_depth value
 *
 * @param path File name of the file/directory to check
 * @param configuration Configuration associated with the file
 * @return Depth of the directory/file, -1 on error
 */
int fim_check_depth(const char* path, const directory_t* configuration);

/**
 * @brief Checks if a specific file has been configured to be ignored
 *
 * @param file_name The name of the file to check
 * @return 1 if it has been configured to be ignored, 0 if not
 */
int fim_check_ignore(const char* file_name);

/**
 * @brief Checks if a specific folder has been configured to be checked with a specific restriction
 *
 * @param file_name The name of the file to check
 * @param restriction The regex restriction to be checked
 * @return 1 if the folder has been configured with the specified restriction, 0 if not
 */
int fim_check_restrict(const char* file_name, OSMatch* restriction);

/**
 * @brief Get the directory that will be effectively monitored depending on configuration the entry configuration and
 * physical object in the filesystem
 *
 * @param dir Pointer to the configuration associated with the directory
 * @return A string holding the element being monitored. It must be freed after it's usage.
 */
char* fim_get_real_path(const directory_t* dir);

/**
 * @brief Calculate checksum of a FIM entry data
 *
 * @param data FIM entry data to calculate the checksum with
 */
void fim_get_checksum(fim_file_data* data);

/**
 * @brief Initialize a fim_file_data structure
 *
 * @param [out] data Data to initialize
 */
void init_fim_data_entry(fim_file_data* data);

/**
 * @brief Free all memory associated with a file data.
 *
 * @param data A fim_file_data object to be free'd.
 */
void free_file_data(fim_file_data * data);

/**
 * @brief Get data from file
 *
 * @param file Name of the file to get the data from
 * @param [in] configuration Configuration block associated with a previous event.
 * @param [in] statbuf Buffer acquired from a stat command with information linked to 'path'
 *
 * @return A fim_file_data structure with the data from the file
 */
fim_file_data* fim_get_data(const char* file, const directory_t* configuration, const struct stat* statbuf);

/**
 * @brief File checker
 *
 * @param [in] path Path of the file to check
 * @param [in] evt_data Information associated to the triggered event
 * @param [in] configuration Configuration block associated with a previous event.
 * @param [in] dbsync_txn Handle to an active dbsync transaction.
 */
void fim_checker(const char* path,
                 event_data_t* evt_data,
                 const directory_t* parent_configuration,
                 TXN_HANDLE dbsync_txn,
                 callback_ctx* ctx);

/**
 * @brief Check file integrity monitoring on a specific folder
 *
 * @param [in] dir
 * @param [in] evt_data Information associated to the triggered event
 * @param [in] configuration Configuration block associated with the directory.
 * @param [in] txn_handle DBSync transaction handler. Can be NULL.
 *
 * @return 0 on success, -1 on failure
 */

int fim_directory(const char* dir,
                  event_data_t* evt_data,
                  const directory_t* configuration,
                  TXN_HANDLE dbsync_txn,
                  callback_ctx* ctx);

/**
 * @brief Check file integrity monitoring on a specific file
 *
 * @param [in] path Path of the file to check
 * @param [in] configuration Configuration block associated with a previous event.
 * @param [in] evt_data Information associated to the triggered event
 * @param [in] txn_handle DBSync transaction handler. Can be NULL.
 * @param [in] ctx DBSync transaction context.
 */
void fim_file(const char* path,
              const directory_t* configuration,
              event_data_t* evt_data,
              TXN_HANDLE txn_handle,
              callback_ctx* ctx);

/**
 * @brief Process a path that has possibly been deleted
 *
 * @note On Windows, calls function fim_checker meanwhile, on Linux, calls function fim_audit_inode_event. It's because
 * Windows haven't got inodes.
 * @param pathname Name of path
 * @param mode Monitoring FIM mode
 * @param w_evt Pointer to whodata information
 */
void fim_process_missing_entry(char* pathname, fim_event_mode mode, whodata_evt* w_evt);

/**
 * @brief Handle symlink deletion.
 *
 * @param config Directory configuration.
 */
void fim_link_delete_range(directory_t *config);

/**
 * @brief Create a delete event and removes the entry from the database.
 *
 * @param file_path path data to be removed.
 * @param evt_data Information associated to the triggered event.
 * @param configuration Directory configuration to be deleted.
 *
 */
void fim_generate_delete_event(const char* file_path, const void* evt_data, const void* configuration);

/**
 * @brief Handle file deletion by path.
 *
 * @param path Path of the file to be deleted.
 * @param evt_data Event data associated with the deletion.
 * @param config Directory configuration for the file.
 * @param to_delete Flag indicating if the entry should be deleted from the database.
 * @param fallback_cb Flag indicating if a fallback callback should be used.
 */
void fim_handle_delete_by_path(const char *path,
                               const event_data_t *evt_data,
                               const directory_t *config,
                               bool to_delete,
                               bool fallback_cb);

/**
 * @brief Main scheduled algorithm for file scan
 */
void fim_file_scan();

/**
 * @brief Create file attribute set JSON from a FIM entry structure
 *
 * @param dbsync_event Pointer to event dbsync JSON structure.
 * @param data Pointer to a FIM entry structure.
 * @param configuration Pointer to the configuration structure.
 * @pre data is mutex-blocked.
 * @return Pointer to cJSON structure.
 */
cJSON* fim_attributes_json(const cJSON* dbsync_event, const fim_file_data* data, const directory_t* configuration);

/**
 * @brief Create file audit data JSON object
 *
 * @param w_evt Pointer to event whodata structure
 * @return cJSON object pointer.
 */
cJSON* fim_audit_json(const whodata_evt* w_evt);

/**
 * @brief Calculates the `changed_attributes` and `old_attributes` for files using the
 *        information collected by the scan and the old attributes returned by DBSync.
 *
 * @param configuration Configuration of the entry.
 * @param old_data Old attributes returned by DBSync.
 * @param changed_attributes JSON Array where the changed attributes will be stored.
 * @param old_attributes JSON where the old attributes will be stored.
 */
void fim_calculate_dbsync_difference(const directory_t *configuration,
                                     const cJSON* old_data,
                                     cJSON* changed_attributes,
                                     cJSON* old_attributes);

#endif
