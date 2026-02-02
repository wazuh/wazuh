/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REGISTRY_H
#define REGISTRY_H

#ifdef WIN32

#include "syscheck.h"

// Structure to hold failed registry key information for deferred deletion
typedef struct failed_registry_key_s {
    char *path;
    int arch;
} failed_registry_key_t;

// Structure to hold failed registry value information for deferred deletion
typedef struct failed_registry_value_s {
    char *path;
    char *value;
    int arch;
} failed_registry_value_t;

typedef struct fim_key_txn_context_s {
    event_data_t *evt_data;
    registry_t *config;
    fim_registry_key *key;
    OSList *failed_keys;  // List of failed_registry_key_t* for deferred deletion
} fim_key_txn_context_t;

typedef struct fim_val_txn_context_s {
    event_data_t *evt_data;
    registry_t *config;
    fim_registry_value_data *data;
    char* diff;
    OSList *failed_values;  // List of failed_registry_value_t* for deferred deletion
} fim_val_txn_context_t;

/**
 * @brief Retrieves the configuration associated with a given registry element.
 *
 * @param key A string holding the full path to the registry element.
 * @param arch An integer specifying the bit count of the register element, must be ARCH_32BIT or ARCH_64BIT.
 * @return A pointer to the associated registry configuration, NULL on error or if no valid configuration was found.
 */
registry_t *fim_registry_configuration(const char *key, int arch);

/**
 * @brief Free all memory associated with a registry.
 *
 * @param data A fim_entry object to be free'd.
 */
void fim_registry_free_entry(fim_entry *entry);

/**
 * @brief Main scheduled algorithm for registry scan
 */
void fim_registry_scan();

/**
 * @brief Create a cJSON object holding the attributes associated with a fim_registry_value_data according to its
 * configuration.
 *
 * @param data A fim_registry_value_data object holding the value attributes to be tranlated.
 * @param configuration The configuration associated with the registry value.
 * @return A pointer to a cJSON object the translated value attributes.
 */
cJSON *fim_registry_value_attributes_json(const cJSON* dbsync_event, const fim_registry_value_data *data,
                                          const registry_t *configuration);

/**
 * @brief Create a cJSON object holding the attributes associated with a fim_registry_key according to its
 * configuration.
 *
 * @param data A fim_registry_key object holding the key attributes to be tranlated.
 * @param configuration The configuration associated with the registry key.
 * @return A pointer to a cJSON object the translated key attributes.
 */
cJSON *fim_registry_key_attributes_json(const cJSON* dbsync_event, const fim_registry_key *data, const registry_t *configuration);

/**
 * @brief Calculates the `changed_attributes` and `old_attributes` for registry keys using the
 *        information collected by the scan and the old attributes returned by DBSync.
 *
 * @param configuration Configuration of the entry.
 * @param old_data Old attributes returned by DBSync.
 * @param changed_attributes JSON Array where the changed attributes will be stored.
 * @param old_attributes JSON where the old attributes will be stored.
 */
void fim_calculate_dbsync_difference_key(const registry_t *configuration,
                                         const cJSON* old_data,
                                         cJSON* changed_attributes,
                                         cJSON* old_attributes);

/**
 * @brief Calculates the `changed_attributes` and `old_attributes` for registry values using the
 *        information collected by the scan and the old attributes returned by DBSync.
 *
 * @param configuration Configuration of the entry.
 * @param old_data Old attributes returned by DBSync.
 * @param changed_attributes JSON Array where the changed attributes will be stored.
 * @param old_attributes JSON where the old attributes will be stored.
 */
void fim_calculate_dbsync_difference_value(const registry_t* configuration,
                                           const cJSON* old_data,
                                           cJSON* changed_attributes,
                                           cJSON* old_attributes);


/**
 * @brief Build a stateful event for a registry key with proper hierarchical structure
 *
 * @param path Full registry path
 * @param sha1_hash SHA1 hash for checksum
 * @param document_version Document version number
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @param dbsync_event Data returned by dbsync in JSON format from where fim attributes will get extracted if no registry_data is passed in.
 * @param registry_data structure from where the fim attributes will get extracted (Optional) 
 * @return cJSON object containing the stateful event, NULL on error
 */
cJSON* build_stateful_event_registry_key(const char* path, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_key *data);

/**
 * @brief Build a stateful event for a registry value with proper hierarchical structure
 *
 * @param path Full registry path
 * @param value Value entry
 * @param sha1_hash SHA1 hash for checksum
 * @param document_version Document version number
 * @param arch Architecture (ARCH_32BIT or ARCH_64BIT)
 * @param dbsync_event Data returned by dbsync in JSON format from where fim attributes will get extracted if no registry_data is passed in.
 * @param registry_data structure from where the fim attributes will get extracted (Optional) 
 * @return cJSON object containing the stateful event, NULL on error
 */
cJSON* build_stateful_event_registry_value(const char* path, const char* value, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_value_data *registry_data);
#endif

#endif
