/*
 * Wazuh FIMDB
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _ENTRY_H
#define _ENTRY_H
#include <json.hpp>
#include "syscheck.h"

/**
 * @brief Function to free the fim_file_data struct.
 *
 * @param data structure to free.
 */
void free_file_data(fim_file_data *data);

/**
 * @brief Function to free the fim_registry_key struct.
 *
 * @param data structure to free.
 */
void fim_registry_free_key(fim_registry_key *key);

/**
 * @brief Function to free the fim_registry_value_data struct.
 *
 * @param data structure to free.
 */
void fim_registry_free_value_data(fim_registry_value_data *data);

/**
 * @brief Function to free registry type fim entry.
 *
 *  @param entry structure to free.
 */
void fim_registry_free_entry(fim_entry *entry);

/**
 * @brief Funtion to free a fim_entry struct
 *
 * @param entry structure to free
 */
void free_entry(fim_entry *entry);

/**
 * @brief Function to fill a file entry using a JSON as a source.
 *
 * @param json_data Data in JSON.
 *
 * @return A fim_entry with the data.
  */
fim_entry *fillFileEntry(const nlohmann::json &json_data);

/**
 * @brief Auxiliar function to fill the data of a registry key using a json as a source.
 *
 * @param json_data JSON with the data that will be used.
 * @param fill_entry The fim_registry_key structure to save the data.
 */
void fillRegistryKeyData(const nlohmann::json &json_data, fim_registry_key &fill_entry);

/**
 * @brief Function to fill a registry value entry.
 *
 * @param json_data JSON with the data to use.
 * @param fill_entry The fim_registry_value_data structure to save the data.
 */
void fillValueEntry(const nlohmann::json &json_data, fim_registry_value_data &fill_entry);

/**
 * @brief Function to get one or more registry entries from a JSON.
 *
 * @param json_data JSON holding the key data and it's values.
 * @return std::vector<fim_entry*> Vector holding the fim_entries stored in the JSON.
 */
std::vector<fim_entry*> fillRegistryEntry(const nlohmann::json &json_data);

/**
 * @brief Print information about a fim_entry
 *
 * @param entry fim_entry where the data is stored.
  */
void print_entry(const fim_entry& entry, const std::function<void(const char *)>& reportFunction);
#endif // _ENTRY_H
