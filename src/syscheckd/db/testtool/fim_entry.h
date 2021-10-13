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
void free_file_data(fim_file_data *data)
{
    if (!data)
    {
        return;
    }

    free(data->perm);
    free(data->attributes);
    free(data->uid);
    free(data->gid);
    free(data->user_name);
    free(data->group_name);

    free(data);
}

/**
 * @brief Function to free the fim_registry_key struct.
 *
 * @param data structure to free.
 */
void fim_registry_free_key(fim_registry_key *key)
{
    if (key)
    {
        free(key->path);
        free(key->perm);
        free(key->uid);
        free(key->gid);
        free(key->user_name);
        free(key->group_name);
        free(key);
    }
}

/**
 * @brief Function to free the fim_registry_value_data struct.
 *
 * @param data structure to free.
 */
void fim_registry_free_value_data(fim_registry_value_data *data)
{
    if (data)
    {
        free(data->name);
        free(data);
    }
}

/**
 * @brief Function to free registry type fim entry.
 *
 *  @param entry structure to free.
 */
void fim_registry_free_entry(fim_entry *entry)
{
    if (entry)
    {
        fim_registry_free_key(entry->registry_entry.key);
        fim_registry_free_value_data(entry->registry_entry.value);
        free(entry);
    }
}

/**
 * @brief Funtion to free a fim_entry struct
 *
 * @param entry structure to free
 */
void free_entry(fim_entry *entry)
{
    if (entry)
    {
        if (entry->type == FIM_TYPE_FILE)
        {
            free(entry->file_entry.path);
            free_file_data(entry->file_entry.data);
            free(entry);
        }
        else
        {
            fim_registry_free_entry(entry);
        }
    }
}

/**
 * @brief Function to fill a file entry using a JSON as a source.
 *
 * @param json_data Data in JSON.
 *
 * @return A fim_entry with the data.
  */
fim_entry *fillFileEntry(const nlohmann::json &json_data)
{
    fim_entry *fill_entry = (fim_entry *)calloc(1, sizeof(fim_entry));
    if (fill_entry == NULL)
    {
        throw std::runtime_error{
            "Cannot allocate memory"};
    }
    fill_entry->type = FIM_TYPE_FILE;
    fill_entry->file_entry.path = strdup(static_cast<std::string>(json_data["path"]).c_str());
    fill_entry->file_entry.data = (fim_file_data *)calloc(1, sizeof(fim_file_data));
    fill_entry->file_entry.data->size = json_data["size"];
    fill_entry->file_entry.data->perm = strdup(static_cast<std::string>(json_data["perm"]).c_str());
    fill_entry->file_entry.data->attributes = strdup(static_cast<std::string>(json_data["attributes"]).c_str());
    fill_entry->file_entry.data->uid = strdup(static_cast<std::string>(json_data["uid"]).c_str());
    fill_entry->file_entry.data->gid = strdup(static_cast<std::string>(json_data["gid"]).c_str());

    fill_entry->file_entry.data->user_name = strdup(static_cast<std::string>(json_data["user_name"]).c_str());
    fill_entry->file_entry.data->group_name = strdup(static_cast<std::string>(json_data["group_name"]).c_str());

    std::strncpy(fill_entry->file_entry.data->hash_md5, const_cast<char *>(static_cast<std::string>(json_data["sha1"]).c_str()), sizeof(fill_entry->file_entry.data->hash_md5));
    std::strncpy(fill_entry->file_entry.data->hash_sha1, const_cast<char *>(static_cast<std::string>(json_data["sha1"]).c_str()), sizeof(fill_entry->file_entry.data->hash_sha1));
    std::strncpy(fill_entry->file_entry.data->hash_sha256, const_cast<char *>(static_cast<std::string>(json_data["sha256"]).c_str()), sizeof(fill_entry->file_entry.data->hash_sha256));
    std::strncpy(fill_entry->file_entry.data->checksum, const_cast<char *>(static_cast<std::string>(json_data["checksum"]).c_str()), sizeof(fill_entry->file_entry.data->checksum));

    fill_entry->file_entry.data->mtime = json_data["mtime"];
    fill_entry->file_entry.data->inode = json_data["inode"];
    fill_entry->file_entry.data->mode = json_data["mode"];
    fill_entry->file_entry.data->last_event = json_data["last_event"];

    fill_entry->file_entry.data->dev = json_data["dev"];
    fill_entry->file_entry.data->scanned = json_data["scanned"];

    return fill_entry;
}

/**
 * @brief Auxiliar function to fill the data of a registry key using a json as a source.
 *
 * @param json_data JSON with the data that will be used.
 * @return A fim_registry_key structure with the data.
 */
fim_registry_key *fillRegistryKeyData(const nlohmann::json &json_data)
{
    fim_registry_key *fill_entry = (fim_registry_key *)calloc(1, sizeof(fim_registry_key));

    fill_entry->user_name = strdup(static_cast<std::string>(json_data["user_name"]).c_str());
    fill_entry->id = json_data["id"];
    fill_entry->path = strdup(static_cast<std::string>(json_data["path"]).c_str());
    fill_entry->perm = strdup(static_cast<std::string>(json_data["perm"]).c_str());
    fill_entry->uid = strdup(static_cast<std::string>(json_data["uid"]).c_str());
    fill_entry->gid = strdup(static_cast<std::string>(json_data["gid"]).c_str());
    fill_entry->user_name = strdup(static_cast<std::string>(json_data["user_name"]).c_str());
    fill_entry->group_name = strdup(static_cast<std::string>(json_data["group_name"]).c_str());
    fill_entry->mtime = json_data["mtime"];
    fill_entry->arch = json_data["arch"];
    fill_entry->scanned = json_data["scanned"];
    fill_entry->last_event = json_data["last_event"];

    std::strncpy(fill_entry->checksum, const_cast<char *>(static_cast<std::string>(json_data["checksum"]).c_str()), sizeof(fill_entry->checksum));

    return fill_entry;
}

/**
 * @brief Function to fill a registry key entry.
 *
 * @param json_data JSON with the data to use.
 * @return A fim_entry with the data.
 */
fim_entry *fillKeyEntry(const nlohmann::json &json_data)
{
    fim_entry *fill_entry = (fim_entry *)calloc(1, sizeof(fim_entry));
    if (fill_entry == NULL)
    {
        throw std::runtime_error{
            "Cannot allocate memory"};
    }
    fill_entry->type = FIM_TYPE_REGISTRY;
    fill_entry->registry_entry.key = fillRegistryKeyData(json_data);
    return fill_entry;
}

/**
 * @brief Function to fill a registry value entry.
 *
 * @param json_data JSON with the data to use.
 * @return A fim_entry with the data.
 */
fim_entry *fillValueEntry(const nlohmann::json &json_data)
{
    fim_entry *fill_entry = (fim_entry *)calloc(1, sizeof(fim_entry));
    if (fill_entry == NULL)
    {
        throw std::runtime_error{
            "Cannot allocate memory"};
    }
    fill_entry->type = FIM_TYPE_REGISTRY;
    fill_entry->registry_entry.key = fillRegistryKeyData(json_data);
    fill_entry->registry_entry.value = (fim_registry_value_data *)calloc(1, sizeof(fim_registry_value_data));

    fill_entry->registry_entry.value->id = json_data["id"];
    fill_entry->registry_entry.value->name = strdup(static_cast<std::string>(json_data["name"]).c_str());
    fill_entry->registry_entry.value->type = json_data["type"];
    fill_entry->registry_entry.value->size = json_data["size"];

    std::strncpy(fill_entry->registry_entry.value->hash_md5, const_cast<char *>(static_cast<std::string>(json_data["sha1"]).c_str()), sizeof(fill_entry->registry_entry.value->hash_md5));
    std::strncpy(fill_entry->registry_entry.value->hash_sha1, const_cast<char *>(static_cast<std::string>(json_data["sha1"]).c_str()), sizeof(fill_entry->registry_entry.value->hash_sha1));
    std::strncpy(fill_entry->registry_entry.value->hash_sha256, const_cast<char *>(static_cast<std::string>(json_data["sha256"]).c_str()), sizeof(fill_entry->registry_entry.value->hash_sha256));
    std::strncpy(fill_entry->registry_entry.value->checksum, const_cast<char *>(static_cast<std::string>(json_data["checksum"]).c_str()), sizeof(fill_entry->registry_entry.value->checksum));

    return fill_entry;
}

/**
 * @brief Print information about a fim_entry
 *
 * @param entry fim_entry where the data is stored.
  */
void print_entry(const fim_entry& entry)
{
    if (entry.type == FIM_TYPE_FILE)
    {
        std::cout << "File path: " << entry.file_entry.path << '\n' << std::endl;
    } else if (entry.type == FIM_TYPE_REGISTRY) {
        std::cout << "Key path: " << entry.registry_entry.key->path << '\n' << std::endl;
        if (entry.registry_entry.value != NULL) {
            std::cout << "Value name: " << entry.registry_entry.value->name << '\n' << std::endl;
        }
    }
}
#endif // _ENTRY_H
