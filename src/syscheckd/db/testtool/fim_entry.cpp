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

#include "fim_entry.hpp"

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

void fim_registry_free_value_data(fim_registry_value_data *data)
{
    if (data)
    {
        free(data->name);
        free(data);
    }
}

void fim_registry_free_entry(fim_entry *entry)
{
    if (entry)
    {
        fim_registry_free_key(entry->registry_entry.key);
        fim_registry_free_value_data(entry->registry_entry.value);
        free(entry);
    }
}

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

fim_entry *fillFileEntry(const nlohmann::json &json_data)
{
    fim_entry *fill_entry = (fim_entry *) std::calloc(1, sizeof(fim_entry));
    if (fill_entry == NULL)
    {
        throw std::runtime_error{
            "Cannot allocate memory"};
    }
    fill_entry->type = FIM_TYPE_FILE;
    fill_entry->file_entry.path = strdup(static_cast<std::string>(json_data["path"]).c_str());
    fill_entry->file_entry.data = (fim_file_data *) std::calloc(1, sizeof(fim_file_data));
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

void fillRegistryKeyData(const nlohmann::json &json_data, fim_registry_key &fill_entry)
{

    fill_entry.id = json_data["id"];
    fill_entry.path = strdup(static_cast<std::string>(json_data["path"]).c_str());
    fill_entry.perm = strdup(static_cast<std::string>(json_data["perm"]).c_str());
    fill_entry.uid = strdup(static_cast<std::string>(json_data["uid"]).c_str());
    fill_entry.gid = strdup(static_cast<std::string>(json_data["gid"]).c_str());
    fill_entry.user_name = strdup(static_cast<std::string>(json_data["user_name"]).c_str());
    fill_entry.group_name = strdup(static_cast<std::string>(json_data["group_name"]).c_str());
    fill_entry.mtime = json_data["mtime"];
    fill_entry.arch = json_data["arch"];
    fill_entry.scanned = json_data["scanned"];
    fill_entry.last_event = json_data["last_event"];

    std::strncpy(fill_entry.checksum, const_cast<char *>(static_cast<std::string>(json_data["checksum"]).c_str()), sizeof(fill_entry.checksum));
}

void fillValueEntry(const nlohmann::json &json_data, fim_registry_value_data &fill_entry)
{

    fill_entry.id = json_data["id"];
    fill_entry.name = strdup(static_cast<std::string>(json_data["name"]).c_str());
    fill_entry.type = json_data["type"];
    fill_entry.size = json_data["size"];

    std::strncpy(fill_entry.hash_md5, const_cast<char *>(static_cast<std::string>(json_data["sha1"]).c_str()), sizeof(fill_entry.hash_md5));
    std::strncpy(fill_entry.hash_sha1, const_cast<char *>(static_cast<std::string>(json_data["sha1"]).c_str()), sizeof(fill_entry.hash_sha1));
    std::strncpy(fill_entry.hash_sha256, const_cast<char *>(static_cast<std::string>(json_data["sha256"]).c_str()), sizeof(fill_entry.hash_sha256));
    std::strncpy(fill_entry.checksum, const_cast<char *>(static_cast<std::string>(json_data["checksum"]).c_str()), sizeof(fill_entry.checksum));
}

void fillRegistryEntry(const nlohmann::json &json_data, std::vector<fim_entry*>& entry_vector) {
    auto key_info = json_data["key"];
    if (json_data.contains("values") == false) {
        fim_entry *fill_entry = (fim_entry *)std::calloc(1, sizeof(fim_entry));
        fill_entry->type = FIM_TYPE_REGISTRY;

        fill_entry->registry_entry.key = (fim_registry_key *) std::calloc(1, sizeof(fim_registry_key));
        fillRegistryKeyData(key_info, *fill_entry->registry_entry.key);
        entry_vector.push_back(fill_entry);
    }
    else
    {
        for (auto value_data: json_data["values"]){
            fim_entry *fill_entry = (fim_entry *)std::calloc(1, sizeof(fim_entry));
            if (fill_entry == NULL)
            {
                throw std::runtime_error{
                    "Cannot allocate memory"};
            }

            fill_entry->type = FIM_TYPE_REGISTRY;
            fill_entry->registry_entry.key = (fim_registry_key *) std::calloc(1, sizeof(fim_registry_key));
            fill_entry->registry_entry.value = (fim_registry_value_data *) std::calloc(1, sizeof(fim_registry_value_data));

            fillRegistryKeyData(key_info, *fill_entry->registry_entry.key);
            fillValueEntry(value_data, *fill_entry->registry_entry.value);

            entry_vector.push_back(fill_entry);
        }
    }
}

void print_entry(const fim_entry& entry, const std::function<void(const char *)>& reportFunction)
{
    char to_print[OS_MAXSTR + 1] = {0};
    if (entry.type == FIM_TYPE_FILE)
    {
        snprintf(to_print, OS_MAXSTR, "File path = %s", entry.file_entry.path);
    }
    else
    {
        if (entry.registry_entry.value != NULL) {
            snprintf(to_print, OS_MAXSTR, "Key path = %s Value name = %s", entry.registry_entry.key->path,
                     entry.registry_entry.value->name);
        } else {
            snprintf(to_print, OS_MAXSTR, "Key path = %s", entry.registry_entry.key->path);
        }

    }

    reportFunction(to_print);
}
