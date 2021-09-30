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
#ifndef _ACTION_H
#define _ACTION_H
#include <json.hpp>
#include <mutex>
// #include "fimDB.hpp"
#include "dbItem.hpp"
#include "dbFileItem.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
// #include "fimDBWrapper.hpp"
#include "syscheck.h"
#include <iostream>


std::unique_ptr<DBItem> fillFileItemJson(const std::string& table, const nlohmann::json& json_data);

class TestAction
{
public:
    TestAction() = default;
    virtual void execute() {};
    virtual ~TestAction() {}
protected:
    std::string m_dbPath;
    std::string m_outPath;
    std::string m_table;
    nlohmann::json m_actionData;
    int m_actionId;
};

class InsertAction final : public TestAction
{
public:
    InsertAction(const std::string& table, const nlohmann::json& actionData) {
        m_table = table;
        m_actionData = actionData;
        // FIMDB::getInstance().init();
    }

    ~InsertAction() {}

    void execute() override
    {

        for (auto it : m_actionData) {
            // std::cout << it["path"] << std::endl;
            auto insertItem = fillFileItemJson(m_table, it);
            // db.insertItem(insertItem);
        }

        std::cout << "execute insert" << std::endl;
    }
};

class UpdateAction final : public TestAction
{
public:
    UpdateAction(const std::string& table, const nlohmann::json& actionData)
    {
        m_table = table;
        m_precondData = actionData["precondition_data"];
        m_actionData = actionData["modification_data"];
        // FIMDB::getInstance().init();

    }
    void execute() override
    {
        std::cout << "execute update preconditions" << std::endl;
        std::cout << "execute modify preconditions" << std::endl;
    }
private:
    nlohmann::json m_precondData;
};

class RemoveAction final : public TestAction
{
public:
    RemoveAction(const std::string& table, const nlohmann::json& actionData) {
        m_table = table;
        m_preconData = actionData["precondition_data"];
        m_actionData = actionData["delete_data"];
        // FIMDB::getInstance().init();

    }
    void execute() override
    {

        std::cout << "executing delete preconditions" << std::endl;


        std::cout << "execute remove test" << std::endl;
    }
private:
    nlohmann::json m_preconData;
};

fim_entry fillFileEntry(const nlohmann::json& json_data) {
    fim_entry entry;
    entry.type = FIM_TYPE_FILE;
    entry.file_entry.path = const_cast<char *>(static_cast<std::string> (json_data["path"]).c_str());
    entry.file_entry.data = fillFileEntryData(json_data);

}

fim_file_data fillFileEntryData(const nlohmann::json& json_data) {


        fill_entry.type = FIM_TYPE_FILE;
        fim_file_data file_data;
        fill_entry.file_entry.path = const_cast<char *>(static_cast<std::string> (json_data["path"]).c_str());

        file_data.size = json_data["size"];
        file_data.perm = const_cast<char *>(static_cast<std::string> (json_data["perm"]).c_str());
        file_data.attributes = const_cast<char *>(static_cast<std::string> (json_data["attributes"]).c_str());
        file_data.uid = const_cast<char *>(static_cast<std::string> (json_data["uid"]).c_str());
        file_data.gid = const_cast<char *>(static_cast<std::string> (json_data["gid"]).c_str());

        file_data.user_name = const_cast<char *>(static_cast<std::string> (json_data["user_name"]).c_str());
        file_data.group_name = const_cast<char *>(static_cast<std::string> (json_data["group_name"]).c_str());

        std::strncpy(file_data.hash_md5, const_cast<char *>(static_cast<std::string> (json_data["sha1"]).c_str()), sizeof(fill_entry.file_entry.data->hash_md5));
        std::strncpy(file_data.hash_sha1, const_cast<char *>(static_cast<std::string> (json_data["sha1"]).c_str()), sizeof(fill_entry.file_entry.data->hash_sha1));
        std::strncpy(file_data.hash_sha256, const_cast<char *>(static_cast<std::string> (json_data["sha256"]).c_str()), sizeof(fill_entry.file_entry.data->hash_sha256));
        std::strncpy(file_data.checksum, const_cast<char *>(static_cast<std::string> (json_data["checksum"]).c_str()), sizeof(fill_entry.file_entry.data->checksum));

        file_data.mtime = json_data["mtime"];
        file_data.inode = json_data["inode"];
        file_data.mode = json_data["mode"];
        file_data.last_event = json_data["last_event"];

        file_data.dev = json_data["dev"];
        file_data.scanned = json_data["scanned"];

        fill_entry.file_entry.data = &file_data;
        // ret = std::make_unique<FileItem>(fill_entry);

    } else if (table == "KEY") {
        fill_entry.type = FIM_TYPE_REGISTRY;



    } else if (table == "VALUE") {

    } else {
        free_entry(fill_entry);

        throw std::runtime_error
        {
            "Unknown table."
        };
    }

    // free_entry(fill_entry);
    return ret;
}

#endif //_ACTION_H
