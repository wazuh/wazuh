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
#include "fim_entry.h"
#include <iostream>



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
        fim_entry *entry = nullptr;
        for (auto it : m_actionData) {
            // std::cout << it["path"] << std::endl;
            entry = fillFileEntry(it);
            std::cout << "execute insert" << std::endl;
            free_entry(entry);
        }

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



#endif //_ACTION_H
