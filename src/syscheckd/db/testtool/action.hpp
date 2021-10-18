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
        virtual void                      execute() {};
        virtual                           ~TestAction() {}

    protected:
        int                               m_actionId;
        std::string                       m_dbPath;
        std::string                       m_outPath;
        std::string                       m_table;
        nlohmann::json                    m_actionData;
        std::function<void(const char*)> m_reportFunction;

};

class InsertAction final : public TestAction
{
    public:
        InsertAction(const std::string& table, const nlohmann::json& actionData,
                     const std::function<void(const char*)> reportFunction)
        {
            m_reportFunction = reportFunction;
            m_table = table;
            m_actionData = actionData;
            // FIMDB::getInstance().init();
        }

        ~InsertAction() {}

        void execute() override
        {
            m_reportFunction("Executing insert action.\n");

            for (auto it : m_actionData)
            {
                if (m_table == "FILE")
                {
                    fim_entry* file_entry = fillFileEntry(it);
                    m_reportFunction("Inserting file entry:");

                    print_entry(*file_entry, m_reportFunction);
                    free_entry(file_entry);
                }
                else if (m_table == "REGISTRY")
                {
                    auto entry_vector = fillRegistryEntry(it);

                    for (fim_entry* entry : entry_vector)
                    {
                        m_reportFunction("Inserting registry entry:");
                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }
        }
};

class UpdateAction final : public TestAction
{
    public:
        UpdateAction(const std::string& table, const nlohmann::json& actionData,
                     const std::function<void(const char*)> reportFunction)
        {
            m_reportFunction = reportFunction;
            m_table = table;
            m_precondData = actionData["precondition_data"];
            m_actionData = actionData["update_data"];
            // FIMDB::getInstance().init();
        }
        void execute() override
        {
            m_reportFunction("Executing update preconditions.\n");

            for (auto it : m_precondData)
            {
                if (m_table == "FILE")
                {
                    fim_entry* file_entry = fillFileEntry(it);
                    m_reportFunction("Inserting file entry:");

                    print_entry(*file_entry, m_reportFunction);
                    free_entry(file_entry);
                }
                else if (m_table == "REGISTRY")
                {
                    auto entry_vector = fillRegistryEntry(it);

                    for (auto entry : entry_vector)
                    {
                        m_reportFunction("Inserting registry entry:");
                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }

            m_reportFunction("Executing update actions.\n");

            for (auto it : m_actionData)
            {

                if (m_table == "FILE")
                {
                    fim_entry* file_entry = fillFileEntry(it);
                    m_reportFunction("Updating file entry:");

                    print_entry(*file_entry, m_reportFunction);
                    free_entry(file_entry);
                }
                else if (m_table == "REGISTRY")
                {
                    auto entry_vector = fillRegistryEntry(it);

                    for (fim_entry* entry : entry_vector)
                    {
                        m_reportFunction("Updating registry entry:");
                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }
        }

    private:
        nlohmann::json m_precondData;
};

class RemoveAction final : public TestAction
{
    public:
        RemoveAction(const std::string& table, const nlohmann::json& actionData,
                     const std::function<void(const char*)> reportFunction)
        {
            m_reportFunction = reportFunction;
            m_table = table;
            m_precondData = actionData["precondition_data"];
            m_actionData = actionData["delete_data"];
            // FIMDB::getInstance().init();
        }
        void execute() override
        {
            m_reportFunction("Executing remove preconditions.\n");

            for (auto it : m_precondData)
            {
                if (m_table == "FILE")
                {
                    fim_entry* file_entry = fillFileEntry(it);
                    m_reportFunction("Inserting file entry:");

                    print_entry(*file_entry, m_reportFunction);
                    free_entry(file_entry);
                }
                else if (m_table == "REGISTRY")
                {
                    auto entry_vector = fillRegistryEntry(it);

                    for (auto entry : entry_vector)
                    {
                        m_reportFunction("Inserting registry entry:");
                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }

            m_reportFunction("Executing remove actions.\n");

            for (auto it : m_actionData)
            {

                if (m_table == "FILE")
                {
                    fim_entry* file_entry = fillFileEntry(it);
                    m_reportFunction("Removing file entry:");

                    print_entry(*file_entry, m_reportFunction);
                    free_entry(file_entry);
                }
                else if (m_table == "REGISTRY")
                {
                    auto entry_vector = fillRegistryEntry(it);

                    for (auto entry : entry_vector)
                    {
                        m_reportFunction("Removing registry entry:");
                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }
        }

    private:
        nlohmann::json m_precondData;
};

#endif //_ACTION_H
