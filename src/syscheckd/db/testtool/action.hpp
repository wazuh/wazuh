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
#include "fim_entry.hpp"
#include <iostream>

/**
 * @brief Abstract class that represents a test action
 *
 */
class TestAction
{
    public:
        TestAction() = default;
        virtual void                      execute() {};
        virtual                           ~TestAction() {}

    protected:
        int                               m_actionId;        /**< Integer to store the action identifier.       */
        std::string                       m_dbPath;          /**< String with the database path.                */
        std::string                       m_outPath;         /**< */
        std::string                       m_table;           /**< Database table where the action is performed. */
        nlohmann::json                    m_actionData;      /**< Json storing the data to perform the action.  */
        std::function<void(const char*)> m_reportFunction;   /**< Function to log */

};

/**
 * @brief Class to perform insertions into a specific table using a JSON as a source.
 */
class InsertAction final : public TestAction
{
    public:
        /**
         * @brief Construct a new Insert Action object
         *
         * @param table Store the table where the action will be performed.
         * @param actionData Data that will be used.
         * @param reportFunction Function that will be use to log.
         */
        InsertAction(const std::string& table, const nlohmann::json& actionData,
                     const std::function<void(const char*)> reportFunction)
        {
            m_reportFunction = reportFunction;
            m_table = table;
            m_actionData = actionData;
            // FIMDB::getInstance().init();
        }

        /**
         * @brief Destroy the Insert Action object
         *
         */
        ~InsertAction() {}

        /**
         * @brief Execute the insert test. It will use the data stored in m_actionData to insert new entries in the DB.
         *
         */
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
                    while (entry_vector.empty() == false) {
                        fim_entry *entry = entry_vector.back();
                        entry_vector.pop_back();
                        m_reportFunction("Inserting registry entry:");

                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }
        }
};

/**
 * @brief Class to perform updates in a specific table using a JSON as a source.
 *
 */
class UpdateAction final : public TestAction
{
    public:
        /**
         * @brief Construct a new Update Action object
         *
         *
         * @param table Store the table where the action will be performed.
         * @param actionData Data that will be used.
         * @param reportFunction Function that will be use to log.
         */
        UpdateAction(const std::string& table, const nlohmann::json& actionData,
                     const std::function<void(const char*)> reportFunction)
        {
            m_reportFunction = reportFunction;
            m_table = table;
            m_precondData = actionData["precondition_data"];
            m_actionData = actionData["update_data"];
            // FIMDB::getInstance().init();
        }

        /**
         * @brief Execute the update test. It will insert the entries stored in m_precondData and after that it will
         *        update the entries stored in m_actionData
         *
         */
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
                    while (entry_vector.empty() == false) {
                        fim_entry *entry = entry_vector.back();
                        entry_vector.pop_back();
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
                    while (entry_vector.empty() == false) {
                        fim_entry *entry = entry_vector.back();
                        entry_vector.pop_back();
                        m_reportFunction("Updating registry entry:");

                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }
        }

    private:
        nlohmann::json m_precondData; /**< JSON with the data that will be inserted before updating. */
};

class RemoveAction final : public TestAction
{
    public:
        /**
         * @brief Construct a new Remove Action object
         *
         * @param table Store the table where the action will be performed.
         * @param actionData Data that will be used.
         * @param reportFunction Function that will be use to log.
         */
        RemoveAction(const std::string& table, const nlohmann::json& actionData,
                     const std::function<void(const char*)> reportFunction)
        {
            m_reportFunction = reportFunction;
            m_table = table;
            m_precondData = actionData["precondition_data"];
            m_actionData = actionData["delete_data"];
            // FIMDB::getInstance().init();
        }

        /**
         * @brief Execute the update test. It will insert the entries stored in m_precondData and after that it will
         *        remove the entries stored in m_actionData
         *
         */
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
                    while (entry_vector.empty() == false) {
                        fim_entry *entry = entry_vector.back();
                        entry_vector.pop_back();
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
                    while (entry_vector.empty() == false) {
                        fim_entry *entry = entry_vector.back();
                        entry_vector.pop_back();
                        m_reportFunction("Removing registry entry:");

                        print_entry(*entry, m_reportFunction);
                        free_entry(entry);
                    }
                }
            }
        }

    private:
        nlohmann::json m_precondData;  /**< JSON with the data that will be inserted before removing. */
};

#endif //_ACTION_H
