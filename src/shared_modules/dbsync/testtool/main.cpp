/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * July 02, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fstream>
#include <stdio.h>
#include <memory>
#include <json.hpp>
#include "makeUnique.h"
#include "dbsync.h"
#include "cmdArgsHelper.h"
#include "testContext.h"
#include "action.h"
#include "factoryAction.h"

static void loggerFunction(const char* msg)
{
    std::cout << "Msg: " << msg << std::endl;
}

int main(int argc, const char* argv[])
{
    try
    {
        CmdLineArgs cmdLineArgs(argc, argv);

        const auto actions { cmdLineArgs.actions() };

        // dbsync configuration data
        std::ifstream configFile{ cmdLineArgs.configFile() };
        const auto& jsonConfigFile { nlohmann::json::parse(configFile) };
        const std::string dbName{ jsonConfigFile.at("db_name").get_ref<const std::string&>() };
        const std::string dbType{ jsonConfigFile.at("db_type").get_ref<const std::string&>() };
        const std::string hostType{ jsonConfigFile.at("host_type").get_ref<const std::string&>() };
        const std::string persistance{ jsonConfigFile.at("persistance").get_ref<const std::string&>() };
        const std::string sqlStmt{ jsonConfigFile.at("sql_statement").get_ref<const std::string&>() };

        dbsync_initialize(loggerFunction);

        DBSYNC_HANDLE handle {0};

        if (persistance.compare("1") == 0)
        {
            handle = dbsync_create_persistent((hostType.compare("0") == 0) ? HostType::MANAGER : HostType::AGENT,
                                              (dbType.compare("1") == 0) ? DbEngineType::SQLITE3 : DbEngineType::UNDEFINED,
                                              dbName.c_str(),
                                              sqlStmt.c_str(),
                                              nullptr);

        }
        else
        {
            handle = dbsync_create((hostType.compare("0") == 0) ? HostType::MANAGER : HostType::AGENT,
                                   (dbType.compare("1") == 0) ? DbEngineType::SQLITE3 : DbEngineType::UNDEFINED,
                                   dbName.c_str(),
                                   sqlStmt.c_str());
        }

        if (0 != handle)
        {
            std::unique_ptr<TestContext> testContext { std::make_unique<TestContext>()};
            testContext->handle = handle;
            testContext->outputPath = cmdLineArgs.outputFolder();

            // Let's take the input json list and apply the changes to the db
            for (size_t idx = 0; idx < actions.size(); ++idx)
            {
                testContext->currentId = idx;
                const std::string inputFile{ actions[idx] };
                std::ifstream actionsIdxFile{ inputFile };
                std::cout << "Processing file: " << inputFile << std::endl;
                const auto& jsonAction { nlohmann::json::parse(actionsIdxFile) };
                auto action { FactoryAction::create(jsonAction["action"].get<std::string>()) };
                action->execute(testContext, jsonAction);
            }

            dbsync_teardown();
            std::cout << "Resulting files are located in the " << cmdLineArgs.outputFolder() << " folder" << std::endl;
        }
        else
        {
            std::cout << std::endl << "Something went wrong configuring the database. Please, check the config file data" << std::endl;
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        CmdLineArgs::showHelp();
    }

    return 0;
}
