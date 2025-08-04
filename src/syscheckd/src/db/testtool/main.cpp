/*
 * Wazuh Syscheck - Test tool
 * Copyright (C) 2015, Wazuh Inc.
 * January 21, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fstream>
#include <ostream>
#include <memory>
#include <json.hpp>
#include "db.hpp"
#include "fimDB.hpp"
#include "cmdArgsHelper.h"
#include "testContext.h"
#include "action.h"
#include "factoryAction.h"

static void loggerFunction(modules_log_level_t level, const char* msg)
{
    std::cout << "Level:" << level << " Msg: " << msg << std::endl;
}

int main(int argc, const char* argv[])
{
    try
    {
        CmdLineArgs cmdLineArgs(argc, argv);

        const auto actions { cmdLineArgs.actions() };

        std::cout << "Actions: " << actions.size() << std::endl;

        std::ifstream configFile{ cmdLineArgs.configFile() };

        if (configFile.good())
        {
            const auto& jsonConfigFile { nlohmann::json::parse(configFile) };
            const auto storageType{ jsonConfigFile.at("storage_type").get<const uint32_t>() };
            const auto fileLimit{ jsonConfigFile.at("file_limit").get<const uint32_t>() };
            const auto registryLimit{ jsonConfigFile.at("registry_limit").get<const uint32_t>() };

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    loggerFunction(level, log.c_str());
                }
            };

            try
            {
                DB::instance().init(storageType,
                                    callbackLogWrapper,
                                    fileLimit,
                                    registryLimit);

                std::unique_ptr<TestContext> testContext { std::make_unique<TestContext>()};
                testContext->outputPath = cmdLineArgs.outputFolder();

                // Let's take the input json list and apply the changes to the db
                for (size_t idx = 0; idx < actions.size(); ++idx)
                {
                    testContext->currentId = idx;
                    const std::string inputFile{ actions[idx] };
                    std::ifstream actionsIdxFile{ inputFile };
                    std::cout << "Processing file: " << inputFile << std::endl;
                    const auto& jsonAction { nlohmann::json::parse(actionsIdxFile) };
                    auto action { FactoryAction::create(jsonAction.at("action").get<std::string>()) };
                    action->execute(testContext, jsonAction.at("body"));
                }

                DB::instance().teardown();
                std::cout << "Resulting files are located in the "
                          << cmdLineArgs.outputFolder() << " folder" << std::endl;
            }
            catch (const std::exception& e)
            {
                std::cerr << std::endl
                          << "Something went wrong configuring the database. Please, check the config file data, "
                          << e.what() << std::endl;
            }
        }
        else
        {
            throw std::runtime_error { "The config file is not valid. Please, check the config file data" };
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        CmdLineArgs::showHelp();
    }

    return 0;
}
