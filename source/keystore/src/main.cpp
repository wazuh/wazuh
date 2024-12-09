/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <filesystem>
#include <fstream>
#include <functional>

#include <base/logging.hpp>
#include <fs/homedirHelper.hpp>

#include "argsParser.hpp"
#include "keyStore.hpp"

int main(int argc, char* argv[])
{
    std::string key;
    std::string value;
    std::string valuePath;
    std::string keystorePath;

    // Logging init
    logging::LoggingConfig logConfig;
    logConfig.level = logging::strToLevel("info");

    logging::start(logConfig);

    try
    {
        // Define current working directory
        std::filesystem::path home_path = fs::findHomeDirectory();
        std::filesystem::current_path(home_path);

        CmdLineArgs args(argc, argv);

        key = args.getKey();
        value = args.getValue();
        valuePath = args.getValuePath();
        keystorePath = args.getKeystorePath();

        if (keystorePath.empty())
        {
            keystorePath = KEYSTORE_PATH;
        }

        if (value.empty() && valuePath.empty())
        {
            std::string valueFromStdin;
            std::getline(std::cin, valueFromStdin);

            if (!valueFromStdin.empty())
            {
                Keystore::put(key, valueFromStdin, keystorePath);
            }
            else
            {
                throw CmdLineArgsException("Error reading from stdin.");
            }
        }
        else if (!value.empty() && valuePath.empty())
        {
            Keystore::put(key, value, keystorePath);
        }
        else if (!valuePath.empty() && value.empty())
        {
            std::ifstream file(valuePath);
            if (!file.is_open())
            {
                throw CmdLineArgsException("Error opening file.");
            }

            std::string content;
            if (std::getline(file, content))
            {
                Keystore::put(key, content, keystorePath);
            }
            else
            {
                throw CmdLineArgsException("Error reading file.");
            }
        }
        else
        {
            throw CmdLineArgsException("Invalid arguments.");
        }
    }
    catch (const CmdLineArgsException& e)
    {
        std::cerr << e.what() << "\n";
        CmdLineArgs::showHelp();
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Unable to update key store file, no changes made. Reason: " << e.what() << "\n";
        return 1;
    }

    std::cout << "Key store file updated successfully.\n";

    return 0;
}
