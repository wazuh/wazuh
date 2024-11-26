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
#include <base/utils/homedirHelper.hpp>

#include "argsParser.hpp"
#include "keyStore.hpp"

int main(int argc, char* argv[])
{
    std::string family;
    std::string key;
    std::string value;
    std::string valuePath;

    try
    {
        // Define current working directory
        std::filesystem::path home_path = Utils::findHomeDirectory();
        std::filesystem::current_path(home_path);

        CmdLineArgs args(argc, argv);

        family = args.getColumnFamily();
        key = args.getKey();
        value = args.getValue();
        valuePath = args.getValuePath();

        if (value.empty() && valuePath.empty())
        {
            std::string valueFromStdin;
            std::getline(std::cin, valueFromStdin);

            if (!valueFromStdin.empty())
            {
                Keystore::put(family, key, valueFromStdin);
            }
            else
            {
                throw CmdLineArgsException("Error reading from stdin.");
            }
        }
        else if (!value.empty() && valuePath.empty())
        {
            Keystore::put(family, key, value);
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
                Keystore::put(family, key, content);
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
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}
