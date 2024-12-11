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

#include "argsParser.hpp"
#include "homedirHelper.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include <filesystem>
#include <fstream>
#include <functional>

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

int main(int argc, char* argv[])
{
    std::string family;
    std::string key;
    std::string value;
    std::string valuePath;

    Log::assignLogFunction(
        [](const int logLevel,
           const std::string&,
           const std::string&,
           const int,
           const std::string&,
           const std::string& str,
           va_list args)
        {
            char formattedStr[MAXLEN] = {0};
            vsnprintf(formattedStr, MAXLEN, str.c_str(), args);

            if (logLevel == Log::LOGLEVEL_ERROR || logLevel == Log::LOGLEVEL_CRITICAL ||
                logLevel == Log::LOGLEVEL_WARNING)
            {
                std::cerr << formattedStr << "\n";
            }
            else
            {
                std::cout << formattedStr << "\n";
            }
        });

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
