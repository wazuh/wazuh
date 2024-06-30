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
#include <iostream>

void setWorkingDirectory()
{
    try
    {
        std::filesystem::path home_path = Utils::findHomeDirectory();
        std::filesystem::current_path(home_path);
        logDebug1("keystore", "Set current working directory to: %s", home_path.c_str());
    }
    catch (const std::exception& e)
    {
        logError("keystore", "Failed to set working directory: %s", e.what());
        throw;
    }
}

void parseArguments(int argc, char* argv[], std::string& family, std::string& key, std::string& value)
{
    try
    {
        CmdLineArgs args(argc, argv);
        family = args.getColumnFamily();
        key = args.getKey();
        value = args.getValue();

        if (family.empty() || key.empty() || value.empty())
        {
            throw std::invalid_argument("Column family, key, and value must be provided");
        }

        logDebug1("keystore", "Parsed arguments - Family: %s, Key: %s", family.c_str(), key.c_str());
    }
    catch (const CmdLineArgsException& e)
    {
        logError("keystore", "Command line argument error: %s", e.what());
        CmdLineArgs::showHelp();
        throw;
    }
    catch (const std::invalid_argument& e)
    {
        logError("keystore", "Invalid argument: %s", e.what());
        CmdLineArgs::showHelp();
        throw;
    }
    catch (const std::exception& e)
    {
        logError("keystore", "Failed to parse arguments: %s", e.what());
        throw;
    }
}

void storeKeyValue(const std::string& family, const std::string& key, const std::string& value)
{
    try
    {
        Keystore::put(family, key, value);
        logDebug1("keystore", "Stored key-value pair - Family: %s, Key: %s", family.c_str(), key.c_str());
    }
    catch (const std::exception& e)
    {
        logError("keystore", "Exception during keystore operation: %s", e.what());
        throw;
    }
}

int main(int argc, char* argv[])
{
    std::string family;
    std::string key;
    std::string value;

    try
    {
        setWorkingDirectory();
        parseArguments(argc, argv, family, key, value);
        storeKeyValue(family, key, value);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
