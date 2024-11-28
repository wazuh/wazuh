/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * July 1, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <functional>
#include <iostream>

#include <base/logging.hpp>

#include "keyStore.hpp"
#include "testtoolArgsParser.hpp"

int main(int argc, char* argv[])
{
    // Logging init
    logging::LoggingConfig logConfig;
    logConfig.level = logging::strToLevel("debug");

    logging::start(logConfig);

    try
    {
        CmdLineArgs args(argc, argv);
        std::string key = args.getKey();
        std::string column = args.getColumnFamily();
        std::string value = args.getValue();
        std::string keystorePath = args.getKeystorePath();

        if (keystorePath.empty())
        {
            keystorePath = KEYSTORE_PATH;
        }

        if (value.empty())
        {
            Keystore::get(column, key, value, keystorePath);
            std::cout << value << std::endl;
        }
        else
        {
            Keystore::put(column, key, value, keystorePath);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
