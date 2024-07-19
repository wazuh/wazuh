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

#include "keyStore.hpp"
#include "testtoolArgsParser.hpp"
#include <functional>
#include <iostream>

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

int main(int argc, char* argv[])
{
    CmdLineArgs args(argc, argv);
    std::string key = args.getKey();
    std::string column = args.getColumnFamily();
    std::string value = args.getValue();

    try
    {
        if (value.empty())
        {
            Keystore::get(column, key, value);
            std::cout << value << std::endl;
        }
        else
        {
            Keystore::put(column, key, value);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
