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

#include "keyStore.hpp"
#include "argsParser.hpp"

int main(const int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);

        std::string family = args.getColumnFamily();
        std::string key = args.getKey();
        std::string value = args.getValue();

        Keystore keystore;
        keystore.put(family, key, value);
    }
    catch (const std::exception& e)
    {
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}
