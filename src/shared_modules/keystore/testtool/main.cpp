/*
 * Wazuh keystore
 * Copyright (C) Wazuh Inc.
 * July 1, 2024.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "keyStore.hpp"
#include "testtoolArgsParser.hpp"
#include <functional>
#include <iostream>

int main(int argc, char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);
        std::string key = args.getKey();
        std::string column = args.getColumnFamily();
        std::string value = args.getValue();

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
