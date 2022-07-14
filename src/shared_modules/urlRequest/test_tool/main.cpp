/*
 * Wazuh urlRequest TestTool
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "cmdArgsParser.hpp"
#include "factoryAction.hpp"

int main(const int argc, const char* argv[])
{
    auto retVal { 0 };

    try
    {
        CmdLineArgs cmdLineArgs(argc, argv);
        FactoryAction::create(cmdLineArgs)->execute();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        retVal = 1;
    }

    return retVal;
}
