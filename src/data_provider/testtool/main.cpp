/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "sysInfo.hpp"
#include "sysInfo.h"

int main()
{
    try
    {
        SysInfo info;
        const auto& hw        {info.hardware()};
        const auto& packages  {info.packages()};
        const auto& processes {info.processes()};
        const auto& networks  {info.networks()};
        const auto& os        {info.os()};
        const auto& ports     {info.ports()};

        std::cout << hw.dump() << std::endl;
        std::cout << packages.dump() << std::endl;
        std::cout << processes.dump() << std::endl;
        std::cout << networks.dump() << std::endl;
        std::cout << os.dump() << std::endl;
        std::cout << ports.dump() << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error getting system information: " << e.what() << std::endl;
    }
}