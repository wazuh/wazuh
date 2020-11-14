/*
 * Wazuh SysCollector Test tool
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fstream>
#include <iostream>
#include <stdio.h>
#include <memory>
#include "dbsync.h"
#include "rsync.h"
#include "sysInfo.hpp"
#include "syscollectorImp.h"

static void logFunction(const char* msg)
{
    std::cout << msg << std::endl;
}

int main(int argc, const char* argv[])
{
    const std::chrono::milliseconds timeout{5000};
    const auto spInfo{ std::make_shared<SysInfo>() };
    rsync_initialize(logFunction);
    dbsync_initialize(logFunction);
    try
    {
        std::thread thread
        {
            []
            {
                while(std::cin.get() != 'q');
                Syscollector::instance().destroy();
            }
        };

        Syscollector::instance().init(spInfo,
                                      "15s",
                                      true,
                                      true,
                                      true,
                                      true,
                                      true,
                                      true,
                                      true,
                                      true,
                                      true);

        if (thread.joinable())
        {
            thread.join();
        }
    }
    catch(const std::exception& ex)
    {
        std::cout << ex.what() << std::endl;
    }
    rsync_teardown();
    dbsync_teardown();
    return 0;
}