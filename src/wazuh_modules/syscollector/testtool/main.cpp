/*
 * Wazuh SysCollector Test tool
 * Copyright (C) 2015, Wazuh Inc.
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
#include <chrono>
#include "defs.h"
#include "dbsync.hpp"
#include "rsync.hpp"
#include "sysInfo.hpp"
#include "syscollector.hpp"

constexpr int DEFAULT_SLEEP_TIME { 60 };

int main(int argc, const char* argv[])
{
    auto timedMainLoop { false };
    auto sleepTime { DEFAULT_SLEEP_TIME };

    if (2 == argc)
    {
        timedMainLoop = true;
        std::string firstArgument { argv[1] };

        sleepTime = firstArgument.find_first_not_of("0123456789") == std::string::npos ? std::stoi(firstArgument) : DEFAULT_SLEEP_TIME;

    }
    else if (2 < argc)
    {
        return -1;
    }

    const auto reportDiffFunction
    {
        [](const std::string & payload)
        {
            std::cout << "diff output payload:" << std::endl;
            std::cout << payload << std::endl;
        }
    };
    const auto reportSyncFunction
    {
        [](const std::string & payload)
        {
            std::cout << "sync output payload:" << std::endl;
            std::cout << payload << std::endl;
        }
    };

    const auto logFunction
    {
        [](const modules_log_level_t level, const std::string & log)
        {
            static const std::map<modules_log_level_t, std::string> s_logStringMap
            {
                {LOG_ERROR, "ERROR"},
                {LOG_INFO, "INFO"},
                {LOG_DEBUG, "DEBUG"},
                {LOG_DEBUG_VERBOSE, "DEBUG2"}
            };
            std::cout << s_logStringMap.at(level) << ": " << log << std::endl;
        }
    };

    const auto logErrorFunction
    {
        [](const std::string & log)
        {
            std::cout << "ERROR: " << log << std::endl;
        }
    };

    const auto spInfo{ std::make_shared<SysInfo>() };
    RemoteSync::initialize(logErrorFunction);
    DBSync::initialize(logErrorFunction);

    try
    {
        std::thread thread
        {
            [timedMainLoop, sleepTime]
            {
                if (!timedMainLoop)
                {
                    while (std::cin.get() != 'q');
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
                }

                Syscollector::instance().destroy();
            }
        };

        Syscollector::instance().init(spInfo,
                                      reportDiffFunction,
                                      reportSyncFunction,
                                      logFunction,
                                      SYSCOLLECTOR_DB_DISK_PATH,
                                      SYSCOLLECTOR_NORM_CONFIG_DISK_PATH,
                                      SYSCOLLECTOR_NORM_TYPE,
                                      15ul,
                                      true,
                                      true,
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
    catch (const std::exception& ex)
    {
        std::cout << ex.what() << std::endl;
    }

    RemoteSync::teardown();
    DBSync::teardown();
    return 0;
}
