/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * August 28, 2020.
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
#include "agentEmulator.h"
#include "managerEmulator.h"
#include "cmdArgsHelper.h"
#include "oneTimeSync.h"

static void logFunction(const char* msg)
{
    std::cout << msg << std::endl;
}

int main(int argc, const char* argv[])
{
    try
    {
        rsync_initialize(logFunction);
        dbsync_initialize(logFunction);
        CmdLineArgs args{argc, argv};

        if (args.inputData().empty())
        {
            const auto syncQueue
            {
                std::make_shared<SyncQueue>()
            };
            const std::chrono::milliseconds syncPeriod{100};
            const auto maxDbItems{100};
            const size_t maxQueueSize{UNLIMITED_QUEUE_SIZE};
            AgentEmulator agent{syncPeriod, maxDbItems, syncQueue, args.outputFolder(), maxQueueSize};
            ManagerEmulator manager{syncQueue};

            while (getc(stdin) != 'q');
        }
        else
        {
            std::ifstream configFile{ args.config() };
            std::ifstream inputData{ args.inputData() };

            if (!configFile.good())
            {
                throw std::runtime_error
                {
                    "Invalid config file."
                };
            }

            if (!inputData.good())
            {
                throw std::runtime_error
                {
                    "Invalid inputs file."
                };
            }

            const auto& jsonConfigFile { nlohmann::json::parse(configFile) };
            const auto& jsonInputFile { nlohmann::json::parse(inputData) };
            const size_t maxQueueSize{UNLIMITED_QUEUE_SIZE};
            OneTimeSync otSync(jsonConfigFile,
                               jsonInputFile,
                               args.outputFolder(),
                               maxQueueSize);
            otSync.syncData();
            otSync.pushData();
            otSync.startSync();
        }
    }
    catch (const std::exception& ex)
    {
        std::cout << ex.what() << std::endl;
        CmdLineArgs::showHelp();
    }

    rsync_teardown();
    dbsync_teardown();
    return 0;
}
