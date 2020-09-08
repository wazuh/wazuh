/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
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

static void logFunction(const char* msg)
{
    std::cout << msg << std::endl;
}

int main(int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args{argc, argv};
        rsync_initialize(logFunction);
        dbsync_initialize(logFunction);
        const auto syncQueue
        {
            std::make_shared<SyncQueue>()
        };
        const std::chrono::milliseconds syncPeriod{100};
        const auto maxDbItems{100};
        AgentEmulator agent{syncPeriod, maxDbItems, syncQueue, args.outputFolder()};
        ManagerEmulator manager{syncQueue};
        while(getc(stdin) != 'q');
    }
    catch(const std::exception& ex)
    {
        std::cout << ex.what() << std::endl;
    }
    rsync_teardown();
    return 0;
}