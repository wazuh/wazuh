/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// TODO: rename files as wazuh style
// TODO: delete dummy test/benchmarks examples, no longer needed
// TODO: QoL CMakeLists

#include <csignal>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <vector>

#include "Catalog.hpp"
#include "builder.hpp"
#include "catalog/storageDriver/disk/DiskStorage.hpp"
#include "cliParser.hpp"
#include "engineServer.hpp"
#include "glog/logging.h"
#include "graph.hpp"
#include "json.hpp"
#include "protocolHandler.hpp"
// #include "queue.hpp"
#include "register.hpp"
#include "router.hpp"
#include "threadPool.hpp"

using namespace std;

int main(int argc, char * argv[])
{
    signal(SIGINT, [](auto s) { exit(1); });

    google::InitGoogleLogging(argv[0]);
    vector<string> serverArgs;
    string storagePath;
    int nThreads;

    try
    {
        cliparser::CliParser cliInput(argc, argv);
        serverArgs.push_back(cliInput.getEndpointConfig());
        storagePath = cliInput.getStoragePath();
        nThreads = cliInput.getThreads();
    }
    catch (const exception & e)
    {
        LOG(ERROR) << "Error while parsing arguments: " << e.what() << endl;
        return 1;
    }

    engineserver::EngineServer server;
    try
    {
        server.configure(serverArgs);
    }
    catch (const exception & e)
    {
        // TODO: implement log with GLOG
        LOG(ERROR) << "Engine error, got exception while configuring server: " << e.what() << endl;
        // TODO: handle if errors on close can happen
        return 1;
    }

    // hardcoded catalog storage driver
    // TODO: use argparse module
    catalog::Catalog _catalog;
    try
    {
        _catalog.setStorageDriver(make_unique<DiskStorage>(storagePath));
    }
    catch (const exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while configuring catalog: " << e.what() << endl;
        return 1;
    }

    // Builder
    try
    {
        builder::internals::registerBuilders();
    }
    catch (const exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while registering builders: " << e.what() << endl;
        return 1;
    }
    builder::Builder<catalog::Catalog> _builder(_catalog);


    // Router is built in each thread
    for (auto i = 0; i < nThreads; ++i)
    {
        std::thread t{[=]()
        {
            router::Router<builder::Builder<catalog::Catalog>> router{_builder};

            try
            {
                // Default route
                router.add("test_route", "test_environment");
            }
            catch (const exception & e)
            {
                LOG(ERROR) << "Engine error, got exception while building default route: " << e.what()
                            << endl;
                return 1;
            }

            engineserver::ProtocolHandler p;
            // Start thread loop
            while(true){
                std::string event;
                threadpool::queue2.wait_dequeue(event);
                // threadpool::queue;
                router.input().on_next(p.parse(event));
            }
        }};

        t.detach();
    }

    // Start main loop
    // server.output()
    //     .subscribe(
    //         [](std::string raw){
    //             threadpool::queue2.enqueue(std::move(raw));
    //         },
    //         [](auto eptr){},
    //         [](){}
    //     );
    server.run();

    return 0;
}
