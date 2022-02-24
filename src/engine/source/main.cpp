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
#include "register.hpp"
#include "router.hpp"
#include "threadPool.hpp"

using std::endl;
using std::exception;
using std::make_unique;
using std::string;
using std::vector;

int main(int argc, char * argv[])
{
    signal(SIGINT, [](auto s) { exit(1); });

    google::InitGoogleLogging(argv[0]);
    vector<string> serverArgs;
    string storagePath;
    try
    {
        cliparser::CliParser cliInput(argc, argv);
        serverArgs.push_back(cliInput.getEndpointConfig());
        storagePath = cliInput.getStoragePath();
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

    // Build router
    // TODO: Integrate filter creation with builder and default route with catalog

    router::Router<builder::Builder<catalog::Catalog>> router{server.output(), _builder};

    try
    {
        const int nThreads{8};
        // Default route
        router.add("test_route", "test_environment", nThreads);
    }
    catch (const exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while building default route: " << e.what() << endl;
        return 1;
    }

    server.run();

    return 0;
}
