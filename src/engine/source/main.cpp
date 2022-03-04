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
#include <atomic>

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

#define WAIT_DEQUEUE_TIMEOUT_USEC 1 * 1000000

using namespace std;

static std::atomic<bool> gs_doRun = true;
static std::vector<std::thread> gs_threadList;

static void sigint_handler(const int signum)
{
    // Inform threads that they should exit
    gs_doRun = false;

    for (auto & t : gs_threadList)
    {
        t.join();
    };

    exit(0);
}

int main(int argc, char * argv[])
{
    signal(SIGINT, sigint_handler);

    // Configure
    google::InitGoogleLogging(argv[0]);
    vector<string> serverArgs;
    string storagePath;
    int nThreads;
    size_t queueSize;

    try
    {
        // TODO: Add and check cliInput missing tests
        cliparser::CliParser cliInput(argc, argv);
        serverArgs.push_back(cliInput.getEndpointConfig());
        storagePath = cliInput.getStoragePath();
        nThreads = cliInput.getThreads();
        queueSize = cliInput.getQueueSize();
    }
    catch (const exception & e)
    {
        LOG(ERROR) << "Error while parsing arguments: " << e.what() << endl;
        return 1;
    }

    // Server
    // TODO: Integrate configure and constructor
    engineserver::EngineServer server{queueSize};
    try
    {
        server.configure(serverArgs);
    }
    catch (const exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while configuring server: " << e.what() << endl;
        // TODO: handle if errors on close can happen
        return 1;
    }

    // Catalog
    // TODO: Integrate configure and constructor
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
    // TODO: Handle errors on construction
    builder::Builder<catalog::Catalog> _builder(_catalog);

    // Processing Workers (Router), Router is replicated in each thread
    // TODO: handle hot modification of routes
    for (auto i = 0; i < nThreads; ++i)
    {
        std::thread t{[=, &eventBuffer = server.output()]()
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

                          // TODO: This should be a method
                          engineserver::ProtocolHandler p;

                          // Thread loop
                          std::string event;
                          while (gs_doRun)
                          {
                              if (eventBuffer.wait_dequeue_timed(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                              {
                                  router.input().on_next(p.parse(event));
                              }
                          }
                          return 0;
                      }};

        gs_threadList.push_back(std::move(t));
    }

    // Server loop
    server.run();

    return 0;
}
