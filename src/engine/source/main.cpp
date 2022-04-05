/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <atomic>
#include <csignal>
#include <string>
#include <thread>
#include <vector>

#include <logging/logging.hpp>
#include <profile/profile.hpp>

#include "builder.hpp"
#include "catalog.hpp"
#include "catalog/storageDriver/disk/diskStorage.hpp"
#include "cliParser.hpp"
#include "engineServer.hpp"
#include "graph.hpp"
#include "json.hpp"
#include "protocolHandler.hpp"
#include "register.hpp"
#include "router.hpp"

#define WAIT_DEQUEUE_TIMEOUT_USEC (1 * 1000000)

using namespace engineserver;

// Static global variables for handling threads
static std::atomic<bool> gs_doRun = true;
static std::vector<std::thread> gs_threadList;

static void sigint_handler(const int signum)
{
    // Inform threads that they must exit
    gs_doRun = false;

    for (auto &t : gs_threadList)
    {
        t.join();
    };

    exit(0);
}

int main(int argc, char *argv[])
{
    sigset_t sig_empty_mask;
    sigemptyset(&sig_empty_mask);

    struct sigaction sigintAction;
    sigintAction.sa_handler = sigint_handler;
    sigintAction.sa_mask = sig_empty_mask;

    sigaction(SIGINT, &sigintAction, NULL);

    std::vector<std::string> serverArgs;
    std::string storagePath;
    int nThreads;
    size_t queueSize;
    bool traceAll;
    bool trace;
    std::vector<std::string> traceNames;

    try
    {
        // TODO: Add and check cliInput missing tests
        cliparser::CliParser cliInput(argc, argv);
        serverArgs.push_back(cliInput.getEndpointConfig());
        storagePath = cliInput.getStoragePath();
        nThreads = cliInput.getThreads();
        queueSize = cliInput.getQueueSize();
        traceAll = cliInput.getTraceAll();
        trace = cliInput.getTrace();
        traceNames = cliInput.getTraceNames();
    }
    catch (const std::exception &e)
    {
        WAZUH_LOG_ERROR("Error while parsing arguments: [{}]", e.what());
        return 1;
    }

    logging::LoggingConfig logConfig;
    // TODO add cmd to config logging level
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);

    // Server
    EngineServer server {serverArgs, queueSize};

    // Check if the server was correctly configured
    if (!server.isConfigured())
    {
        return 1;
    }

    // Catalog
    // TODO: Integrate configure and constructor
    catalog::Catalog _catalog;
    try
    {
        _catalog.setStorageDriver(std::make_unique<DiskStorage>(storagePath));
    }
    catch (const std::exception &e)
    {
        WAZUH_LOG_ERROR("Exception while creating catalog configuration : [{}]",
                        e.what());
        return 1;
    }

    // Builder
    try
    {
        builder::internals::registerBuilders();
    }
    catch (const std::exception &e)
    {
        WAZUH_LOG_ERROR("Exception while registering builders: [{}]", e.what());
        return 1;
    }
    // TODO: Handle errors on construction
    builder::Builder<catalog::Catalog> _builder(_catalog);

    // Processing Workers (Router), Router is replicated in each thread
    // TODO: handle hot modification of routes
    for (auto i = 0; i < nThreads; ++i)
    {
        std::thread t {
            [=, &eventBuffer = server.output()]()
            {
                WAZUH_PROFILE_THREAD_NAME(
                    fmt::format("[worker:{}]", i).c_str());
                router::Router<builder::Builder<catalog::Catalog>> router {
                    _builder};

                try
                {
                    // Default route
                    router.add("test_route", "test_environment");
                }
                catch (const std::exception &e)
                {
                    WAZUH_LOG_ERROR(
                        "Exception while building default route: [{}]",
                        e.what());
                    return 1;
                }

                // Trace cerr logger
                // TODO: this will need to be handled by the api and on the
                // reworked router
                auto cerrLogger = [name = "test_environment"](auto msg)
                {
                    std::stringstream ssTid;
                    ssTid << std::this_thread::get_id();
                    std::cerr
                        << fmt::format("{}: [{}]{}\n", ssTid.str(), name, msg);
                };
                if (traceAll)
                {
                    router.subscribeAllTraceSinks("test_environment",
                                                  cerrLogger);
                }
                else if (trace)
                {
                    for (auto assetName : traceNames)
                    {
                        router.subscribeTraceSink(
                            "test_environment", assetName, cerrLogger);
                    }
                }

                // Thread loop
                while (gs_doRun)
                {
                    std::string event;

                    if (eventBuffer.wait_dequeue_timed(
                            event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        WAZUH_TRACE_SCOPE("Router on-next");
                        router.input().on_next(ProtocolHandler::parse(event));
                    }
                }

                router.input().on_completed();
                return 0;
            }};

        gs_threadList.push_back(std::move(t));
    }

    server.run();

    logging::loggingTerm();

    return 0;
}
