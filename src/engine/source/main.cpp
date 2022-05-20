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

#include <argparse/argparse.hpp>

#include <builder.hpp>
#include <catalog.hpp>
#include <engineServer.hpp>
#include <graph.hpp>
#include <json.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <profile/profile.hpp>
#include <protocolHandler.hpp>
#include <register.hpp>
#include <router.hpp>
#include <hlp/hlp.hpp>
#include <wdb/wdb.hpp>

#define WAIT_DEQUEUE_TIMEOUT_USEC (1 * 1000000)

using namespace engineserver;

// Static global variables for handling threads
static std::atomic<bool> gs_doRun = true;
static std::vector<std::thread> gs_threadList;

static void sigint_handler(const int signum)
{
    // Inform threads that they must exit
    gs_doRun = false;

    for (auto& t : gs_threadList)
    {
        t.join();
    };

    exit(0);
}

static auto configureCliArgs()
{
    argparse::ArgumentParser argParser("server");

    argParser.add_argument("-e", "--endpoint")
        .help("Endpoint configuration string")
        .required();

    argParser.add_argument("-t", "--threads")
        .help("Set the number of threads to use while computing")
        .scan<'i', int>()
        .default_value(1);

    argParser.add_argument("-f", "--file_storage")
        .help("Path to storage folder")
        .required();

    argParser.add_argument("-q", "--queue_size")
        .help("Number of events that can be queued for processing")
        .scan<'i', int>()
        .default_value(1000000);

    // TODO this is just to give the posibility to avoid a 'protected' folder
    // on the developement cycle of the engine. This would come from a config
    // later on and the option will be removed
    argParser.add_argument("--kvdbPath")
        .help("Optional path where the kvdb will be created")
        .default_value<std::string>("/var/ossec/queue/db/kvdb/");

    argParser.add_argument("-T", "--trace_all")
        .help("Subscribe to all trace sinks and print in cerr")
        .default_value(false)
        .implicit_value(true);

    argParser.add_argument("--trace")
        .help("Subscribe to specified trace sinks and print in cerr")
        .default_value(false)
        .implicit_value(true);

    argParser.add_argument("trace_assets").remaining();

    return argParser;
}

int main(int argc, char* argv[])
{
    sigset_t sig_empty_mask;
    sigemptyset(&sig_empty_mask);

    struct sigaction sigintAction;
    sigintAction.sa_handler = sigint_handler;
    sigintAction.sa_mask = sig_empty_mask;

    sigaction(SIGINT, &sigintAction, NULL);

    auto argParser = configureCliArgs();
    try
    {
        argParser.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err)
    {
        WAZUH_LOG_ERROR("Invalid command line arguments: [{}]", err.what());
        std::cout << argParser.help().str();
        return -1;
    }

    auto serverArgs = argParser.get("--endpoint");
    auto storagePath = argParser.get("--file_storage");
    auto nThreads = argParser.get<int>("--threads");
    auto queueSize = argParser.get<int>("--queue_size");
    auto kvdbPath = argParser.get("--kvdbPath");
    auto traceAll = argParser.get<bool>("--trace_all");
    auto trace = argParser.get<bool>("--trace");
    std::vector<std::string> traceNames;
    if (trace)
    {
        traceNames = argParser.get<std::vector<std::string>>("trace_assets");
    }

    logging::LoggingConfig logConfig;
    // TODO add cmd to config logging level
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);

    KVDBManager::init(kvdbPath);

    EngineServer server {{serverArgs}, static_cast<size_t>(queueSize)};
    if (!server.isConfigured())
    {
        return 1;
    }

    catalog::Catalog _catalog(catalog::StorageType::Local, storagePath);

    auto hlpParsers = _catalog.getFileContents(catalog::AssetType::Schema,
                                               "wazuh-logql-types");
    // TODO because builders don't have access to the catalog we are configuring
    // the parser mappings on start up for now
    hlp::configureParserMappings(hlpParsers);

    try
    {
        builder::internals::registerBuilders();
    }
    catch (const std::exception& e)
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
                catch (const std::exception& e)
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
