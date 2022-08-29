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
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <CLI/CLI.hpp>

#include <builder.hpp>
#include <catalog.hpp>
#include <engineServer.hpp>
#include <graph.hpp>
#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <profile/profile.hpp>
#include <protocolHandler.hpp>
#include <register.hpp>
// #include <router.hpp>
#include <hlp/hlp.hpp>
#include <rxbk/rxFactory.hpp>
#include <wdb/wdb.hpp>

constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

// Static global variables for handling threads
static std::atomic<bool> gs_doRun = true;
static std::vector<std::thread> gs_threadList;

// Arguments configuration
namespace args
{
// Subcommand names
constexpr auto SUBCOMMAND_RUN = "run";
constexpr auto SUBCOMMAND_LOGTEST = "logtest";
constexpr auto SUBCOMMAND_GRAPH = "generate_graph";

// Arguments
static std::string endpoint;
static std::string file_storage;
static unsigned int queue_size;
static unsigned int threads;
static std::string kvdb_path;
static std::string environment;

void configureSubcommandRun(std::shared_ptr<CLI::App> app)
{
    CLI::App* run =
        app->add_subcommand(args::SUBCOMMAND_RUN, "Run the Wazuh engine module.");

    // Endpoint
    run->add_option("-e, --endpoint",
                    args::endpoint,
                    "Endpoint configuration string. Specifies the endpoint where the "
                    "engine module will be listening for incoming connections. "
                    "PROTOCOL_STRING = <protocol>:<ip>:<port>")
        ->option_text("TEXT:PROTOCOL_STRING REQUIRED")
        ->required();

    // Threads
    run->add_option("-t, --threads",
                    args::threads,
                    "Number of dedicated threads for the environment.")
        ->default_val(1);

    // File storage
    run->add_option("-f, --file_storage",
                    args::file_storage,
                    "Path to folder where assets are located.")
        ->required()
        ->check(CLI::ExistingDirectory);

    // Queue size
    run->add_option("-q, --queue_size",
                    args::queue_size,
                    "Number of events that can be queued for processing.")
        ->default_val(1000000);

    // KVDB path
    run->add_option("-k, --kvdb_path", args::kvdb_path, "Path to KVDB folder.")
        ->default_val("/var/ossec/queue/db/kvdb/")
        ->check(CLI::ExistingDirectory);

    // Environment
    run->add_option("--environment", args::environment, "Environment name.")
        ->required();
}

void configureSubcommandLogtest(std::shared_ptr<CLI::App> app)
{
    CLI::App* logtest = app->add_subcommand(args::SUBCOMMAND_LOGTEST,
                                            "Run the Wazuh engine module in test mode.");
}

void configureSubcommandGraph(std::shared_ptr<CLI::App> app)
{
    CLI::App* graph = app->add_subcommand(
        args::SUBCOMMAND_GRAPH,
        "Validate and generate environment graph and expression graph.");
}

std::shared_ptr<CLI::App> configureCliApp()
{
    auto app = std::make_shared<CLI::App>(
        "Wazuh engine module. Check Subcommands for more information.");
    app->require_subcommand();

    // Add subcommands
    configureSubcommandRun(app);
    configureSubcommandLogtest(app);
    configureSubcommandGraph(app);

    return app;
}
} // namespace args

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

// Get all exceptions nested also
static std::string getFullException(const std::exception& e, int level = 0)
{
    std::stringstream ss;
    ss << std::string(level, ' ') << "exception: " << e.what() << '\n';
    try
    {
        std::rethrow_if_nested(e);
    }
    catch (const std::exception& nestedException)
    {
        ss << getFullException(nestedException, level + 1);
    }
    catch (...)
    {
    }

    return ss.str();
}

static void run()
{
    // Init logging
    // TODO: add cmd to config logging level
    logging::LoggingConfig logConfig;
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);

    KVDBManager::init(args::kvdb_path);

    engineserver::EngineServer server {{args::endpoint},
                                       static_cast<size_t>(args::queue_size)};
    if (!server.isConfigured())
    {
        WAZUH_LOG_ERROR("Could not configure server for endpoint [{}], engine "
                        "inizialization aborted.",
                        args::endpoint);
        return;
    }

    catalog::Catalog _catalog(catalog::StorageType::Local, args::file_storage);

    auto hlpParsers =
        _catalog.getFileContents(catalog::AssetType::Schema, "wazuh-logql-types");
    // TODO because builders don't have access to the catalog we are configuring
    // the parser mappings on start up for now
    hlp::configureParserMappings(hlpParsers);

    try
    {
        builder::internals::registerBuilders();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while registering builders: [{}]",
                        getFullException(e));
        return;
    }
    // TODO: Handle errors on construction
    builder::Builder<catalog::Catalog> _builder(_catalog);
    decltype(_builder.buildEnvironment(args::environment)) env;
    try
    {
        env = _builder.buildEnvironment(args::environment);
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Exception while building environment: [{}]",
                        getFullException(e));
        return;
    }

    // Processing Workers (Router), Router is replicated in each thread
    // TODO: handle hot modification of routes
    for (auto i = 0; i < args::threads; ++i)
    {
        std::thread t {
            [=, &eventBuffer = server.output()]()
            {
                auto controller = rxbk::buildRxPipeline(env);

                // else if (trace)
                // {
                //     for (auto assetName : traceNames)
                //     {
                //         router.subscribeTraceSink(
                //             "test_environment", assetName, cerrLogger);
                //     }
                // }

                // Thread loop
                while (gs_doRun)
                {
                    std::string event;

                    if (eventBuffer.wait_dequeue_timed(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        WAZUH_TRACE_SCOPE("Router on-next");
                        try
                        {
                            auto result = base::result::makeSuccess(
                                engineserver::ProtocolHandler::parse(event));
                            controller.ingestEvent(
                                std::make_shared<base::result::Result<base::Event>>(
                                    std::move(result)));
                        }
                        catch (const std::exception& e)
                        {
                            WAZUH_LOG_ERROR(
                                "An error ocurred while parsing a message: [{}]",
                                e.what());
                        }
                    }
                }

                controller.complete();
                return 0;
            }};

        gs_threadList.push_back(std::move(t));
    }

    server.run();

    logging::loggingTerm();

    return;
}

static void logtest() {}

static void graph() {}

int main(int argc, char* argv[])
{
    // Set Crt+C handler
    sigset_t sig_empty_mask;
    sigemptyset(&sig_empty_mask);

    struct sigaction sigintAction;
    sigintAction.sa_handler = sigint_handler;
    sigintAction.sa_mask = sig_empty_mask;

    sigaction(SIGINT, &sigintAction, NULL);

    // Configure argument parsers
    auto app = args::configureCliApp();
    CLI11_PARSE(*app, argc, argv);

    // Launch parsed subcommand
    if (app->get_subcommand(args::SUBCOMMAND_RUN)->parsed())
    {
        run();
    }
    else if (app->get_subcommand(args::SUBCOMMAND_LOGTEST)->parsed())
    {
        logtest();
    }
    else if (app->get_subcommand(args::SUBCOMMAND_GRAPH)->parsed())
    {
        graph();
    }
    else
    {
        // This code should never reach as parse is configured to required a subcommand
        WAZUH_LOG_ERROR("No subcommand specified when launching engine, use -h for "
                        "detailed information.");
    }

    return 0;
}
