#include "cmds/start.hpp"

#include <atomic>
#include <csignal>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <api/api.hpp>
#include <api/catalog/catalog.hpp>
#include <api/catalog/commands.hpp>
#include <api/config/config.hpp>
#include <api/kvdb/commands.hpp>
#include <api/router/commands.hpp>
#include <builder/builder.hpp>
#include <builder/register.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <hlp/logpar.hpp>
#include <hlp/registerParsers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <router/router.hpp>
#include <rxbk/rxFactory.hpp>
#include <server/engineServer.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "defaultSettings.hpp"
#include "register.hpp"
#include "registry.hpp"

namespace
{
cmd::details::StackExecutor g_exitHanlder {};

void sigint_handler(const int signum)
{
    g_exitHanlder.execute();
    exit(EXIT_SUCCESS);
}

struct Options
{
    std::string kvdbPath;
    std::string eventEndpoint;
    std::string apiEndpoint;
    int queueSize;
    int threads;
    std::string fileStorage;
    int logLevel;
    std::string logOutput;
    std::vector<std::string> environment;
    bool forceRouterArg;
    std::string floodFilePath;
};

} // namespace

namespace cmd::server
{
void runStart(ConfHandler confManager)
{
    // Get needed configuration on main function
    const auto logLevel = confManager->get<int>("server.log_level");
    const auto logOutput = confManager->get<std::string>("server.log_output");
    const auto confPath = confManager->get<std::string>("config");

    // Server config
    const auto queueSize = confManager->get<int>("server.queue_size");
    const auto eventEndpoint = confManager->get<std::string>("server.event_socket");
    const auto apiEndpoint = confManager->get<std::string>("server.api_socket");
    const auto threads = confManager->get<int>("server.threads");
    const auto floodFilePath = confManager->get<std::string>("server.flood_file");

    std::optional<std::string> floodFile = std::nullopt;
    if (!floodFilePath.empty())
    {
        floodFile = floodFilePath;
    }

    // KVDB config
    const auto kvdbPath = confManager->get<std::string>("server.kvdb_path");

    // Store config
    const auto fileStorage = confManager->get<std::string>("server.store_path");

    // Start environment
    const auto environment = confManager->get<std::vector<std::string>>("server.start.environment");
    const auto routeName = environment[0];
    int routePriority;
    try
    {
        routePriority = std::stoi(environment[1]);
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Invalid route priority '{}'", environment[1]);
        exit(EXIT_FAILURE); // TODO Change whens add the LOG_CRITICAL / LOG_FATAL
    }
    const auto routeFilter = environment[2];
    const auto routeEnvironment = environment[3];
    const auto forceRouterArg = confManager->get<bool>("server.start.force_router_arg");

    // Set Crt+C handler
    {
        // Set the signal handler for SIGINT
        struct sigaction sigIntHandler;
        sigIntHandler.sa_handler = sigint_handler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;
        sigaction(SIGINT, &sigIntHandler, nullptr);
    }

    // Init logging
    logging::LoggingConfig logConfig;
    switch (logLevel)
    {
        case 0: logConfig.logLevel = logging::LogLevel::Debug; break;
        case 1: logConfig.logLevel = logging::LogLevel::Info; break;
        case 2: logConfig.logLevel = logging::LogLevel::Warn; break;
        case 3: logConfig.logLevel = logging::LogLevel::Error; break;
        default: logging::LogLevel::Error;
    }
    logConfig.header = "{YmdHMSe} {t} {l}: "; // On debug mode, add the thread id, file, function and line
    logConfig.filePath = logOutput.c_str();
    logging::loggingInit(logConfig);
    g_exitHanlder.add([]() { logging::loggingTerm(); });
    WAZUH_LOG_INFO("Logging initialized");
    // WAZUH_LOG_DEBUG("Log output in '{}'", logConfig.filePath);
    WAZUH_LOG_DEBUG("Logging poll interval '{}'", logConfig.pollInterval);

    // Init modules
    std::shared_ptr<store::FileDriver> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<engineserver::EngineServer> server;
    std::shared_ptr<router::Router> router;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdb_manager::KVDBManager> kvdb;

    try
    {
        const auto bufferSize {static_cast<size_t>(queueSize)};

        // TODO Add the option to configure the flooded file
        // TODO Change the default buffer size to a multiple of 1024
        server =
            std::make_shared<engineserver::EngineServer>(apiEndpoint, nullptr, eventEndpoint, floodFile, bufferSize);
        g_exitHanlder.add([server]() { server->close(); });
        WAZUH_LOG_DEBUG("Server configured.");

        kvdb = std::make_shared<kvdb_manager::KVDBManager>(kvdbPath);
        WAZUH_LOG_INFO("KVDB initialized.");
        g_exitHanlder.add(
            [kvdb]()
            {
                WAZUH_LOG_INFO("KVDB terminated.");
                kvdb->clear();
            });

        // Register KVDB commands
        api::kvdb::cmds::registerAllCmds(kvdb, server->getRegistry());
        WAZUH_LOG_DEBUG("KVDB API registered.")

        store = std::make_shared<store::FileDriver>(fileStorage);
        WAZUH_LOG_INFO("Store initialized.");

        base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
        auto hlpParsers = store->get(hlpConfigFileName);
        if (std::holds_alternative<base::Error>(hlpParsers))
        {
            WAZUH_LOG_ERROR("Could not retreive configuration file [{}] needed by the "
                            "HLP module, error: {}",
                            hlpConfigFileName.fullName(),
                            std::get<base::Error>(hlpParsers).message);

            g_exitHanlder.execute();
            return;
        }
        logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers));
        hlp::registerParsers(logpar);
        WAZUH_LOG_INFO("HLP initialized.");

        auto registry = std::make_shared<builder::internals::Registry>();
        builder::internals::registerBuilders(registry, {0, logpar, kvdb});
        WAZUH_LOG_DEBUG("Builders registered.");

        builder = std::make_shared<builder::Builder>(store, registry);
        WAZUH_LOG_INFO("Builder initialized.");

        api::catalog::Config catalogConfig {
            store,
            builder,
            fmt::format("schema{}wazuh-asset{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S),
            fmt::format("schema{}wazuh-environment{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S)};

        catalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
        WAZUH_LOG_INFO("Catalog initialized.");

        api::catalog::cmds::registerAllCmds(catalog, server->getRegistry());
        WAZUH_LOG_DEBUG("Catalog API registered.")

        router = std::make_shared<router::Router>(builder, store, threads);
        router->run(server->getEventQueue());
        g_exitHanlder.add([router]() { router->stop(); });
        WAZUH_LOG_INFO("Router initialized.");

        // Register the API command
        //server->getRegistry()->registerCommand("router", router->apiCallbacks());
        api::router::cmds::registerCommands(router, server->getRegistry());
        WAZUH_LOG_DEBUG("Router API registered.")

        // If the router table is empty or the force flag is passed, load from the command line
        if (router->getRouteTable().empty())
        {
            router->addRoute(routeName, routePriority, routeFilter, routeEnvironment);
        }
        else if (forceRouterArg)
        {
            router->clear();
            router->addRoute(routeName, routePriority, routeFilter, routeEnvironment);
        }

        // Register Configuration API commands
        api::config::cmds::registerCommands(server->getRegistry(), confManager);
        WAZUH_LOG_DEBUG("Configuration manager API registered.");
    }
    catch (const std::exception& e)
    {
        const auto msg = utils::getExceptionStack(e);
        WAZUH_LOG_ERROR("While initializing modules: {}", msg);
        g_exitHanlder.execute();
        return;
    }

    // Start server
    try
    {
        server->run();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("While server running: {}.", utils::getExceptionStack(e));
        g_exitHanlder.execute();
        return;
    }
    g_exitHanlder.execute();
}

void configure(CLI::App_p app)
{
    auto serverApp = app->add_subcommand("server", "Start/Stop a Wazuh engine instance.");
    serverApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Log level
    serverApp
        ->add_option(
            "--log_level", options->logLevel, "Sets the logging level: 0 = Debug, 1 = Info, 2 = Warning, 3 = Error")
        ->default_val(ENGINE_LOG_LEVEL)
        ->check(CLI::Range(0, 3))
        ->envname(ENGINE_LOG_LEVEL_ENV);
    // Log output
    serverApp->add_option("--log_output", options->logOutput, "Sets the logging output")
        ->default_val(ENGINE_LOG_OUTPUT)
        ->envname(ENGINE_LOG_OUTPUT_ENV);

    // Server
    // Endpoints
    serverApp->add_option("--event_socket", options->eventEndpoint, "Sets the events server socket address.")
        ->default_val(ENGINE_EVENT_SOCK)
        ->envname(ENGINE_EVENT_SOCK_ENV);
    serverApp->add_option("--api_socket", options->apiEndpoint, "Sets the API server socket address.")
        ->default_val(ENGINE_API_SOCK)
        ->envname(ENGINE_API_SOCK_ENV);
    // Threads
    serverApp
        ->add_option("--threads", options->threads, "Sets the number of threads to be used by the engine environment.")
        ->default_val(ENGINE_THREADS)
        ->check(CLI::PositiveNumber)
        ->envname(ENGINE_THREADS_ENV);
    // Queue size
    serverApp
        ->add_option(
            "--queue_size", options->queueSize, "Sets the number of events that can be queued to be processed.")
        ->default_val(ENGINE_QUEUE_SIZE)
        ->check(CLI::PositiveNumber)
        ->envname(ENGINE_QUEUE_SIZE_ENV);
    // Flood file
    serverApp
        ->add_option(
            "--flood_file", options->floodFilePath, "Sets the path to the file where the flood events will be stored.")
        ->default_val(ENGINE_FLOOD_FILE)
        ->envname(ENGINE_FLOOD_FILE_ENV);

    // Store
    // Path
    serverApp
        ->add_option(
            "--store_path", options->fileStorage, "Sets the path to the folder where the assets are located (store).")
        ->default_val(ENGINE_STORE_PATH)
        ->check(CLI::ExistingDirectory)
        ->envname(ENGINE_STORE_PATH_ENV);

    // KVDB
    // Path
    serverApp->add_option("--kvdb_path", options->kvdbPath, "Sets the path to the KVDB folder.")
        ->default_val(ENGINE_KVDB_PATH)
        ->check(CLI::ExistingDirectory)
        ->envname(ENGINE_KVDB_PATH_ENV);

    // Start subcommand
    auto startApp = serverApp->add_subcommand("start", "Start a Wazuh engine instance");
    startApp
        ->add_option("--environment",
                     options->environment,
                     "Sets the environment to be used the first time an engine instance is started.")
        ->default_val(ENGINE_ENVIRONMENT)
        ->expected(4)
        ->delimiter(':')
        ->envname(ENGINE_ENVIRONMENT_ENV);
    startApp
        ->add_flag("--force_router_arg",
                   options->forceRouterArg,
                   "Use the router parameter, even if there is previous configuration.")
        ->default_val(false);

    // Register callback
    startApp->callback(
        [app, options]()
        {
            auto confManager = std::make_shared<conf::IConf<conf::CliConf>>(conf::CliConf(app));
            runStart(confManager);
        });
}
} // namespace cmd::server
